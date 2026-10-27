import cv2
import jsonschema
import numpy as np
from conftest import Boom, Scripted

from vis.types import Detection

PERSON = Detection("person", 0.9, (10, 10, 40, 80))
UNKNOWN = Detection("face_unknown", 0.95, (20, 15, 20, 24))


def run(pipe, frame, n, clock, step=0.2):
    sent = []
    for _ in range(n):
        sent += pipe.process(clock(), frame)
        clock.advance(step)
    return sent


def test_needs_confirm_frames_in_a_row(make_pipeline, frame, clock, sink):
    pipe = make_pipeline(objects=Scripted([PERSON], [], [PERSON], [PERSON]))
    sent = run(pipe, frame, 4, clock)
    assert [e.type for e in sent] == ["person.detected"]      # frames 3+4 confirm; 1 was flicker
    assert len(sink.events) == 1


def test_cooldown_blocks_repeats_then_allows_again(make_pipeline, frame, clock):
    pipe = make_pipeline(objects=Scripted([PERSON]))
    assert len(run(pipe, frame, 10, clock)) == 1              # 2 s of video, cooldown is 10 s
    clock.advance(10)
    assert len(run(pipe, frame, 2, clock)) == 1


def test_unknown_face_event_matches_contract(make_pipeline, frame, clock, settings, event_schema):
    pipe = make_pipeline(faces=Scripted([UNKNOWN]))
    (event,) = run(pipe, frame, 2, clock)
    assert event.type == "face.unknown" and event.severity_hint == "high"
    assert event.source == "vision" and event.zone == "entrance"
    assert 0 < event.data["confidence"] <= 1
    assert event.data["snapshot"] == f"snapshots/{event.id}.jpg"
    jsonschema.validate(event.model_dump(), event_schema)
    saved = cv2.imread(str(settings.data_dir / event.data["snapshot"]))
    assert saved is not None and saved.shape == frame.shape
    assert not np.array_equal(saved[10:40, 15:45], frame[10:40, 15:45])     # box drawn on it


def test_known_face_is_a_named_person_and_hides_plain_person(make_pipeline, frame, clock):
    known = Detection("face_known", 0.97, (20, 15, 20, 24), name="maria")
    pipe = make_pipeline(objects=Scripted([PERSON]), faces=Scripted([known]))
    sent = run(pipe, frame, 2, clock)
    assert [(e.type, e.data.get("name")) for e in sent] == [("person.detected", "maria")]


def test_unknown_face_and_person_both_reported(make_pipeline, frame, clock):
    pipe = make_pipeline(objects=Scripted([PERSON]), faces=Scripted([UNKNOWN]))
    assert {e.type for e in run(pipe, frame, 2, clock)} == {"person.detected", "face.unknown"}


def test_low_confidence_face_is_ignored(make_pipeline, frame, clock):
    weak = Detection("face_unknown", 0.5, (1, 1, 10, 10))
    assert run(make_pipeline(faces=Scripted([weak])), frame, 5, clock) == []


def test_motion_only_counts_in_outdoor_zones(make_pipeline, frame, clock, settings):
    motion = Detection("motion", 0.4)
    (event,) = run(make_pipeline(motion=Scripted([motion])), frame, 2, clock)
    assert event.type == "motion.outdoor" and event.data["sensor_id"] == "cam_entrance"
    settings.zone = "kitchen"
    assert run(make_pipeline(motion=Scripted([motion])), frame, 2, clock) == []


def test_smoke_and_fire_events_have_contract_fields(make_pipeline, frame, clock, event_schema):
    pipe = make_pipeline(fire=[Scripted([Detection("smoke", 0.8), Detection("fire", 0.7)])])
    sent = {e.type: e for e in run(pipe, frame, 2, clock)}
    assert sent["smoke.detected"].data["sensor_id"] == "cam_entrance"
    assert sent["fire.detected"].data["snapshot"].startswith("snapshots/")
    assert sent["fire.detected"].severity_hint == "critical"
    for e in sent.values():
        jsonschema.validate(e.model_dump(), event_schema)


def test_vehicle_and_package_are_plain_events(make_pipeline, frame, clock):
    dets = [Detection("vehicle", 0.8, (5, 5, 50, 30)), Detection("package", 0.6, (60, 60, 20, 20))]
    sent = run(make_pipeline(objects=Scripted(dets)), frame, 2, clock)
    assert {e.type for e in sent} == {"vehicle.detected", "package.detected"}


def test_latency_is_measured_from_capture(make_pipeline, frame, clock):
    pipe = make_pipeline(faces=Scripted([UNKNOWN]))
    pipe.process(clock(), frame)
    clock.advance(0.3)
    (event,) = pipe.process(clock() - 0.25, frame)
    assert event.data["latency_ms"] == 250


def test_one_broken_detector_does_not_blind_the_rest(make_pipeline, frame, clock):
    pipe = make_pipeline(objects=Boom(), faces=Scripted([UNKNOWN]))
    assert [e.type for e in run(pipe, frame, 2, clock)] == ["face.unknown"]


def test_alert_still_sent_when_snapshot_cannot_be_written(make_pipeline, frame, clock, settings):
    settings.data_dir.joinpath("snapshots").write_text("a file, not a folder")
    (event,) = run(make_pipeline(faces=Scripted([UNKNOWN])), frame, 2, clock)
    assert event.type == "face.unknown" and "snapshot" not in event.data


def test_camera_disconnected_is_rate_limited(make_pipeline, clock, sink):
    pipe = make_pipeline()
    assert pipe.camera_down() is not None
    assert pipe.camera_down() is None
    clock.advance(301)
    assert pipe.camera_down() is not None
    assert [e.type for e in sink.events] == ["camera.disconnected"] * 2
    assert sink.events[0].data == {"camera_id": "cam_entrance"}


def test_fire_model_class_names_map_to_kinds(tmp_path):
    from vis.detectors import fire_class_kinds, load_class_names
    names = tmp_path / "fire.names"
    names.write_text("Fire\n\nSmoke\nperson\n")
    assert fire_class_kinds(load_class_names(names)) == {0: "fire", 1: "smoke"}


def test_three_class_roboflow_model_ignores_the_default_class(tmp_path):
    """The Roboflow fire model has ids 0=Fire, 1=default, 2=smoke: `default` must not alert."""
    from vis.detectors import fire_class_kinds, load_class_names
    names = tmp_path / "fire.names"
    names.write_text("Fire\ndefault\nsmoke\n")
    assert fire_class_kinds(load_class_names(names)) == {0: "fire", 2: "smoke"}


def test_per_kind_confidence_floors(tmp_path):
    """Fire 0.5 is under its 0.55 floor, smoke 0.9 passes its 0.8 floor, class 1 is ignored."""
    import numpy as np

    from vis.detectors import YoloOnnx

    det = YoloOnnx.__new__(YoloOnnx)
    det.class_kinds = {0: "fire", 2: "smoke"}
    det.class_conf = {0: 0.55, 2: 0.8}
    det.min_conf, det.nms_iou, det.size = 0.45, 0.5, 100

    class Net:
        def __init__(self, scores):
            self.scores = scores

        def setInput(self, _):
            pass

        def forward(self):
            # (1, 4 + 3 classes, 3 anchors): 3 separated boxes, scores given per anchor
            out = np.zeros((1, 7, 3), np.float32)
            out[0, 0:4, :] = [[20, 50, 80], [20, 50, 80], [10, 10, 10], [10, 10, 10]]
            out[0, 4:, :] = self.scores
            return out

    # anchor 0: fire 0.50 (rejected) ; anchor 1: default 0.95 (ignored) ; anchor 2: smoke 0.90
    det.net = Net([[0.50, 0.0, 0.0], [0.0, 0.95, 0.0], [0.0, 0.0, 0.90]])
    got = det.detect(np.zeros((100, 100, 3), np.uint8))
    assert [(d.kind, round(d.confidence, 2)) for d in got] == [("smoke", 0.9)]
    det.net = Net([[0.60, 0.0, 0.0], [0.0, 0.0, 0.0], [0.0, 0.0, 0.0]])
    assert [d.kind for d in det.detect(np.zeros((100, 100, 3), np.uint8))] == ["fire"]


def _gated_frames():
    """Two scenes with a fire box: one static, one flickering inside the box."""
    import numpy as np
    rng = np.random.default_rng(1)
    static = [np.full((180, 320, 3), 90, np.uint8) for _ in range(4)]
    flicker = []
    for _ in range(4):
        f = np.full((180, 320, 3), 90, np.uint8)
        f[40:120, 60:200] = rng.integers(0, 255, (80, 140, 3), dtype=np.uint8)
        flicker.append(f)
    return static, flicker


class _AlwaysFire:
    def detect(self, frame):
        return [Detection("fire", 0.7, (60, 40, 140, 80)), Detection("person", 0.9, (0, 0, 5, 5))]


def test_motion_gate_drops_static_fire_and_keeps_flickering_fire():
    from vis.detectors import MotionGated
    static, flicker = _gated_frames()
    gate = MotionGated(_AlwaysFire(), kinds=("fire",), min_motion=0.25)
    out_static = [gate.detect(f) for f in static]
    assert all(d.kind == "person" for out in out_static for d in out)       # fire never passes
    gate = MotionGated(_AlwaysFire(), kinds=("fire",), min_motion=0.25)
    out_flicker = [gate.detect(f) for f in flicker]
    assert [d.kind for d in out_flicker[0]] == ["person"]                   # first frame: unknown
    assert all("fire" in [d.kind for d in out] for out in out_flicker[1:])  # then it passes
    assert all("person" in [d.kind for d in out] for out in out_flicker)    # other kinds untouched


def test_package_model_names_and_coco_stand_ins():
    from vis.detectors import COCO_KINDS, coco_kinds, package_class_kinds
    assert package_class_kinds(["parcel", "person", "Cardboard Box"]) == {0: "package"}
    assert package_class_kinds(["package", "box_open"]) == {0: "package", 1: "package"}
    assert package_class_kinds(["dog"]) == {}
    assert coco_kinds(False) == COCO_KINDS
    assert "package" not in coco_kinds(True).values() and "person" in coco_kinds(True).values()
