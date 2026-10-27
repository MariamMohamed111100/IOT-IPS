import cv2
import numpy as np

from vis.source import FrameSource


class FakeCap:
    """A camera with `n` frames; `fail_opens` initial open() attempts fail."""

    def __init__(self, n=5, fps=10.0):
        self.n, self.pos, self.fps, self.opened = n, 0, fps, True

    def isOpened(self):
        return self.opened

    def get(self, prop):
        return self.fps if prop == cv2.CAP_PROP_FPS else 0

    def set(self, prop, value):
        self.pos = int(value)

    def grab(self):
        if self.pos >= self.n:
            return False
        self.pos += 1
        return True

    def retrieve(self):
        return True, np.full((4, 4, 3), self.pos, np.uint8)

    def release(self):
        self.opened = False


class Clock:
    def __init__(self, tick=0.0):
        self.t, self.tick = 0.0, tick

    def __call__(self):
        self.t += self.tick                  # a streaming clock keeps moving between reads
        return self.t

    def sleep(self, s):
        self.t += s


def take(src, n):
    out = []
    for item in src.frames():
        out.append(item)
        if len(out) == n:
            return out


def test_file_is_looped_forever_and_paced_to_fps():
    c = Clock()
    src = FrameSource("clip.mp4", fps=5, opener=lambda _: FakeCap(5, 10.0), clock=c, sleep=c.sleep)
    got = take(src, 12)
    assert len(got) == 12 and src.loops >= 2               # 5-frame clip played 2+ times
    gaps = [b[0] - a[0] for a, b in zip(got, got[1:], strict=False)]
    ordinary = sorted(gaps)[: len(gaps) - 2]               # the loop seam may be a bit shorter
    assert all(abs(g - 0.2) < 1e-6 for g in ordinary)      # 5 frames/s out of a 10 fps clip


def test_unreadable_file_reports_down_instead_of_spinning():
    c = Clock()
    src = FrameSource("clip.mp4", opener=lambda _: FakeCap(0), clock=c, sleep=c.sleep)
    t, frame = take(src, 1)[0]
    assert frame is None and src.down_since is not None and not src.connected


def test_stream_that_fails_to_open_then_recovers():
    c = Clock()
    caps = [None, None, FakeCap(100)]

    def opener(_):
        cap = caps.pop(0)
        if cap is None:
            dead = FakeCap()
            dead.opened = False
            return dead
        return cap

    src = FrameSource("rtsp://cam/x", fps=10, opener=opener, clock=c, sleep=c.sleep,
                      retry_seconds=2)
    got = take(src, 3)
    assert [f is None for _, f in got] == [True, True, False]
    assert src.connected and c.t >= 4                      # waited between retries


def test_stream_drop_reconnects():
    c = Clock(tick=0.01)
    caps = [FakeCap(2), FakeCap(50)]
    src = FrameSource("rtsp://cam/x", fps=1000, opener=lambda _: caps.pop(0), clock=c,
                      sleep=c.sleep)
    got = take(src, 4)
    assert [f is None for _, f in got] == [False, False, True, False]


def test_real_video_file_loops(tmp_path):
    path = tmp_path / "clip.avi"
    writer = cv2.VideoWriter(str(path), cv2.VideoWriter_fourcc(*"MJPG"), 20, (64, 48))
    for i in range(6):
        writer.write(np.full((48, 64, 3), i * 40, np.uint8))
    writer.release()
    src = FrameSource(str(path), fps=1000)
    got = take(src, 14)
    assert all(f is not None and f.shape == (48, 64, 3) for _, f in got) and src.loops >= 2
    src.close()


def test_slow_consumer_skips_frames_instead_of_slowing_the_video():
    """A file plays on wall-clock time: if detection takes 0.35 s per frame the video moves on."""
    c = Clock()
    src = FrameSource("clip.mp4", fps=10, opener=lambda _: FakeCap(200, 10.0),
                      clock=c, sleep=c.sleep)
    positions = []
    for _, frame in src.frames():
        positions.append(int(frame[0, 0, 0]))        # FakeCap paints its position into the frame
        c.t += 0.35                                   # the consumer is busy detecting
        if len(positions) == 5:
            break
    # 4 x 0.35 s of work before the 5th frame = 1.4 s of wall clock = ~14 video frames at 10 fps.
    # Without skipping, the video would still be on frame 5.
    assert positions[-1] >= 12, positions
