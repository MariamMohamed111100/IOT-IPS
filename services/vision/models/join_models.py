"""Join the downloaded model parts and verify every model file.

Usage (any OS, Python 3 only):
    python join_models.py <folder with the downloaded files>  [<destination, default: same folder>]

Joins fire.onnx.part00+part01 -> fire.onnx and sface.onnx.part00+part01 -> sface.onnx, then checks
the SHA-256 of fire.onnx, sface.onnx, yolov8n.onnx and yunet.onnx. Finally copy the result to
services/vision/models/ (together with fire.names).
"""
import hashlib
import shutil
import sys
from pathlib import Path

SHA256 = {
    "fire.onnx": "406c65488a2082b7a9d1fad43cdfd5ecfce76128dbbab185b553c99826469d51",
    "sface.onnx": "0ba9fbfa01b5270c96627c4ef784da859931e02f04419c829e83484087c34e79",
    "yolov8n.onnx": "f3cfe8b2120725b39b5d5f080bd213fde648fa38088c6c4d83d0c73f86055a28",
    "yunet.onnx": "8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4",
}


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    src = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    dst = Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else src
    dst.mkdir(parents=True, exist_ok=True)
    ok = True
    for name, want in SHA256.items():
        parts = sorted(src.glob(name + ".part*"))
        target = dst / name
        if parts:
            with target.open("wb") as out:
                for p in parts:
                    out.write(p.read_bytes())
        elif (src / name).exists():
            if src != dst:
                shutil.copy2(src / name, target)
        else:
            print(f"MISSING  {name} (no file and no .part files in {src})")
            ok = False
            continue
        got = digest(target)
        good = got == want
        ok &= good
        print(f"{'OK      ' if good else 'CORRUPT '}{name}  {target.stat().st_size / 1e6:.1f} MB")
    names = src / "fire.names"
    if names.exists() and src != dst:
        shutil.copy2(names, dst / "fire.names")
    msg = ("All models are complete." if ok
           else "Some files are missing or damaged: download them again.")
    print("\n" + msg)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
