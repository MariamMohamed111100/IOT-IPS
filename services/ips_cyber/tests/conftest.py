import pathlib
import sys

SERVICE = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SERVICE))
sys.path.insert(0, str(SERVICE / "tests"))
