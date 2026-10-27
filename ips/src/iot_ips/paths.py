"""Where the project's files live (configuration, data, example outputs)."""
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKAGE_DIR.parents[1]          # src/iot_ips -> src -> repository root
CONFIG_DIR = REPO_ROOT / "config"
DATA_DIR = REPO_ROOT / "data"
EXAMPLES_DIR = REPO_ROOT / "examples"
DEFAULT_DEVICES_PATH = CONFIG_DIR / "devices.json"
