"""
Shared path helpers for ISEC.
Centralizes state directory resolution so both CLI and UI can store local state
outside the project root (safer for packaging and permissions).
"""
import os
import platform


def get_project_root():
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def get_state_dir(explicit_dir=None):
    """Resolve the per-user state directory for ISEC."""
    env_dir = explicit_dir or os.environ.get("ISEC_STATE_DIR")
    if env_dir:
        return env_dir

    if os.name == "nt":
        base = os.environ.get("APPDATA") or os.path.expanduser("~\\AppData\\Roaming")
        return os.path.join(base, "ISEC")

    system = platform.system()
    if system == "Darwin":
        return os.path.expanduser("~/Library/Application Support/ISEC")

    return os.path.expanduser("~/.config/ISEC")


def ensure_dir(path):
    if path:
        os.makedirs(path, exist_ok=True)
    return path


def get_state_file(filename, state_dir=None, subdir=None):
    base = ensure_dir(get_state_dir(state_dir))
    if subdir:
        base = ensure_dir(os.path.join(base, subdir))
    return os.path.join(base, filename)
