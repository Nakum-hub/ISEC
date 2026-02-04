"""Print the local system fingerprint used for node-locked licenses."""
from src.utils.license_manager import get_system_fingerprint


def main():
    fingerprint, system_info = get_system_fingerprint()
    print("System Fingerprint:", fingerprint)
    print("System Info:")
    for key, value in system_info.items():
        print(f"  {key}: {value}")


if __name__ == "__main__":
    main()
