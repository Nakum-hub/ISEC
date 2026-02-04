import os
import sqlite3
import tempfile


def validate_environment(output_dir):
    checks = []

    def add_check(name, success, message=""):
        checks.append({"name": name, "success": success, "message": message})

    exists = os.path.isdir(output_dir)
    add_check("output_dir_exists", exists, "" if exists else "Output directory does not exist or is not a directory")

    writable = False
    writable_message = ""
    if exists:
        try:
            fd, tmp_path = tempfile.mkstemp(dir=output_dir)
            os.close(fd)
            os.remove(tmp_path)
            writable = True
        except Exception as exc:
            writable_message = str(exc)
    add_check("output_dir_writable", writable, writable_message)

    db_ok = False
    db_message = ""
    db_path = os.path.join(output_dir, "evidence.db")
    try:
        conn = sqlite3.connect(db_path)
        try:
            conn.execute("PRAGMA user_version;")
            conn.commit()
            db_ok = True
        finally:
            conn.close()
    except Exception as exc:
        db_message = str(exc)
    add_check("database_accessible", db_ok, db_message)

    success = all(check["success"] for check in checks)
    return {"success": success, "checks": checks}
