import json

import main


class _BrokenStream:
    def write(self, _data):
        raise OSError(22, "Invalid argument")

    def flush(self):
        raise OSError(22, "Invalid argument")


class _CaptureStream:
    def __init__(self):
        self.data = []

    def write(self, text):
        self.data.append(text)

    def flush(self):
        return None


def test_emit_json_writes_to_action_stdout(monkeypatch):
    capture = _CaptureStream()
    monkeypatch.setattr(main, "ACTION_STDOUT", capture)

    payload = {"success": True, "message": "ok"}
    main.emit_json(payload)

    assert capture.data
    line = capture.data[-1]
    assert line.startswith("ISEC_JSON:")
    parsed = json.loads(line[len("ISEC_JSON:"):].strip())
    assert parsed == payload


def test_emit_json_falls_back_to_os_write_when_streams_invalid(monkeypatch):
    monkeypatch.setattr(main, "ACTION_STDOUT", _BrokenStream())
    monkeypatch.setattr(main.sys, "stdout", _BrokenStream())
    monkeypatch.setattr(main.sys, "__stdout__", _BrokenStream())

    captured = {}

    def fake_os_write(fd, data):
        captured["fd"] = fd
        captured["data"] = data
        return len(data)

    monkeypatch.setattr(main.os, "write", fake_os_write)

    payload = {"success": False, "message": "fallback"}
    main.emit_json(payload)

    assert captured["fd"] == 1
    line = captured["data"].decode("utf-8")
    assert line.startswith("ISEC_JSON:")
    parsed = json.loads(line[len("ISEC_JSON:"):].strip())
    assert parsed == payload
