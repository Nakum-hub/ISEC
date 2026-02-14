from main import check_action_feature_access, load_feature_flags


def test_feature_flags_fail_closed_when_empty():
    flags = load_feature_flags({"valid": True, "features": []})
    assert flags["collect"] is False
    assert flags["view"] is False
    assert flags["report"] is False
    assert flags["export"] is False

    allowed, missing = check_action_feature_access("collect", flags)
    assert allowed is False
    assert "collect" in missing


def test_feature_flags_allows_all_keyword():
    flags = load_feature_flags({"valid": True, "features": ["all"]})
    assert flags["collect"] is True
    assert flags["view"] is True
    assert flags["report"] is True
    assert flags["export"] is True

    allowed, missing = check_action_feature_access("export", flags)
    assert allowed is True
    assert missing == []
