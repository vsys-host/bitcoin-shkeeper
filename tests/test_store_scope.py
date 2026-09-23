from app.services.store import parse_store_id


def test_parse_store_id():
    assert parse_store_id("default") == 1
    assert parse_store_id(2) == 2
    assert parse_store_id("7") == 7
    assert parse_store_id(None, required=False) is None
    assert parse_store_id("", required=False) is None
    try:
        parse_store_id(None)
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "required" in str(exc)
    try:
        parse_store_id("none")
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "Invalid store_id" in str(exc)
    try:
        parse_store_id("")
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "required" in str(exc)
