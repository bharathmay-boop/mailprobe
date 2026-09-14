"""Checks for the parts that do not need a network connection.

Run with: python test_mailprobe.py
"""

from mailprobe import (
    DISPOSABLE_DOMAINS,
    INVALID,
    RISKY,
    ROLE_NAMES,
    UNKNOWN,
    VALID,
    decide,
    verify,
    _split,
)


def test_syntax_rejects_bad_addresses():
    for bad in ["", "plainstring", "no-at-sign.com", "two@@at.com", "@nolocal.com",
                "trailing@dot.", "spaces in@name.com", "unicode@dom ain.com"]:
        result = verify(bad)
        assert result.status == INVALID, f"{bad!r} should be invalid, got {result.status}"


def test_length_limits():
    assert verify("a" * 65 + "@example.com").status == INVALID
    assert verify("a" * 250 + "@example.com").status == INVALID


def test_accepted_and_not_catch_all_is_valid():
    status, reason = decide(250, catch_all=False, disposable=False)
    assert status == VALID
    assert "confirmed" in reason


def test_catch_all_downgrades_to_risky():
    """The whole point of the tool: a domain that accepts everything proves nothing."""
    status, reason = decide(250, catch_all=True, disposable=False)
    assert status == RISKY
    assert "every address" in reason


def test_unchecked_catch_all_is_unknown():
    status, _ = decide(250, catch_all=None, disposable=False)
    assert status == UNKNOWN


def test_disposable_domain_is_risky_even_when_real():
    status, _ = decide(250, catch_all=False, disposable=True)
    assert status == RISKY


def test_permanent_rejection_is_invalid():
    for code in (550, 551, 553, 500):
        assert decide(code, False, False)[0] == INVALID


def test_temporary_rejection_is_unknown():
    """Greylisting is not a rejection, and calling it one loses real addresses."""
    for code in (450, 451, 421):
        assert decide(code, False, False)[0] == UNKNOWN


def test_dropped_connection_is_unknown_not_invalid():
    """A server that hangs up has told us nothing, so we must not guess."""
    status, reason = decide(-1, None, False)
    assert status == UNKNOWN
    assert "closed the connection" in reason


def test_role_and_disposable_lists_are_sane():
    assert "support" in ROLE_NAMES
    assert "noreply" in ROLE_NAMES
    assert "bharath" not in ROLE_NAMES
    assert "mailinator.com" in DISPOSABLE_DOMAINS
    assert "gmail.com" not in DISPOSABLE_DOMAINS


def test_splitting_input():
    assert _split(["a@b.com,c@d.com"]) == ["a@b.com", "c@d.com"]
    assert _split(["a@b.com, c@d.com ", "e@f.com"]) == ["a@b.com", "c@d.com", "e@f.com"]
    assert _split(["", "  "]) == []


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for test in tests:
        test()
        print(f"ok  {test.__name__}")
    print(f"\n{len(tests)} passed")
