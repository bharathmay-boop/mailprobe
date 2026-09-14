"""Checks for the parts that do not need a network connection.

Run with: python test_mailprobe.py
"""

import json
import os
import threading
import urllib.error
import urllib.request

from mailprobe import (
    DEFAULT_FROM,
    DISPOSABLE_DOMAINS,
    FROM_ENV_VAR,
    INVALID,
    MAX_PER_REQUEST,
    RISKY,
    ROLE_NAMES,
    UNKNOWN,
    VALID,
    _split,
    decide,
    default_from_address,
    format_error,
    helo_name,
    main,
    make_handler,
    verify,
    verify_many,
)


# --- address format ---------------------------------------------------------

def test_syntax_rejects_bad_addresses():
    for bad in ["", "plainstring", "no-at-sign.com", "two@@at.com", "@nolocal.com",
                "trailing@dot.", "spaces in@name.com", "unicode@dom ain.com"]:
        assert format_error(bad), f"{bad!r} should be rejected"
        assert verify(bad).status == INVALID


def test_good_addresses_pass_the_format_check():
    for good in ["a@b.co", "first.last@example.com", "user+tag@sub.example.org",
                 "x!#$%&'*+-/=?^_`{|}~@example.com"]:
        assert format_error(good) is None, f"{good!r} should be accepted"


def test_length_limits():
    assert format_error("a" * 65 + "@example.com")
    assert format_error("a" * 250 + "@example.com")
    assert format_error("a" * 64 + "@example.com") is None


# --- turning a server reply into an answer ----------------------------------

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
    assert decide(250, catch_all=None, disposable=False)[0] == UNKNOWN


def test_disposable_domain_is_risky_even_when_real():
    assert decide(250, catch_all=False, disposable=True)[0] == RISKY


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


# --- greeting name ----------------------------------------------------------

def test_helo_name_comes_from_the_sending_domain():
    """Greeting a server with a bare machine name gets the sender refused."""
    assert helo_name("me@my-company.com") == "my-company.com"
    assert helo_name("me@mail.sub.example.org") == "mail.sub.example.org"


def test_helo_name_never_returns_a_bare_hostname():
    for odd in ["broken", "no-at-sign", "me@localhost", "me@"]:
        assert "." in helo_name(odd) or helo_name(odd) == "localhost"


# --- sender configuration ---------------------------------------------------

def test_sender_can_be_set_by_environment():
    original = os.environ.get(FROM_ENV_VAR)
    try:
        os.environ[FROM_ENV_VAR] = "checker@my-company.com"
        assert default_from_address() == "checker@my-company.com"
        os.environ[FROM_ENV_VAR] = "   "
        assert default_from_address() == DEFAULT_FROM
        os.environ.pop(FROM_ENV_VAR)
        assert default_from_address() == DEFAULT_FROM
    finally:
        os.environ.pop(FROM_ENV_VAR, None)
        if original is not None:
            os.environ[FROM_ENV_VAR] = original


def test_bad_sender_address_is_rejected_before_any_network_use():
    try:
        main(["--from-address", "not-an-address", "someone@example.com"])
    except SystemExit as exc:
        assert exc.code == 2
    else:
        raise AssertionError("a malformed sender should stop the run")


# --- batching ---------------------------------------------------------------

def test_results_keep_input_order_and_length():
    emails = ["bad@", "also bad", "worse"]
    results = verify_many(emails)
    assert [r.email for r in results] == emails
    assert all(r.status == INVALID for r in results)


def test_repeated_addresses_still_return_one_row_each():
    results = verify_many(["bad@", "bad@", "nope"])
    assert len(results) == 3


def test_splitting_input():
    assert _split(["a@b.com,c@d.com"]) == ["a@b.com", "c@d.com"]
    assert _split(["a@b.com, c@d.com ", "e@f.com"]) == ["a@b.com", "c@d.com", "e@f.com"]
    assert _split(["", "  "]) == []


def test_role_and_disposable_lists_are_sane():
    assert "support" in ROLE_NAMES
    assert "noreply" in ROLE_NAMES
    assert "bharath" not in ROLE_NAMES
    assert "mailinator.com" in DISPOSABLE_DOMAINS
    assert "gmail.com" not in DISPOSABLE_DOMAINS


# --- the local web interface ------------------------------------------------

class _Server:
    """Starts the interface on a spare port for the duration of a test."""

    def __enter__(self):
        import http.server

        handler = make_handler(DEFAULT_FROM, 5.0, 1)
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()

    def post(self, body):
        req = urllib.request.Request(
            self.url + "/check",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as res:
            return json.loads(res.read())


def test_web_page_loads():
    with _Server() as s:
        with urllib.request.urlopen(s.url, timeout=10) as res:
            assert res.status == 200
            assert b"mailprobe" in res.read()


def test_web_favicon_does_not_error():
    with _Server() as s:
        with urllib.request.urlopen(s.url + "/favicon.ico", timeout=10) as res:
            assert res.status == 204


def test_web_unknown_path_is_404():
    with _Server() as s:
        try:
            urllib.request.urlopen(s.url + "/nope", timeout=10)
        except urllib.error.HTTPError as exc:
            assert exc.code == 404
        else:
            raise AssertionError("unknown paths should 404")


def test_web_checks_format_without_touching_the_network():
    with _Server() as s:
        data = s.post({"emails": "bad@, also-bad"})
        assert [r["status"] for r in data["results"]] == [INVALID, INVALID]


def test_web_empty_input_returns_nothing():
    with _Server() as s:
        assert s.post({"emails": "   "})["results"] == []


def test_web_refuses_an_oversized_batch():
    """A pasted list of thousands would get the sender blocked by mail servers."""
    with _Server() as s:
        many = ",".join(f"a{i}@example.com" for i in range(MAX_PER_REQUEST + 1))
        assert "too many" in s.post({"emails": many})["error"]


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for test in tests:
        test()
        print(f"ok  {test.__name__}")
    print(f"\n{len(tests)} passed")
