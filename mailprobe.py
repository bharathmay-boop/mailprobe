"""Check whether an email address can actually receive mail.

Most checkers stop at the format of the address. This one asks the receiving
mail server directly, and reports "unknown" when the server refuses to say.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import http.server
import json
import os
import re
import secrets
import smtplib
import socket
import sys
import threading
import webbrowser
from dataclasses import asdict, dataclass

import dns.exception
import dns.resolver

__version__ = "0.2.0"

VALID = "valid"
INVALID = "invalid"
RISKY = "risky"
UNKNOWN = "unknown"

# Used when the caller gives us nothing better. example.com is reserved and
# cannot send or receive mail, so some servers refuse it. main() warns when
# this is still in place.
DEFAULT_FROM = "verify@example.com"
FROM_ENV_VAR = "MAILPROBE_FROM"

# RFC 5321 caps the local part at 64 characters and the whole address at 254.
MAX_LOCAL = 64
MAX_TOTAL = 254

_SYNTAX = re.compile(
    r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+"
    r"(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
    r"@(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}$"
)

# A 2xx reply to RCPT TO means the server accepted the recipient.
ACCEPTED = frozenset({250, 251})

# Mailboxes that usually belong to a team rather than a person. Still real
# addresses, so this is reported as a flag and does not change the status.
ROLE_NAMES = frozenset(
    """admin administrator abuse alerts billing careers contact donotreply
    do-not-reply enquiries feedback help hello hostmaster hr info inquiries
    jobs legal mailer-daemon marketing media newsletter no-reply noreply
    notifications office postmaster press root sales security service
    subscribe support team unsubscribe webmaster""".split()
)

# Starter list of throwaway mail services. Deliberately short: a handful of
# providers cover most real traffic. See README for the full public list.
DISPOSABLE_DOMAINS = frozenset(
    """10minutemail.com 1secmail.com 20minutemail.com 33mail.com
    dispostable.com discard.email emailondeck.com fakeinbox.com getairmail.com
    getnada.com grr.la guerrillamail.com guerrillamailblock.com inboxkitten.com
    mailcatch.com maildrop.cc mailinator.com mailnesia.com mailsac.com
    minuteinbox.com mohmal.com moakt.com mytemp.email sharklasers.com
    spam4.me spamgourmet.com tempail.com tempinbox.com tempmail.com
    tempmailo.com temp-mail.org tempr.email throwawaymail.com trashmail.com
    yopmail.com""".split()
)


@dataclass
class Result:
    email: str
    status: str
    reason: str
    mx: str | None = None
    catch_all: bool | None = None
    disposable: bool = False
    role: bool = False


def default_from_address() -> str:
    """The sending address to introduce ourselves with.

    Reads MAILPROBE_FROM so anyone installing this can set their own domain
    once instead of passing it on every run.
    """
    return os.environ.get(FROM_ENV_VAR, "").strip() or DEFAULT_FROM


def helo_name(from_address: str) -> str:
    """The name we announce ourselves as when greeting a mail server.

    The standard library would use this computer's hostname, which on most
    machines is something like "laptop" or "DESKTOP-ABC123". That is not a
    domain name, and plenty of mail servers refuse to talk to a sender that
    greets them with one. The domain of the sending address is both correct
    and something the user can control.
    """
    domain = from_address.rpartition("@")[2].strip()
    return domain if "." in domain else "localhost"


def format_error(email: str) -> str | None:
    """Explain why an address is malformed, or return None if it looks fine."""
    if not email:
        return "no address given"
    if len(email) > MAX_TOTAL:
        return "the address is too long"
    if not _SYNTAX.match(email):
        return "not a valid email address format"
    if len(email.rpartition("@")[0]) > MAX_LOCAL:
        return "the part before the @ is too long"
    return None


def find_mx(domain: str, timeout: float = 10.0) -> tuple[str | None, str]:
    """Return the best mail host for a domain, and a note explaining the lookup.

    Falls back to the A record when there is no MX record, which RFC 5321
    allows and plenty of small domains rely on.
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    try:
        records = resolver.resolve(domain, "MX")
        best = min(records, key=lambda r: r.preference)
        return str(best.exchange).rstrip("."), "mx record found"
    except dns.resolver.NXDOMAIN:
        return None, "domain does not exist"
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        pass
    except dns.exception.Timeout:
        return None, "dns lookup timed out"
    except dns.exception.DNSException:
        return None, "dns lookup failed"

    try:
        resolver.resolve(domain, "A")
        return domain, "no mx record, using the domain itself"
    except dns.exception.DNSException:
        return None, "domain has no mail server"


def decide(code: int, catch_all: bool | None, disposable: bool) -> tuple[str, str]:
    """Turn a server reply into a status and a plain explanation.

    Kept free of network calls so the rules can be tested directly.
    """
    if code in ACCEPTED:
        if catch_all is True:
            return RISKY, "server accepts every address on this domain, so this mailbox cannot be confirmed"
        if catch_all is None:
            return UNKNOWN, "server accepted the address but we could not check for a catch-all"
        if disposable:
            return RISKY, "mailbox exists but the domain is a throwaway mail service"
        return VALID, "server confirmed the mailbox exists"

    if 500 <= code < 600:
        return INVALID, f"server rejected the address (code {code})"

    if 400 <= code < 500:
        return UNKNOWN, f"server asked us to try again later (code {code})"

    # smtplib reports -1 when the connection drops or the reply cannot be read.
    # Servers that dislike being probed often behave this way.
    if code < 200:
        return UNKNOWN, "server closed the connection without answering"

    return UNKNOWN, f"unexpected reply from server (code {code})"


def _flags(email: str) -> tuple[bool, bool]:
    local, _, domain = email.rpartition("@")
    return domain.lower() in DISPOSABLE_DOMAINS, local.lower() in ROLE_NAMES


def _explain_failure(exc: BaseException) -> str:
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "mail server did not respond in time"
    if isinstance(exc, smtplib.SMTPServerDisconnected):
        return "mail server closed the connection"
    if isinstance(exc, ConnectionRefusedError):
        return "mail server refused the connection"
    if isinstance(exc, OSError) and getattr(exc, "errno", None) is not None:
        return (
            "could not reach the mail server, outbound port 25 is blocked on "
            "most hosting providers"
        )
    return f"could not complete the check ({type(exc).__name__})"


def verify_domain(
    domain: str,
    emails: list[str],
    from_address: str = DEFAULT_FROM,
    timeout: float = 10.0,
) -> dict[str, Result]:
    """Check every address at one domain over a single connection.

    One connection per domain rather than one per address. Opening many
    connections to the same server in parallel is what gets a sender blocked,
    and reusing one is faster besides.
    """
    results: dict[str, Result] = {}

    mx_host, note = find_mx(domain, timeout=timeout)
    if mx_host is None:
        for email in emails:
            disposable, role = _flags(email)
            results[email] = Result(email, INVALID, note, disposable=disposable, role=role)
        return results

    failure = "could not complete the check"
    try:
        with smtplib.SMTP(local_hostname=helo_name(from_address), timeout=timeout) as smtp:
            smtp.connect(mx_host, 25)
            smtp.ehlo_or_helo_if_needed()
            smtp.mail(from_address)

            # Ask about an address that cannot exist, before asking about any
            # real one. If the server accepts this, its answers carry no
            # information and there is no point probing the rest.
            decoy_code, _ = smtp.rcpt(f"{secrets.token_hex(12)}@{domain}")
            catch_all = decoy_code in ACCEPTED

            for email in emails:
                disposable, role = _flags(email)
                if catch_all:
                    status, reason = decide(250, True, disposable)
                    code = 250
                else:
                    code, _ = smtp.rcpt(email)
                    status, reason = decide(code, False, disposable)
                results[email] = Result(
                    email, status, reason, mx_host, catch_all, disposable, role
                )
    except (smtplib.SMTPException, OSError) as exc:
        failure = _explain_failure(exc)

    # Anything the connection did not get to is reported honestly rather than
    # guessed at.
    for email in emails:
        if email not in results:
            disposable, role = _flags(email)
            results[email] = Result(
                email, UNKNOWN, failure, mx=mx_host, disposable=disposable, role=role
            )
    return results


def verify_many(
    emails: list[str],
    from_address: str = DEFAULT_FROM,
    timeout: float = 10.0,
    workers: int = 5,
) -> list[Result]:
    """Check several addresses, grouped by domain, keeping the input order."""
    cleaned = [e.strip() for e in emails]
    results: dict[str, Result] = {}
    groups: dict[str, list[str]] = {}

    for email in cleaned:
        problem = format_error(email)
        if problem:
            results[email] = Result(email, INVALID, problem)
        else:
            groups.setdefault(email.rpartition("@")[2].lower(), []).append(email)

    if groups:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(verify_domain, domain, members, from_address, timeout): members
                for domain, members in groups.items()
            }
            for future in concurrent.futures.as_completed(futures):
                members = futures[future]
                try:
                    results.update(future.result())
                except Exception as exc:  # one bad domain must not sink the batch
                    for email in members:
                        disposable, role = _flags(email)
                        results[email] = Result(
                            email, UNKNOWN, _explain_failure(exc),
                            disposable=disposable, role=role,
                        )

    return [results[email] for email in cleaned]


def verify(
    email: str,
    from_address: str = DEFAULT_FROM,
    timeout: float = 10.0,
) -> Result:
    """Check one address end to end."""
    return verify_many([email], from_address, timeout, workers=1)[0]


# The browser page is kept here so the tool stays a single file with no
# data files to install alongside it.
PAGE = """<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mailprobe</title>
<style>
  :root {
    --bg:#f7f6f3; --card:#fff; --ink:#1b1d22; --soft:#6b6f77; --line:#e2e0da;
    --valid:#2f7a4d; --invalid:#b03a2e; --risky:#a6701c; --unknown:#6b6f77;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg:#15171b; --card:#1d2026; --ink:#e9e7e1; --soft:#9aa0aa; --line:#2c3037;
      --valid:#68b98a; --invalid:#e07a6b; --risky:#d7a45a; --unknown:#9aa0aa;
    }
  }
  * { box-sizing:border-box; }
  body {
    margin:0; padding:40px 20px 80px; background:var(--bg); color:var(--ink);
    font:15px/1.6 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  }
  .wrap { max-width:760px; margin:0 auto; }
  h1 { font-size:26px; margin:0 0 6px; letter-spacing:-.02em; }
  .sub { color:var(--soft); margin:0 0 28px; }
  textarea {
    width:100%; min-height:150px; padding:14px 16px; border:1px solid var(--line);
    border-radius:10px; background:var(--card); color:var(--ink); resize:vertical;
    font:14px/1.6 ui-monospace, SFMono-Regular, Menlo, monospace;
  }
  textarea:focus { outline:2px solid var(--ink); outline-offset:-1px; }
  .row { display:flex; gap:12px; align-items:center; margin-top:14px; flex-wrap:wrap; }
  button {
    background:var(--ink); color:var(--bg); border:0; border-radius:9px;
    padding:11px 22px; font-size:15px; font-weight:600; cursor:pointer;
  }
  button:disabled { opacity:.55; cursor:default; }
  .note { color:var(--soft); font-size:13.5px; }
  table { width:100%; border-collapse:collapse; margin-top:30px; }
  th {
    text-align:left; font-size:11.5px; text-transform:uppercase; letter-spacing:.07em;
    color:var(--soft); font-weight:600; padding:0 10px 8px 0; border-bottom:1px solid var(--line);
  }
  td { padding:13px 10px 13px 0; border-bottom:1px solid var(--line); vertical-align:top; }
  td.addr { font-family:ui-monospace, SFMono-Regular, Menlo, monospace; font-size:13.5px; overflow-wrap:anywhere; }
  .badge { font-size:12px; font-weight:700; text-transform:uppercase; letter-spacing:.04em; white-space:nowrap; }
  .valid{color:var(--valid)} .invalid{color:var(--invalid)}
  .risky{color:var(--risky)} .unknown{color:var(--unknown)}
  .flag {
    display:inline-block; margin-left:6px; padding:1px 7px; border:1px solid var(--line);
    border-radius:20px; font-size:11px; color:var(--soft); text-transform:uppercase; letter-spacing:.04em;
  }
</style>
<div class="wrap">
  <h1>mailprobe</h1>
  <p class="sub">Checks whether an address can actually receive mail. Says unknown when the server will not tell us.</p>

  <textarea id="input" placeholder="one@example.com, two@example.com
or one address per line"></textarea>

  <div class="row">
    <button id="go">Check</button>
    <span class="note" id="note">Runs on your machine. Nothing is sent to any third party.</span>
  </div>

  <div id="out"></div>
</div>
<script>
  const input = document.getElementById('input');
  const go = document.getElementById('go');
  const note = document.getElementById('note');
  const out = document.getElementById('out');

  async function check() {
    const text = input.value.trim();
    if (!text) { input.focus(); return; }

    go.disabled = true;
    note.textContent = 'Checking. Each address needs a round trip to its mail server.';
    out.innerHTML = '';

    try {
      const res = await fetch('/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ emails: text })
      });
      const data = await res.json();
      if (data.error) { note.textContent = data.error; return; }
      render(data.results);
      note.textContent = data.results.length + ' checked.';
    } catch (e) {
      note.textContent = 'Could not reach the local server. Is it still running?';
    } finally {
      go.disabled = false;
    }
  }

  function render(rows) {
    const esc = s => String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
    let html = '<table><tr><th>Address</th><th>Result</th><th>Why</th></tr>';
    for (const r of rows) {
      let flags = '';
      if (r.disposable) flags += '<span class="flag">disposable</span>';
      if (r.role) flags += '<span class="flag">role</span>';
      html += '<tr><td class="addr">' + esc(r.email) + '</td>'
            + '<td><span class="badge ' + esc(r.status) + '">' + esc(r.status) + '</span></td>'
            + '<td class="why">' + esc(r.reason) + flags + '</td></tr>';
    }
    out.innerHTML = html + '</table>';
  }

  go.addEventListener('click', check);
  input.addEventListener('keydown', e => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') check();
  });
</script>
"""

# Checking a large list from one IP address gets that address refused by mail
# servers. The browser makes it easy to paste thousands by accident.
MAX_PER_REQUEST = 100
MAX_BODY_BYTES = 100_000


def make_handler(from_address: str, timeout: float, workers: int):
    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = f"mailprobe/{__version__}"

        def _send(self, code, body, content_type):
            payload = body.encode("utf-8")
            try:
                self.send_response(code)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass  # the tab was closed while we were still checking

        def _json(self, code, obj):
            self._send(code, json.dumps(obj), "application/json")

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                self._send(200, PAGE, "text/html; charset=utf-8")
            elif self.path == "/favicon.ico":
                try:
                    self.send_response(204)
                    self.end_headers()
                except (BrokenPipeError, ConnectionResetError):
                    pass
            else:
                self._send(404, "not found", "text/plain; charset=utf-8")

        def do_POST(self):
            if self.path != "/check":
                self._send(404, "not found", "text/plain; charset=utf-8")
                return

            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                self._json(400, {"error": "could not read that input"})
                return

            if length > MAX_BODY_BYTES:
                self._json(413, {"error": "that is too much text to check at once"})
                return

            try:
                payload = json.loads(self.rfile.read(length) or b"{}")
                emails = _split(str(payload.get("emails", "")).splitlines())
            except (ValueError, TypeError):
                self._json(400, {"error": "could not read that input"})
                return

            if not emails:
                self._json(200, {"results": []})
                return

            if len(emails) > MAX_PER_REQUEST:
                self._json(200, {
                    "error": f"{len(emails)} addresses is too many at once. "
                             f"Check up to {MAX_PER_REQUEST} here, or use the "
                             f"command line for larger lists."
                })
                return

            results = verify_many(emails, from_address, timeout, workers)
            self._json(200, {"results": [asdict(r) for r in results]})

        def log_message(self, *args):
            pass  # keep the terminal readable

    return Handler


def serve(
    port: int = 8765,
    from_address: str = DEFAULT_FROM,
    timeout: float = 10.0,
    workers: int = 5,
    open_browser: bool = True,
) -> None:
    """Run the browser interface on this machine.

    Bound to localhost on purpose. This tool opens connections to other
    people's mail servers, so it should not be reachable from the network.
    """
    handler = make_handler(from_address, timeout, workers)

    try:
        server = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    except OSError as exc:
        print(f"could not start on port {port}: {exc}", file=sys.stderr)
        print("try a different one with --port", file=sys.stderr)
        raise SystemExit(1)

    url = f"http://127.0.0.1:{port}"
    print(f"mailprobe is running at {url}")
    print("press ctrl+c to stop")

    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        server.server_close()


def _split(values: list[str]) -> list[str]:
    out = []
    for value in values:
        out.extend(part.strip() for part in value.split(",") if part.strip())
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mailprobe",
        description="Check whether an email address can actually receive mail.",
    )
    parser.add_argument("emails", nargs="*", help="one or more addresses, separated by commas or spaces")
    parser.add_argument("--json", action="store_true", help="print results as JSON")
    parser.add_argument(
        "--from-address",
        default=None,
        help=f"address to introduce ourselves with, use a domain you own "
             f"(or set {FROM_ENV_VAR})",
    )
    parser.add_argument("--timeout", type=float, default=10.0, help="seconds to wait per step")
    parser.add_argument("--workers", type=int, default=5, help="how many domains to check at once")
    parser.add_argument("--serve", action="store_true", help="open the browser interface on this machine")
    parser.add_argument("--port", type=int, default=8765, help="port for --serve")
    parser.add_argument("--no-browser", action="store_true", help="with --serve, do not open a browser window")
    parser.add_argument("--quiet", action="store_true", help="do not print the sender warning")
    parser.add_argument("--version", action="version", version=f"mailprobe {__version__}")
    args = parser.parse_args(argv)

    if args.workers < 1:
        parser.error("--workers must be at least 1")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")

    from_address = args.from_address or default_from_address()
    if format_error(from_address):
        parser.error(f"--from-address is not a valid email address: {from_address}")

    if from_address == DEFAULT_FROM and not args.quiet:
        print(
            f"note: introducing ourselves as {DEFAULT_FROM}, which some mail servers refuse.\n"
            f"      set {FROM_ENV_VAR} or pass --from-address with a domain you own "
            f"for better results.",
            file=sys.stderr,
        )

    if args.serve:
        serve(args.port, from_address, args.timeout, args.workers, not args.no_browser)
        return 0

    emails = _split(args.emails) if args.emails else _split(sys.stdin.read().splitlines())
    if not emails:
        parser.error("no addresses given")

    results = verify_many(emails, from_address, args.timeout, args.workers)

    if args.json:
        print(json.dumps([asdict(r) for r in results], indent=2))
    else:
        width = max(len(r.email) for r in results)
        for r in results:
            flags = "".join(f" [{f}]" for f in ("disposable", "role") if getattr(r, f))
            print(f"{r.email:<{width}}  {r.status:<7}  {r.reason}{flags}")

    return 1 if any(r.status == INVALID for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
