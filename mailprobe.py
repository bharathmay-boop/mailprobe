"""Check whether an email address can actually receive mail.

Most checkers stop at the format of the address. This one asks the receiving
mail server directly, and reports "unknown" when the server refuses to say.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import http.server
import json
import re
import secrets
import smtplib
import socket
import sys
import threading
import webbrowser
from dataclasses import asdict, dataclass

import dns.resolver

__version__ = "0.1.0"

VALID = "valid"
INVALID = "invalid"
RISKY = "risky"
UNKNOWN = "unknown"

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
    except (dns.resolver.LifetimeTimeout, dns.exception.Timeout):
        return None, "dns lookup timed out"
    except dns.exception.DNSException:
        return None, "dns lookup failed"

    try:
        resolver.resolve(domain, "A")
        return domain, "no mx record, using the domain itself"
    except dns.exception.DNSException:
        return None, "domain has no mail server"


def probe(
    mx_host: str,
    email: str,
    domain: str,
    from_address: str,
    timeout: float = 10.0,
) -> tuple[int, bool | None]:
    """Ask the mail server about an address without sending anything.

    Returns the reply code for the address, plus whether the domain accepts
    every address it is offered. That second answer is the important one: a
    domain that accepts everything cannot confirm any single mailbox.
    """
    with smtplib.SMTP(timeout=timeout) as smtp:
        smtp.connect(mx_host, 25)
        smtp.ehlo_or_helo_if_needed()
        smtp.mail(from_address)

        code, _ = smtp.rcpt(email)

        try:
            decoy = f"{secrets.token_hex(12)}@{domain}"
            decoy_code, _ = smtp.rcpt(decoy)
            catch_all = decoy_code in ACCEPTED
        except (smtplib.SMTPException, OSError):
            # Some servers hang up after the first recipient. Without the
            # second answer we cannot rule out a catch-all.
            catch_all = None

    return code, catch_all


def decide(code: int, catch_all: bool | None, disposable: bool) -> tuple[str, str]:
    """Turn a server reply into a status and a plain explanation.

    Kept free of network calls so the rules can be tested directly.
    """
    if code in ACCEPTED:
        if catch_all is True:
            return RISKY, "server accepts every address on this domain, so this mailbox cannot be confirmed"
        if catch_all is None:
            return UNKNOWN, "server accepted the address but closed before the catch-all check"
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


def verify(
    email: str,
    from_address: str = "verify@example.com",
    timeout: float = 10.0,
) -> Result:
    """Check one address end to end."""
    email = email.strip()

    if len(email) > MAX_TOTAL or not _SYNTAX.match(email):
        return Result(email, INVALID, "not a valid email address format")

    local, _, domain = email.rpartition("@")
    domain = domain.lower()

    if len(local) > MAX_LOCAL:
        return Result(email, INVALID, "the part before the @ is too long")

    disposable = domain in DISPOSABLE_DOMAINS
    role = local.lower() in ROLE_NAMES

    mx_host, note = find_mx(domain, timeout=timeout)
    if mx_host is None:
        return Result(email, INVALID, note, disposable=disposable, role=role)

    try:
        code, catch_all = probe(mx_host, email, domain, from_address, timeout)
    except (socket.timeout, TimeoutError):
        return Result(
            email, UNKNOWN, "mail server did not respond in time",
            mx=mx_host, disposable=disposable, role=role,
        )
    except (smtplib.SMTPException, OSError) as exc:
        return Result(
            email, UNKNOWN,
            f"could not reach the mail server ({type(exc).__name__}), "
            "outbound port 25 may be blocked on this network",
            mx=mx_host, disposable=disposable, role=role,
        )

    status, reason = decide(code, catch_all, disposable)
    return Result(email, status, reason, mx_host, catch_all, disposable, role)


def verify_many(
    emails: list[str],
    from_address: str = "verify@example.com",
    timeout: float = 10.0,
    workers: int = 5,
) -> list[Result]:
    """Check several addresses at once, keeping the input order."""
    if not emails:
        return []

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(lambda e: verify(e, from_address, timeout), emails))


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
  .row { display:flex; gap:12px; align-items:center; margin-top:14px; }
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
  .why { color:var(--soft); font-size:13.5px; }
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


def serve(
    port: int = 8765,
    from_address: str = "verify@example.com",
    timeout: float = 10.0,
    workers: int = 5,
    open_browser: bool = True,
) -> None:
    """Run the browser interface on this machine.

    Bound to localhost on purpose. This tool opens connections to other
    people's mail servers, so it should not be reachable from the network.
    """

    class Handler(http.server.BaseHTTPRequestHandler):
        def _send(self, code, body, content_type):
            payload = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                self._send(200, PAGE, "text/html; charset=utf-8")
            elif self.path == "/favicon.ico":
                self.send_response(204)
                self.end_headers()
            else:
                self._send(404, "not found", "text/plain; charset=utf-8")

        def do_POST(self):
            if self.path != "/check":
                self._send(404, "not found", "text/plain; charset=utf-8")
                return

            length = int(self.headers.get("Content-Length") or 0)
            if length > 100_000:
                self._send(413, json.dumps({"error": "that is too much text to check at once"}),
                           "application/json")
                return

            try:
                payload = json.loads(self.rfile.read(length) or b"{}")
                emails = _split(str(payload.get("emails", "")).splitlines())
            except (ValueError, TypeError):
                self._send(400, json.dumps({"error": "could not read that input"}), "application/json")
                return

            if not emails:
                self._send(200, json.dumps({"results": []}), "application/json")
                return

            if len(emails) > MAX_PER_REQUEST:
                self._send(200, json.dumps({
                    "error": f"{len(emails)} addresses is too many at once. "
                             f"Check up to {MAX_PER_REQUEST} here, or use the command line for larger lists."
                }), "application/json")
                return

            results = verify_many(emails, from_address, timeout, workers)
            self._send(200, json.dumps({"results": [asdict(r) for r in results]}), "application/json")

        def log_message(self, *args):
            pass  # keep the terminal readable

    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
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
        default="verify@example.com",
        help="address to introduce ourselves with, use a domain you own",
    )
    parser.add_argument("--timeout", type=float, default=10.0, help="seconds to wait per step")
    parser.add_argument("--workers", type=int, default=5, help="how many addresses to check at once")
    parser.add_argument("--serve", action="store_true", help="open the browser interface on this machine")
    parser.add_argument("--port", type=int, default=8765, help="port for --serve")
    parser.add_argument("--no-browser", action="store_true", help="with --serve, do not open a browser window")
    args = parser.parse_args(argv)

    if args.serve:
        serve(args.port, args.from_address, args.timeout, args.workers, not args.no_browser)
        return 0

    emails = _split(args.emails) if args.emails else _split(sys.stdin.read().splitlines())
    if not emails:
        parser.error("no addresses given")

    results = verify_many(emails, args.from_address, args.timeout, args.workers)

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
