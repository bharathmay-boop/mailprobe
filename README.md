# mailprobe

Check whether an email address can actually receive mail, and say "unknown" when that cannot be determined.

## The problem

Most email checkers only look at the shape of the address. They confirm there is text, an @ sign, and a domain, then report the address as valid. That check passes for addresses that will bounce the moment you send to them.

The tools that go further have a second problem. Many domains are configured to accept every address offered to them, a setup called catch-all. On those domains, asking the mail server whether a mailbox exists always returns yes. Plenty of verifiers take that yes at face value and report the address as valid.

Here is what that looks like in practice. These three addresses are invented, and every one of them is accepted by the receiving server:

```
$ mailprobe zzq7x2random@sendgrid.com,zzq7x2random@cloudflare.com,zzq7x2random@shopify.com

zzq7x2random@sendgrid.com    risky  server accepts every address on this domain, so this mailbox cannot be confirmed
zzq7x2random@cloudflare.com  risky  server accepts every address on this domain, so this mailbox cannot be confirmed
zzq7x2random@shopify.com     risky  server accepts every address on this domain, so this mailbox cannot be confirmed
```

A checker that reports those as valid is not verifying anything. It is guessing, and passing the guess off as a result.

## What this does instead

mailprobe runs four checks in order and stops as soon as it has a definite answer.

1. Format. Does the address follow the rules for a real address, including the length limits.
2. Mail server. Does the domain publish a mail server. If there is no MX record it falls back to the domain's A record, which the mail standard allows and many small domains depend on.
3. Mailbox. It opens a conversation with the mail server and asks about the address, then disconnects. No mail is ever sent.
4. Catch-all. It asks the same server about a randomly generated address that cannot exist. If the server accepts that one too, the answer to question 3 was meaningless, and the result is reported as risky rather than valid.

## Results

| Status | Meaning |
|---|---|
| `valid` | The server confirmed this mailbox exists and does not accept every address. |
| `invalid` | The format is wrong, the domain has no mail server, or the server rejected the address outright. |
| `risky` | The address may work, but it cannot be confirmed. Catch-all domains and throwaway mail services land here. |
| `unknown` | The server would not answer. It asked us to retry later, hung up, or could not be reached. |

The `unknown` status is deliberate. A server that refuses to answer has told you nothing, and recording that as either valid or invalid loses information you might act on later. Temporary rejections are the common case here. Many servers reply "try again later" to any sender they have not seen before, which is a delay tactic, not a rejection.

Two extra flags are reported alongside the status. `role` marks addresses like support@ or info@ that usually reach a team rather than one person. `disposable` marks throwaway mail services. Neither is a failure on its own, so they are reported separately and you decide what they mean for your use.

## Install

```bash
git clone https://github.com/bharathmay-boop/mailprobe.git
cd mailprobe
pip install .
```

Python 3.9 or newer. The only dependency is dnspython, used for the mail server lookup.

## Use

Check one address, or several separated by commas:

```bash
mailprobe someone@example.com
mailprobe "first@example.com,second@example.com"
```

Read a list from a file, one address per line:

```bash
cat addresses.txt | mailprobe
```

Get JSON back for use in another program:

```bash
mailprobe --json someone@example.com
```

From Python:

```python
from mailprobe import verify

result = verify("someone@example.com")
print(result.status, result.reason)
```

### Options

| Option | Default | What it does |
|---|---|---|
| `--from-address` | `verify@example.com` | The address used to introduce ourselves to the mail server. Set this to a domain you own. |
| `--timeout` | `10` | Seconds to wait for each step. |
| `--workers` | `5` | How many addresses to check at the same time. |
| `--json` | off | Print results as JSON. |

## Things worth knowing before you rely on this

**Outbound port 25 is blocked on most hosted platforms.** This is the big one. Checking a mailbox requires talking to the receiving mail server on port 25, and AWS, Google Cloud, Azure, Vercel, and most shared hosting block that by default to limit spam. On those platforms every check returns `unknown`. mailprobe is built to run from a machine where port 25 is open, such as a local computer or a server where the block has been lifted. This is a limit of how mail works, not something the code can route around.

**Set `--from-address` to a domain you control.** Mail servers check who is asking. Leaving the default in place will get you turned away more often.

**Go gently on volume.** Checking thousands of addresses from one IP address in a short window looks like the behaviour of a spammer, and mail servers will start refusing you. Lower `--workers` for large lists.

**Large providers vary.** Gmail answers honestly about whether a mailbox exists. Some other large providers accept everything at this stage and reject later, which means an honest result for them is `risky`, not `valid`. That is the correct answer, not a gap.

**The throwaway domain list is a starter set.** It covers the services that show up most often. If you need full coverage, the [disposable-email-domains](https://github.com/disposable-email-domains/disposable-email-domains) project maintains a much longer list you can load in.

## Running the tests

```bash
python test_mailprobe.py
```

The tests cover format rules and how server replies map to a status, and do not touch the network.

## Licence

MIT. See [LICENSE](LICENSE).
