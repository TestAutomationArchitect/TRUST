# Acceptable use

TRUST is licensed under [Apache-2.0](LICENSE). That licence governs copying, modification
and redistribution of the **software**. It says nothing about which **systems** you may point
it at — and it cannot, because that is a question of authorisation, not copyright.

These terms are therefore separate from the licence. They are not a licence restriction and
do not modify Apache-2.0; they are the conditions under which running TRUST is legitimate.

## Run it only against systems you are authorised to test

TRUST sends live requests: it attempts cross-user reads, submits spoofed identities, invokes
LLM agents with injection payloads, and requests sensitive paths. Against a system you do not
own or have written permission to test, that is unauthorised access under, among others, the
UK Computer Misuse Act 1990, the US Computer Fraud and Abuse Act, and equivalent law in most
jurisdictions.

Before a run, you should have:

- **Written authorisation** naming the target environment, from someone entitled to give it —
  the system owner, not only your own manager.
- **A scope** that matches `targets.allowedHosts`. That allowlist is the technical boundary of
  your authorisation, so keep the two identical.
- **Test identities you were issued for this purpose.** Do not use another person's account,
  and never use a real customer's credentials.
- **A window and a contact**, so unusual traffic is not mistaken for an incident.

## What the harness enforces for you

These are guard rails, not permission. They reduce the chance of accidental harm; they do not
make an unauthorised run acceptable.

| Guard | Effect |
|---|---|
| Host allowlist | Requests to any other host are refused before leaving the process |
| Production block | `prod`/`production`/`live` environments and hostnames are refused unless `safety.productionOverride` is explicitly set |
| Request cap and delay floor | Bounded volume and rate, so a run cannot degrade a service |
| Writes off by default | `PUT`/`PATCH`/`DELETE` and write-marked `POST`s need `safety.allowWrites` |
| Agent invocations off by default | Live LLM calls need `safety.allowAgentInvocations` |
| HTTPS-only, manual redirects | No plaintext traffic; redirects are observed, never followed |

**`productionOverride` is not a convenience flag.** Set it only with written authorisation for
that specific production system, and prefer a staging environment that mirrors it.

## Do not

- Test third-party services, SaaS platforms or partner systems that you do not control,
  including any host reachable through your target. Bug-bounty scope is not a substitute for
  a scope agreement with the system's owner.
- Use TRUST to exfiltrate real data. The probes are designed to prove a boundary is missing,
  not to collect what is behind it — if a cross-user probe fails, stop and report; do not
  enumerate further.
- Weaken the guards to reach more surface. If a probe cannot run inside the safety limits, the
  answer is a narrower scope or a proper test environment, not a raised cap.
- Route a run through an anonymising proxy or from infrastructure that misrepresents its
  origin. Testing should be attributable to you.

## Handling what you find

- Reports are classified **Internal — Security Sensitive** and are written `0600`. Treat them
  as you would a penetration-test report.
- Evidence is redacted automatically, but redaction is best-effort pattern matching. Read a
  report before you forward it.
- Disclose findings to the system owner through their vulnerability-management process, and
  give them time to remediate before wider circulation.
- A `SKIP` is not a `PASS`. Do not report an unvalidated control as verified.

## Contributions

By contributing you confirm that any probe you add is safe by default: it degrades to `SKIP`
without credentials, respects every safety guard, needs no write access unless explicitly
gated, and cannot cause data loss on a target. See [CONTRIBUTING.md](CONTRIBUTING.md).
