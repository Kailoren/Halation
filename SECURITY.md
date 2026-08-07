# Security

## Reporting a vulnerability

Use **[private vulnerability reporting](https://github.com/kailoren/vibecheck/security/advisories/new)**
on this repository. It goes to the maintainer and stays private until there is something to
publish. Please do not open a public issue or discussion for a flaw in VibeCheck itself.

This is a one-person project, so there is no response-time commitment I could make and keep. What
I will do is acknowledge the report, tell you honestly whether I think it is a real problem, and
say what I intend to do about it.

## What counts

VibeCheck exists to be pointed at files nobody trusts. It opens installers, unpacks archives,
reads bundles out of executables and decompiles assemblies, on purpose, and usually because
somebody already suspects the thing they downloaded. **That recovery path is the real attack
surface, and it is the part worth attacking.**

Reports about it are exactly what this page is for:

- A crafted archive, installer or bundle that makes VibeCheck write outside the directory it was
  given, execute anything, or read a file it was not pointed at
- Anything that turns scanning a hostile artifact into running it
- A path that leaks the stored API key, the endpoint key, or the recovered source of a scanned
  application to somewhere it was not sent deliberately
- A way to make the deep pass send files to an endpoint other than the configured one
- A crash or resource exhaustion reachable from a scanned file, if it can be steered rather than
  merely triggered

The dependency surface counts too. If a package this application ships has an advisory that
reaches it in practice, that is worth reporting, and saying how it is reached is what makes the
report actionable.

## What does not count

**A wrong scan result is not a vulnerability in VibeCheck.** A missed flaw, a false positive, a
score you disagree with, or an artifact it declined to read are all ordinary defects, and they are
the most useful thing you can send. They belong in
[Discussions](https://github.com/kailoren/vibecheck/discussions), under "It got this wrong", where
they can be argued about in the open.

That distinction matters more here than in most projects, because for a scanner almost anything
can be described as a security issue. The question this page is asking is narrower: **can an
application being scanned do something to the person scanning it?** If it can, report it
privately. If instead the tool simply judged something incorrectly, that is a defect worth fixing
in public.

Two related things that are also not vulnerabilities, because they are documented behaviour:

- **The deep pass uploads recovered source** to whichever endpoint is configured, when it is
  switched on. That is what it is for, it is off by default, and what leaves the machine is stated
  on screen before a scan and in the report afterwards.
- **VibeCheck reports its own findings against itself.** The rule table contains the patterns it
  looks for, so a scanner scanning a scanner sees them. Matches discounted for that reason are
  counted and printed on the receipt rather than removed quietly.

## Supported versions

Pre-1.0, so only the latest release is supported. There are no backports; if a fix matters it goes
into the next release.

Releases are not code-signed yet. Until they are, SmartScreen will warn on download, and the
in-application updater deliberately refuses to install an update it cannot hold to a publisher,
announcing the new version and linking the release page instead. That refusal is the intended
behaviour rather than a bug.

## Scope

This policy covers the VibeCheck application and this repository, including the website under
`docs/`. It does not cover the applications you scan with it, or the third-party model endpoints
you may configure the deep pass to use.
