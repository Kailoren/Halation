# Contributing

Short version: **pull requests are closed, issues and discussions are open, and the most useful
thing you can send is an application this tool got wrong.**

## Why there are no pull requests

Halation is maintained by one person, and it is a security tool. Those two facts together decide
this.

A merged pull request ships in the release that carries my name and, in time, my signing
certificate, to people who are running the tool precisely because they want to know whether
something is trustworthy. A change to the rule table can suppress findings as easily as add them,
and a narrowed regex that looks like a tidy-up is exactly the shape a bad-faith change would take.
Reviewing every contribution to that standard is not something I can promise to keep up, and a
pull request that sits unreviewed for months is worse for you than one I never accepted.

So the guarantee is deliberately simple: every line in a Halation release was written by its
maintainer.

**This costs you nothing.** The licence is MIT. Fork it, change whatever you like, ship your own
build. Nothing here restricts what you can do with the code; it only decides what goes out under
this name.

## What is actually worth sending

**Evidence beats patches here.** Nearly every real improvement to this tool came from pointing it
at a real application and finding it wrong, not from someone editing a rule:

- A shipped app read as 100/100 while carrying four separately vulnerable packages, which is how
  dependency resolution from vendored manifests got written.
- A high severity on ordinary auto-update behaviour, which is how capabilities stopped being
  counted as defects.
- A score of 58 that looked like noise and turned out to be a real bug, which is how that rule
  survived being softened.

None of those arrived as code. They arrived as somebody saying "look at what it did to this".

### A result that looks wrong

The most valuable report there is. Please include:

- What you scanned, and where it came from, ideally with a link if it is public
- The score and the finding, or the finding you expected and did not get
- Why you think it is wrong

If it is your own application and you can share the source, say so. A false positive is usually
much easier to settle against real source than against a decompiled binary.

### A check it should have

Say what the flaw is and how it shows up in real code, rather than supplying a regex. What decides
whether a rule can exist is not the pattern, it is whether the two severity judgments can be made
honestly and whether it will fire on ordinary code.

### A file type it cannot read

Coverage is bounded by what can be recovered, not by the rule table. If it declined to read
something, that is worth knowing, and so is the artifact.

## Reporting a security flaw in Halation itself

Not in a public issue, please. Use GitHub's private vulnerability reporting on this repository, so
there is time to fix it before it is described in public.

## If you fork it

Everything you need is in the repository, but two things are not obvious:

- **`docs/assets/js/rules.json` is generated, not written.** It comes from
  `RuleEngine.DefaultRules`, so the published rule reference cannot drift from the checks that
  actually run. Regenerate it whenever a rule is added, removed, retitled or re-rated;
  `docs/README.md` has the procedure.
- **Every rule must judge both readings.** `Finding.UserSeverity` and `UserDescription` are
  required rather than optional, so that a new rule cannot quietly inherit the developer's answer
  for the person who merely downloaded the application. A leaked key is critical for whoever ships
  it and close to nothing for whoever runs it, and the rule table is where that gets decided.

Build and test:

```
dotnet test
```

The suite is the contract. If it passes, the behaviour the project promises is intact; if you
change what a rule reports, expect to change a test that says so on purpose.
