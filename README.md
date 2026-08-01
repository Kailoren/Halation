# VibeCheck

A drag-and-drop security scanner for AI-generated applications.

Drop in an app, and VibeCheck recovers what source it can, checks it against the
vulnerability classes AI code generators actually produce, and reports what it found and
what it could not reach.

All analysis happens on your machine. The only thing that ever leaves it is the list of
package names and versions the application declares, sent to check them against published
advisories, and that can be turned off entirely. Your code is never uploaded.

## Who it is for

**Before you ship.** Run your own app through it as a final check. AI-generated code has been
measured at roughly 2.7x the vulnerability rate of hand-written code, and the failures are
predictable: keys committed to the bundle, database row-level security left off, API routes
with no authentication, dependencies years out of date.

**Before you install.** Run something you downloaded through it. For Electron and .NET
applications, VibeCheck recovers the real application code from the shipped binary and reads
it, rather than trusting the description on a download page.

## What it does not do

**It cannot tell you an application is safe.** Static analysis can demonstrate that bad
patterns are present; it can never demonstrate that none are. A deliberately malicious app
will read cleaner than a sloppy honest one.

So VibeCheck does not print a verdict of "safe". It reports:

- **A score out of 100**, capped by the single worst issue found. Fifty passing checks cannot
  lift an app that ships a live API key out of the red band.
- **A coverage figure**, kept deliberately separate from the score, saying how much of the
  application could actually be read. A clean result at 12% coverage is a different claim
  from a clean result at 95%.
- **What could not be checked**, listed explicitly, so a short findings list is never
  mistaken for a clean bill of health.

An explicit "do not install" is triggered only by specific, high-confidence deterministic
rules, never by the score alone.

## Recovery depth by artifact type

| Artifact | Recovery | Depth |
|---|---|---|
| Source folder, zip, or repository | read directly | full |
| .NET executable or library | decompiled (ILSpy) | full, near-original C# |
| Electron application or `.asar` | unpacked | full, often unminified |
| Java archive | decompiled | good |
| Native Windows binary | not possible | signing and hardening flags only |

## Dependency checks and isolate mode

Out-of-date dependencies are one of the most common real problems in shipped applications,
so VibeCheck checks them against [OSV.dev](https://osv.dev) **at the moment you scan**. A
vulnerability database bundled into a release is out of date the day it ships, and findings
cite CVE identifiers and link through to the NVD entry.

What is sent: the package names and versions the application declares, and nothing else. No
source, no file contents, nothing identifying you or the artifact.

**Isolate mode** exists for the case that matters most: a normal scan flags something, and
you want to examine it on a machine deliberately cut off from everything.

1. Scan normally. A small **data bundle** is written beside the artifact, holding its hash,
   its dependency list, and the advisories that matched.
2. Carry the artifact and the bundle to the isolated machine.
3. Scan there with isolate mode on. **No network request is made at all**, and you get the
   same dependency result, with the hash proving the bundle belongs to that artifact.

A bundle is typically a few hundred kilobytes, against 1.3 GB for the whole database.

For a machine that will never see a network, you can instead download a local mirror,
choosing the ecosystems you care about: NuGet is around 2 MB, PyPI 31 MB, npm 203 MB.

Every report states which of these it used and how old the data was. A result checked
against a database three months old is a weaker claim than one checked a second ago, and
you should not have to guess which you are reading.

## Optional deep pass (bring your own key)

The scan above is free, offline, and needs no account. Optionally, you can supply your own
Anthropic API key to add a second pass that catches logic flaws pattern rules cannot express.

This is off by default and entirely optional. The key stays on your machine, only regions
already flagged by the deterministic pass are sent, and findings from this pass are labelled
as inferred and can never trigger a "do not install" verdict.

## Status

Early development. The analysis core is implemented and tested; the user interface and
rule set are in progress.

## Building

Requires the .NET 10 SDK.

```
dotnet test
dotnet run --project VibeCheck.App
```
