# VibeCheck

A drag-and-drop security scanner for AI-generated applications.

Drop in an app, and VibeCheck recovers what source it can, checks it against the
vulnerability classes AI code generators actually produce, and reports what it found and
what it could not reach.

It runs fully offline. Nothing is uploaded, and the vulnerability database ships inside the
application so scans work in an air-gapped environment.

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
