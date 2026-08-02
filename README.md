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
| NSIS installer | unpacked, then as above | as deep as what it contains |
| Java archive | decompiled | good |
| Native Windows binary | not possible | signing and hardening flags only |

Installers matter more than that table makes them look, because almost nothing is downloaded
as a bare executable. An installer is a native stub with the application attached, so reading
only the stub writes off everything worth checking. VibeCheck unpacks NSIS installers, which
is what `electron-builder` produces, and then treats what it finds as the artifact it is.
Nothing is executed and nothing is written to disk: the installer is read, never run.

Installers built with Inno Setup, or NSIS installers using solid compression, cannot be
unpacked yet. Those say so rather than reporting an empty result.

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

The scan above is free, needs no account, and sends nothing but package names. Optionally,
you can supply your own Anthropic API key to add a second pass that reads the code and
reasons about it, which is what catches the things a pattern cannot express: a guard that
exists but is incomplete, whether untrusted input can actually reach a dangerous operation,
two individually harmless pieces of code that are unsafe together.

**What is sent.** The files that handle input the application does not control, plus any file
that calls into one a rule flagged. Not the whole application, and not only the lines a rule
matched. Both of those bounds are deliberate:

- Sending only flagged lines would mean the pass could deepen findings you already have and
  never discover one in code no rule happened to hit. Tested against a real application, the
  two issues the pattern rules missed were both in files with zero findings.
- Reading one hop of callers is what makes reachability answerable. The same application had
  an unbounded stack allocation recorded as a local-only crash risk; it was reachable from a
  remote HTTP response, and the file that proved it was one call away.

The report lists exactly which files were read and how much the pass cost.

**Bounds on it.** Off unless you tick it, per scan, and never on an isolated scan. Your key
is encrypted to your Windows account and stored outside the application folder. Findings from
this pass are labelled as inferred, carry a confidence level, and **can never trigger a "do
not install" verdict** — the strongest claim in a report must not depend on whether the reader
happened to have an API key.

## Status

Early development. The analysis core, the rule set, the desktop interface and the optional
deep pass are implemented and tested. Releases are not yet code-signed.

## Building

Requires the .NET 10 SDK.

```
dotnet test
dotnet run --project VibeCheck.App
```

A release build is a single self-contained `VibeCheck.exe` with no runtime to install:

```
dotnet publish VibeCheck.App -p:PublishProfile=win-x64 -o <output folder>
```
