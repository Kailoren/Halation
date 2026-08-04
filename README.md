# VibeCheck

A drag-and-drop security scanner for AI-generated applications.

Drop in an app, and VibeCheck recovers what source it can, checks it against the
vulnerability classes AI code generators actually produce, and reports what it found and
what it could not reach.

All analysis happens on your machine. The only thing that ever leaves it is the list of
package names and versions the application declares, sent to check them against published
advisories, and that can be turned off entirely. Your code is never uploaded.

<img width="1116" height="815" alt="mainscreen" src="https://github.com/user-attachments/assets/c418a6d9-0c95-49c2-92fd-b0e18dbf6ecb" />

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
  from a clean result at 95%. Coverage measures what was *understood*, not what was written
  out: an obfuscated application decompiles into thousands of files of `a.b(c)`, none of which
  count, so it gets no score at all rather than a good one.
- **What could not be checked**, listed explicitly, so a short findings list is never
  mistaken for a clean bill of health.

An explicit "do not install" is triggered only by specific, high-confidence deterministic
rules, never by the score alone.

<img width="1114" height="1038" alt="scanresults" src="https://github.com/user-attachments/assets/194d0b7d-7bd6-423d-b2d1-c5d0ffc90ad5" />

## Recovery depth by artifact type

| Artifact | Recovery | Depth |
|---|---|---|
| Source folder, zip, or repository | read directly | full |
| .NET executable or library | decompiled (ILSpy) | full, near-original C# |
| Electron application or `.asar` | unpacked | full, often unminified |
| NSIS installer | unpacked, then as above | full for Electron and .NET payloads |
| Java archive | decompiled | good |
| Native Windows binary | not possible | signing and hardening flags only |

Installers matter more than that table makes them look, because almost nothing is downloaded
as a bare executable. An installer is a native stub with the application attached, so reading
only the stub writes off everything worth checking. VibeCheck unpacks NSIS installers, which
is what `electron-builder` produces, and hands each payload to the recovery it deserves: an
asar to the Electron reader, a .NET assembly or single-file bundle to the decompiler.
Nothing is executed and nothing is written to disk: the installer is read, never run.

A payload that is a native binary still yields nothing, because nothing can decompile one.
The report says that in those words rather than reporting an empty result, so a low coverage
figure on an installer means "this was not examined" and never "this was examined and was
clean".

Installers built with Inno Setup, or NSIS installers using solid compression, cannot be
unpacked yet. Those say so rather than reporting an empty result.

## Dependency checks

Out-of-date dependencies are one of the most common real problems in shipped applications,
so VibeCheck checks them against [OSV.dev](https://osv.dev) **at the moment you scan**. A
vulnerability database bundled into a release is out of date the day it ships, and findings
cite CVE identifiers and link through to the NVD entry.

What is sent: the package names and versions the application declares, and nothing else. No
source, no file contents, nothing identifying you or the artifact.

**This is the one part of a scan that needs a network.** With no connection, dependencies are
not checked and the report says so rather than reporting no known vulnerabilities. There is no
offline database to download: bundling one, or shipping a mirror to keep in sync, was tried and
removed, because a vulnerability database is out of date the day it ships and a stale answer
here is worse than an absent one.

Every report states which source it used and when the data was current, so a check that could
not run is never mistaken for one that came back clean.

## Optional deep pass

<img width="1117" height="819" alt="deepscan" src="https://github.com/user-attachments/assets/2591fb74-a535-4a77-93fb-085d3fd7156b" />

The main scan is free, needs no account, and sends nothing but package names. Optionally, a
second deep pass reads the code and reasons about it, which is what catches the things a pattern
cannot express: a guard that exists but is incomplete, whether untrusted input can actually
reach a dangerous operation, two individually harmless pieces of code that are unsafe together.

It is off unless you turn it on, per scan, and there are two ways to power it. Both use Claude
Opus. **They differ in whose account pays and in what that costs you.**

### Route 1: connect the Claude Code you already have

VibeCheck looks for Claude Code when it starts, including the copy bundled inside the Claude
desktop app, and asks it whether it is signed in. That happens on its own, with nothing to click
and nothing to configure, and **Claude Code does not need to be running**. If it is installed and
signed in, the app says so and the route is ready; if it is installed but signed out, a **Sign
in** button appears and opens Claude Code's own sign-in for you. VibeCheck never sees your
credentials. The CLI holds them, exactly as it does when you use it directly.

**Detection still does not mean a scan will use it.** The deep pass is a tick box, off by
default, and no scan sends anything anywhere until you tick it. What being signed in buys you is
that ticking the box is the only thing you have to do: the route is chosen for you, so there is
no second setting to find.

One thing worth knowing: the check runs once, at startup. Sign in to Claude Code while VibeCheck
is already open and it will not notice until you press **Sign in** or restart it.

**This spends the usage allowance of the Claude subscription you already pay for.** Nothing is
charged on top. A deep pass is a handful of requests, so on a Pro or Max plan it is a small
share of a day's allowance, but it does come out of the same pot as your own work with Claude,
and a large application read at the file ceiling will make a dent in it.

The report says which installation answered, and states plainly that no money was charged.

### Route 2: bring your own Anthropic API key

Paste an API key from the [Anthropic Console](https://console.anthropic.com) and VibeCheck calls
the API directly.

**This costs real money, every scan.** The API is billed per token against credit you buy up
front; it is a separate product from a Claude subscription, with separate billing and no bridge
between the two, so a Pro or Max plan does not cover it and its allowance is not touched. A
typical pass over a dozen files runs to a few cents, and the report prints the estimate with the
tokens it is based on, so you can see what a scan cost rather than find out at the end of the
month.

Your key is encrypted to your Windows account and stored outside the application folder. It is
never written to a report, and the interface only ever shows it masked.

### Both routes are for applications you built

The deep pass is offered in **developer mode only**. Checking something you downloaded runs
entirely on this machine, with no account, no key and nothing leaving it.

For the API route that is a decision about what the window offers. **For the Claude Code route
it is a refusal enforced in the core**, and the reason is worth stating: Claude Code is an agent
with shell and filesystem access, and the API is an endpoint that cannot execute anything.
Feeding source recovered from software you do not trust into something that can act on your
machine is the attack this tool exists to warn people about. The scanned program never has to
run, because getting VibeCheck to read it becomes the attack instead.

Where it is used, that agent is fenced in: no tools, safe mode, an empty working directory, no
session persistence, and the file content arrives on standard input rather than on a command
line other processes can read.

**What is sent.** The files that handle input the application does not control, plus any file
that calls into one a rule flagged. Not the whole application, and not only the lines a rule
matched. Both of those bounds are deliberate:

- Sending only flagged lines would mean the pass could deepen findings you already have and
  never discover one in code no rule happened to hit. Tested against a real application, the
  two issues the pattern rules missed were both in files with zero findings.
- Reading one hop of callers is what makes reachability answerable. The same application had
  an unbounded stack allocation recorded as a local-only crash risk; it was reachable from a
  remote HTTP response, and the file that proved it was one call away.

The report lists exactly which files were read, what answered, and what the pass cost.

**Bounds on it.** At most 40 files per scan, whichever route answers, so neither your allowance
nor your credit can run away on one large application. Findings from this pass are labelled `AI`,
carry a confidence level, and low-confidence ones are dropped rather than hedged. None of them
can **trigger a "do not install" verdict**, because the strongest claim in a report must not
depend on whether the reader happened to have a key or a subscription.

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
