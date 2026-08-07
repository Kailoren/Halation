
<div align="center">

# VibeCheck
[![License](https://img.shields.io/github/license/kailoren/vibecheck?style=plastic)](LICENSE)
[![Release](https://img.shields.io/github/v/release/kailoren/vibecheck?style=plastic)](https://github.com/kailoren/vibecheck/releases/latest)
![Platform](https://img.shields.io/badge/platform-Windows-blue?style=plastic)

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/T3N624MRS4)

A drag-and-drop security scanner for AI-generated applications.

Drop in an app, and VibeCheck recovers what source it can, checks it against the
vulnerability classes AI code generators actually produce, and reports what it found and
what it could not reach.

All analysis happens on your machine. The only thing that ever leaves it is the list of
package names and versions the application declares, sent to check them against published
advisories, and that can be turned off entirely. Your code is never uploaded. VibeCheck also
asks GitHub what the newest release is when it starts, which sends nothing at all and is
likewise switchable.

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
  lift an app that ships a live API key out of the red band. There is **one score**, and it is
  the worse of the two readings: the artifact is scored both as a question about shipping it
  and as a question about running it, and the harsher answer is the one both reports print.
  Otherwise an author could scan their own work, switch to the reader it treats more kindly,
  and screenshot a number produced for a question they were not asking. Which findings appear,
  how they are worded, what can be done about them and what order they come in all still change
  with the reader. Only the number does not, and the report says what both readings were.
- **A number that means the same thing in everybody's report.** The score comes from the
  deterministic checks alone. Whatever the optional AI pass finds is reported in full and never
  moves it, because a number that changed with whichever model you had configured could not be
  compared with anyone else's. What the AI keeps is the power to withhold the all-clear: a
  result cannot be labelled clean while its suggestions are sitting underneath it.
- **A coverage figure**, kept deliberately separate from the score, saying how much of the
  application could actually be read. A clean result at 12% coverage is a different claim
  from a clean result at 95%. Coverage measures what was *understood*, not what was written
  out: an obfuscated application decompiles into thousands of files of `a.b(c)`, none of which
  count, so it gets no score at all rather than a good one.
- **What could not be checked**, listed explicitly, so a short findings list is never
  mistaken for a clean bill of health. When a whole class of check could not run at all, such
  as dependencies in an application that ships no lock file, that is said beside the score
  rather than four sections below it: a shipped application can otherwise score 100 under "no
  known issues found", beside a coverage meter reading 100% readable, while nothing whatever
  is known about the packages inside it.
- **What the application can do**, listed separately and scored nowhere. Updating itself and
  starting with Windows are how a great many correct programs work, so charging them a band of
  score was a scanner calling a feature a fault. They are still reported, and for somebody
  deciding whether to run a download they can be the most useful lines in it: an application
  that replaces its own code is one whose future behaviour no scan of it describes.

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

## Languages and package managers

Source is read for C#, JavaScript, TypeScript, Python, Java and Kotlin, plus JSON, YAML, TOML,
XML, HTML, Vue, Svelte, XAML, shell scripts and `.env` files. Go, Rust, PHP, Ruby, Swift, Dart,
C, C++, Objective-C, SQL, GraphQL, Razor, Astro, Scala, Elixir, Clojure, F# and Haskell are read
too, in a bucket with no rules written for their idioms.

That last distinction matters and is worth stating plainly. **33 of the 39 rules carry no
language filter**, so a Go or Rust file gets every secret, configuration and malicious-behaviour
check. What it does not get is the injection rules keyed to C# and JavaScript syntax: SQL built
by joining strings is caught in Go, and missed in PHP, because PHP concatenates with `.` and the
pattern was written for `+`. More patterns, not a closed door.

A compiled native binary remains unreadable, whatever produced it. A Go or Rust executable has
nothing to decompile, and the report says so rather than reporting an empty result.

Dependencies are resolved from `package-lock.json`, `yarn.lock` (classic and Berry),
`pnpm-lock.yaml`, vendored `node_modules` manifests, `*.deps.json`, `packages.lock.json`,
`requirements.txt`, `Pipfile.lock`, `go.sum`, `Cargo.lock`, `poetry.lock`, `composer.lock`,
`Gemfile.lock` and `gradle.lockfile`, covering npm, NuGet, PyPI, Go, crates.io, Packagist,
RubyGems and Maven. A
lock file is the only artifact that says what a project actually installed rather than what it
asked for, which is the difference between a dependency that can be checked and one that cannot.

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

<img width="1120" height="997" alt="Screenshot 2026-08-06 224153" src="https://github.com/user-attachments/assets/5b003aec-85b2-47b4-94f2-c4d41b038b23" />

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

### Point it at your source, not your release build

The AI pass reasons about intent, and **decompiling a binary destroys every comment in it**. On a
real application whose source was to hand, three findings from a frontier model against the
decompiled release were checked line by line and all three were wrong, each one answered by a
comment the author had already written and the decompiler had thrown away. The deterministic
checks are unaffected, since a pattern does not care about comments.

So scan the source tree when you have it. The pattern checks give the same answer either way; the
AI half is a much better instrument when the reasoning is still in the file.

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

## Scanning a scanner

A detection tool is a program whose source contains, in quotation marks, every string it looks
for. Pointed at its own published build VibeCheck used to score 16/100 and advise against
installing itself, on nine findings that were all its own rule table read as the behaviour the
rules describe. Antivirus signatures, WAF rules and linter configurations all have this shape.

A match is discounted when it sits inside a string literal **and** that string is either being
handed to a regex constructor or surrounded by enough other pattern definitions to be a
catalogue of them. Ordinary code satisfies neither: a real `new BinaryFormatter()` is not in
quotes, and a real registry path in quotes does not sit in a file of forty regexes. Measured
across four hand-written applications, nothing was discounted in any of them.

**The count is on the receipt.** A tool that quietly removes its own findings is asking to be
trusted about the one thing nobody can check, so the report says how many matches it discounted
and why. Secrets are exempt: a credential in quotation marks is a leaked credential wherever it
lives, including in the source of a security tool.

## The progress bar takes longer than the scan

A scan of a typical application finishes in a second or two, and in testing nobody believed it.
The results screen says exactly what was examined and how much of it was readable, but a reader
who watched the bar flash past has already decided nothing happened and does not go looking.

So the readout is paced: between five and twenty seconds depending on how much there was to
look at, with each stage on screen while the bar is inside that stage's share of the whole.
**The work is not slowed and nothing is invented.** The bar shows the lower of two figures, how
far the scan has actually got and how far there has been time to read, which means it can never
claim progress that has not happened and never finishes before its stages can be read. A scan
that genuinely takes longer than that, such as one running the deep pass, is not padded at all;
the bar simply follows it.

The duration in the report is the real one, so a report saying `0.8s` after a twelve second bar
is not a contradiction. The receipt records the work; the bar reports it at reading speed.

## Updates

On startup VibeCheck asks GitHub for the public release list and compares it with the build
you are running. A newer one gets a strip across the top of the window. Nothing about you or
the machine is sent, the comparison happens locally, and the whole check can be switched off
on the drop screen.

**It will not install a build it cannot verify.** VibeCheck's own `VC-MAL-007` tells other
applications that an updater must check what it downloaded against a signature, and not
against a hash served from the same place as the file, so this one is held to that: a download
is installed only when Windows validates its Authenticode signature and the signer matches the
publisher who signed the copy already running. Until releases are code-signed there is no such
publisher, so the strip announces the version and links to the release page rather than
offering to install it. The refusal is stated on screen instead of the button quietly being
absent.

When an update is installed, the old build is renamed aside, the new one takes its place, and
VibeCheck restarts into it. The next launch deletes what was moved. A build running from its
own build output, or from a folder it cannot write to, declines to replace itself and says so.

Prereleases are offered only to somebody already running one. A release build is never moved
onto a beta because the number happens to be larger.

## Status

Early development. The analysis core, the rule set, the desktop interface and the optional
deep pass are implemented and tested. Releases are not yet code-signed, which is also what
stops the updater installing anything on its own; see above.

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

## Supporting it

[**Ko-fi**](https://ko-fi.com/kailodev), if you would like to. Nothing is behind it and nothing
will be: there is one build, everything in it is unlocked, and the licence is MIT either way.
This is one person's work, and what it costs is time and the occasional certificate.

The most useful thing you can send costs nothing at all, which is an application this tool got
wrong. See [CONTRIBUTING.md](CONTRIBUTING.md) for why that beats a patch here.
