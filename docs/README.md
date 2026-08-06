# The VibeCheck website

Static HTML, no build step. GitHub Pages serves this folder as it stands.

Six pages: `index`, `docs`, `setup`, `rules`, `faq`, `changelog`. The navigation and footer are
repeated in each file rather than shared, because there is no build step to share them with;
changing a nav item means changing it in six places.

## Publishing it

In the repository's **Settings → Pages**, set the source to **Deploy from a branch**, branch
`main`, folder `/docs`. The site appears at `https://kailoren.github.io/VibeCheck/`.

Every path in here is relative, so the site works from that subfolder, from the root of a custom
domain, or from a local server, without anything being edited. To attach a custom domain later,
add a `CNAME` file to this folder containing the bare hostname and point a DNS `CNAME` record at
`kailoren.github.io`.

**The one absolute URL in the site is `og:image`.** A social scraper does not resolve a
relative image path, so those tags name `https://kailoren.github.io/VibeCheck/` in full. If the
site ever moves to a custom domain, that base has to be updated in all six pages; everything
else is relative and moves on its own.

`.nojekyll` stops GitHub running the pages through Jekyll first. Nothing here needs it, and
skipping it makes deploys quicker.

## Regenerating the rule reference

`assets/js/rules.json` is generated from `RuleEngine.DefaultRules`, not written by hand, so
`rules.html` cannot drift away from the checks the scanner actually runs. **Regenerate it
whenever a rule is added, removed, retitled or re-rated.**

A throwaway console project that references `VibeCheck.Core` does it:

```csharp
var rules = RuleEngine.DefaultRules
    .OfType<PatternRule>()
    .Select(r => new
    {
        id = r.Id,
        family = RuleFamily.PrefixOf(r.Id),
        familyName = RuleFamily.NameOf(r.Id),
        title = r.Title,
        category = r.Category.ToString(),
        severity = r.Severity.ToString(),
        userSeverity = r.UserSeverity.ToString(),
        description = r.Description,
        userDescription = r.UserDescription,
        remediation = r.Remediation,
        userRemediation = r.UserRemediation,
        blocking = r.IsBlocking,
        capability = r.IsCapability,
        accountableAs = r.Capability?.ToString(),
        languages = r.Languages?.Select(l => l.ToString()).ToArray(),
        reference = r.Reference,
    })
    .ToArray();
```

Serialised with `WriteIndented`, `JsonIgnoreCondition.WhenWritingNull` and
`JavaScriptEncoder.UnsafeRelaxedJsonEscaping`, alongside a `families` array built from
`RuleFamily.NameOf` and `RuleFamily.DescribeOf`. The page reads `rules`, `families` and nothing
else, so extra keys are harmless.

The five families with no rule list of their own — `DEP`, `PKG`, `BIN`, `DUP`, `AI` — are
described on the page but not enumerated, because their checks are produced by the recovery,
packaging and dependency stages rather than declared in a table.

## Screenshots

`assets/img/screen-*.png` are real renders of the real windows, produced by a throwaway WPF
harness that constructs the app's own `Application` subclass, shows each window off every
monitor with `ShowActivated = false`, and captures it with `RenderTargetBitmap`. See
`reference-wpf-screenshot-without-focus` for the traps; the two that cost the most time:

- A window that is measured and arranged but never shown renders a **blank** bitmap. It has to
  be shown, just somewhere nothing can see it.
- Without `Application.Run`, no dispatcher synchronization context is installed, so every
  `await` in the view model resumes on a thread pool thread and the first one to touch a bound
  collection throws. Install a `DispatcherSynchronizationContext` by hand.

The results screenshot is a genuine scan of a small deliberately-flawed demonstration project,
not a mock-up, which is why the dependency findings name real advisory counts: a handful of
hardcoded credentials and injection flaws, plus five pinned packages with published advisories
against those exact versions.

**That project is deliberately not in this repository.** It contains live-shaped credentials, so
committing it would trip GitHub's secret scanning, and VibeCheck would raise the same findings
against its own source. Rebuild it if the screenshot needs retaking; the numbers in the image are
whatever the scan says on the day.

## Conventions worth keeping

- **The palette, the typefaces and the metrics mirror `VibeCheck.App/Themes/Theme.xaml`.** The
  severity ramp especially: those colours carry meaning rather than decoration.
- **Fonts are self-hosted**, not fetched from a font CDN. A site for a tool whose whole claim is
  that nothing leaves your machine should not hand a third party a record of everyone who reads
  about it.
- **Animation is additive.** The reveal styles are scoped to a `js-reveal` class that `site.js`
  adds to `<html>`, so a browser with scripting off gets the whole page rather than an empty
  one. Nothing is hidden until something is present to unhide it.
- **Scroll work is throttled with timers, not `requestAnimationFrame`.** Frame callbacks are
  never delivered to a page that is not being drawn, and an element still waiting to be told to
  appear when somebody finally looks at it is a blank page.
