# VibeCheck theming

Every colour, font and metric the interface uses is a named key in
[`Theme.xaml`](Theme.xaml). Nothing visual is hardcoded in a window: if a value cannot be
changed from the theme, that is a bug in the theme rather than a preference of the window.

## Trying a different look

1. Copy `Theme.xaml` to `%LOCALAPPDATA%\VibeCheck\theme.xaml`.
2. Edit it. Keep only the keys you are changing; everything you leave out falls back to the
   built-in default.
3. Restart VibeCheck.

**To revert, delete `%LOCALAPPDATA%\VibeCheck\theme.xaml`.** The default is compiled into the
executable, so it cannot be lost, and there is nothing to reinstall.

A theme that fails to parse is reported in a message box once and then ignored, so a bad edit
gives you the application back with an explanation rather than a window that will not open.

A minimal override is legitimate and is the recommended shape:

```xml
<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
    <SolidColorBrush x:Key="Bg"     Color="#0B0E14"/>
    <SolidColorBrush x:Key="Accent" Color="#C77DFF"/>
</ResourceDictionary>
```

Every key below can be overridden this way, including the ones the built-in styles use
internally. That works because the default theme refers to its own keys with
`DynamicResource` rather than `StaticResource`: a `StaticResource` is resolved once when the
default loads, so a later override would silently fail to reach anything already built from
it. If you add keys of your own and want them overridable in turn, refer to them the same way.

## Palette

| Key | Default | What it controls |
|---|---|---|
| `Bg` | `#16181D` | Window background behind everything |
| `Panel` | `#1E2128` | Card and title bar fill |
| `PanelRaised` | `#252932` | Button fill, input fill |
| `Edge` | `#2E323B` | All one-pixel borders and dividers |
| `Text` | `#E4E7EC` | Default text |
| `Muted` | `#8B93A1` | Captions, explanatory text, title bar glyphs |
| `Accent` | `#4C8DFF` | Links, focus and hover borders, progress bar |
| `Hover` | `#2F3540` | Button and title bar button hover fill |
| `CloseHover` | `#C42B1C` | Close button hover fill |
| `OnDanger` | `#FFFFFF` | Text on `CloseHover` |

## Severity ramp

Read left to right as worsening. These are the only saturated colours in the application, so
they carry meaning by contrast rather than by decoration. Keep them distinguishable by
lightness as well as hue, or a colour-blind reader loses the ordering.

| Key | Default | Meaning |
|---|---|---|
| `Critical` | `#FF4D4F` | Critical findings, and the do-not-install banner |
| `High` | `#FF8A3D` | High findings |
| `Medium` | `#FFC53D` | Medium findings |
| `Low` | `#58B2FF` | Low findings |
| `Good` | `#52C41A` | The "no known issues found" band |
| `Unknown` | `#6B7280` | The "could not analyse" band |

> **`Unknown` must not be green.** An artifact that could not be read must not look like one
> that passed. Keeping those two visually distinct is the entire reason the band exists, and a
> theme that blurs them makes the tool dishonest on the tool's behalf.

## Typography

| Key | Default | Notes |
|---|---|---|
| `UiFont` | `Segoe UI` | Everything except code and glyphs |
| `MonoFont` | `Consolas` | Evidence snippets, file paths, hashes |
| `IconFont` | `Segoe MDL2 Assets` | Title bar glyphs. Changing this means changing the glyph codes in the window markup too |
| `BodySize` | `13` | |
| `CaptionSize` | `12` | Captions and explanatory text |
| `HeadingSize` | `15` | Card headings |
| `ScoreSize` | `42` | The headline number |

## Metrics

| Key | Default | Notes |
|---|---|---|
| `CardRadius` | `6` | Card corners |
| `ButtonRadius` | `4` | Button corners |
| `CardPadding` | `16` | Inside cards |
| `ButtonPadding` | `14,7` | Inside buttons |
| `CaptionHeight` | `36` | Title bar height. Must match the `CaptionHeight` on each window's `WindowChrome`, or the drag region and the visible bar disagree |

## Styles

Restyling rather than recolouring means overriding these whole. Copy the one you want from
`Theme.xaml` and change it; a `Style` cannot be partially overridden.

| Key | Applies to |
|---|---|
| *(implicit)* `TextBlock` | Default text colour for every `TextBlock` |
| `Heading` | Card headings |
| `Caption` | Small muted explanatory text |
| `Card` | The bordered panels |
| `Btn` | Ordinary buttons |
| `CaptionBtn` | Minimise and maximise |
| `CloseBtn` | Close, inherits `CaptionBtn` |

## What a theme cannot change

Layout, wording, and which findings appear. Those are decided before anything is drawn, and
the report's honesty guarantees do not depend on the theme. The one place appearance carries a
guarantee is the `Unknown` band above.
