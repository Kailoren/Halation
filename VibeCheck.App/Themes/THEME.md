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

> **Install themes you trust.** A theme is XAML, and XAML is not a data format: it constructs
> whatever objects it names, and there are well-known constructions that start processes. Write
> your own or read one before you install it, and treat a theme downloaded from a stranger the
> way you would treat any other executable from a stranger, which is the thing this application
> exists to talk you out of.

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
| `AccentWash` | `#1F4C8DFF` | A surface being pointed at or dragged onto, laid **over** whatever it highlights |
| `CloseHover` | `#C42B1C` | Close button hover fill |
| `OnDanger` | `#FFFFFF` | Text on `CloseHover` |

`AccentWash` is translucent on purpose. It is drawn over the surface it highlights rather than
replacing that surface's colour, so one key covers every such surface whatever colour each one
happens to be, and all of them are the same colour as each other by construction rather than
because somebody copied a hex value into two templates and kept them in step by hand.

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

Two panels belong to a severity rather than merely being coloured by one:

| Key | Default | What it fills |
|---|---|---|
| `CriticalFill` | `#2A1618` | The do-not-install banner |
| `MediumFill` | `#2A2418` | The note marking a finding as inferred by the deep pass |

Opaque in the default theme, unlike `AccentWash`: these are the surface rather than a tint laid
over one, and both values were chosen against the default background. A theme is free to make
them translucent, and `Cyberpunk2077.xaml` does, holding them to the same opacity as its panels
so its animated backdrop reads through them.

These reach further than the severity bar. A finding row is outlined in its own severity too,
through the same converter and the same brush, so the outline can never disagree with the label
it surrounds. Changing one of these colours changes how loud a whole screen of findings is, not
just how a twelve pixel tag looks.

There is one margin here worth understanding before spending it. Colour is not the only carrier
of severity: every finding row prints the word beside the bar, and the score band prints its
label beside the number. So a theme that puts two neighbouring severities in the same family is
degrading a redundant signal rather than removing the only one.

`Cyberpunk2077.xaml` does exactly that, and says so where it happens. Its `High` is red rather
than the conventional orange, because orange sat too close to the yellow that theme is built on
and stopped reading as a warning. `Critical` and `High` are then separated by hue alone, the
first carrying a blue cast and the second not. On a near-black background there is no third
option, since darkening one far enough to also separate it by lightness drops it below the
contrast a ten pixel label needs.

That is a defensible trade while the words are on screen. It stops being one the moment they are
not, so if the severity label is ever dropped from a finding row, every ramp has to be revisited
in the same change.

## Typography

| Key | Default | Notes |
|---|---|---|
| `UiFont` | `Segoe UI` | Body text, buttons, captions |
| `DisplayFont` | `Segoe UI` | The app name, card headings, the big screen titles, and the score. Separate from `UiFont` because display faces are usually wide and unreadable at paragraph size |
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

## Motion

| Key | Default | Notes |
|---|---|---|
| `SwiftDuration` | `0:0:0.13` | Hover and press, the states that should feel immediate |
| `CalmDuration` | `0:0:0.30` | Release, which is allowed to linger |

These reach the templates in `Theme.xaml` through `StaticResource`, not `DynamicResource`, and
that is deliberate. Animations are `Freezable`s rather than framework elements, so they have no
element tree for a `DynamicResource` to walk and it silently resolves to nothing. The practical
consequence is the same as `BasedOn` further down: **overriding these two keys alone does not
change the built-in templates.** A theme that wants different timing overrides the template as
well, which is where motion belongs anyway.

### Writing motion that works

Animate `Opacity` and `RenderTransform`, and nothing else.

Those are plain dependency properties on framework elements. They compose, they never invalidate
layout, and they cannot hit the wall that catches everyone the first time:

```
Cannot animate '...' on an immutable object instance.
```

That error means you tried to animate a brush or an effect directly, and WPF had frozen it.
The way round it is not to unfreeze anything, it is to stop animating the decoration and start
animating a *layer* that carries it. Every hover in this application is a second element sitting
exactly on the first with its opacity taken from 0 to 1. That is why `Btn` and `DropZone` each
have an otherwise pointless-looking extra `Border` in their templates.

Two more traps worth knowing:

- **`x:Shared="False"` does not work in a loose theme.** It is only honoured in compiled XAML
  and throws when `XamlReader` meets it. Declare per-instance objects inside a template instead,
  where each templated control gets its own copy for free.
- **A forever-repeating storyboard and a trigger storyboard must not share a target element.**
  Whichever started last owns the property and the other stops working with no error. Give them
  separate layers.

## Decoration slots

Empty in the default theme. Each is a template the windows already mount and the default theme
declines to fill, so a theme can add whole visual layers without a change to any window. All of
them are mounted with `IsHitTestVisible="False"`, so nothing a theme draws can swallow a click
or block a drop however large it is.

| Key | Where it sits |
|---|---|
| `WindowBackdrop` | Behind the entire interface, above the window background. Gradients, grain, scanlines |
| `WindowOverlay` | In front of the entire interface. Vignettes and glass. Keep it faint; the findings are underneath |
| `CardChrome` | Inside every card, between its border and its content. Corner cuts and ticks |

Each is a `ControlTemplate` with `TargetType="ContentControl"`:

```xml
<ControlTemplate x:Key="WindowOverlay" TargetType="ContentControl">
    <Rectangle Fill="#22000000"/>
</ControlTemplate>
```

## Effects

| Key | Applied to |
|---|---|
| `CardGlow` | The card's border element |
| `ButtonGlow` | The button's hover layer |
| `DropZoneGlow` | The drop zone's drag layer |

All three are `x:Null` by default and expect a `DropShadowEffect` with `ShadowDepth="0"`, which
is the only way WPF draws light rather than shade:

```xml
<DropShadowEffect x:Key="CardGlow" Color="#F9F002" ShadowDepth="0" BlurRadius="18" Opacity="0.45"/>
```

They attach to border elements and never to whole controls, and the templates are built to keep
that possible: each border is an empty **sibling** of the content rather than its parent. An
`Effect` rasterises the subtree it is set on, so a glow set on a card would push every paragraph
inside it through the same intermediate surface and cost the text its subpixel antialiasing. Set
one on something with words in it and you will see the text soften.

## Styles

Restyling rather than recolouring means overriding these whole. Copy the one you want from
`Theme.xaml` and change it; a `Style` cannot be partially overridden.

| Key | Applies to |
|---|---|
| *(implicit)* `TextBlock` | Default text colour for every `TextBlock` |
| `Heading` | Card headings |
| `Caption` | Small muted explanatory text |
| `Card` | The panels. A templated `ContentControl`, not a `Border` |
| `DropZone` | The drop target, including its drag state |
| `Btn` | Ordinary buttons |
| `ChoiceBtn` | The two audience choices, which are buttons the size of paragraphs |
| `CaptionBtn` | Minimise and maximise |
| `CloseBtn` | Close, inherits `CaptionBtn` |
| *(implicit)* `ScrollBar` | Every scroll bar in every window |
| `ScrollThumb` | The draggable part, used by the above |
| `ScrollPage` | The click-to-page halves of the track, used by the above |

The scroll bar is templated in full for the same reason the audience choices are: WPF's stock
one takes its colours from the framework's own theme dictionary, so no palette here could reach
it and a native light grey bar sat down the side of a dark window. It is implicit, so it applies
everywhere without being asked for, and it names no colours of its own beyond `Muted` and
`Accent` at graded opacities. A theme that never mentions scroll bars still gets one that
matches it.

> **Every clickable control needs a style here, including the ones that look fine without one.**
> The audience choices had none for a while, so they fell through to WPF's stock `Button`
> template and lit up in the Aero2 mouse-over blue. That blue lives in the framework's own theme
> dictionary, which made it the single colour in the application that no theme could reach and no
> palette could account for. An unstyled control is a hole in the theme, not a neutral default.

`Card` and `DropZone` are `ContentControl`s so that a theme can own their shape and not merely
their colour. A `Border` has exactly one child and no template, so the only thing a style could
ever say about one was what colour it was.

## A worked example

`Cyberpunk2077.xaml` beside this file is a complete theme built from
[gwannon/Cyberpunk-2077-theme-css](https://github.com/gwannon/Cyberpunk-2077-theme-css). It is
worth reading as a model of the two things a theme has to get right: it says where it departed
from its source and why, and it leaves `Unknown` alone.

It is also the worked example for everything above. It fills all three decoration slots, sets
all three glows, replaces the `Card`, `Btn` and `DropZone` templates outright, and animates a
backdrop, and none of it required a change to a window.

Its card is worth reading for one technique in particular. **To make a shape that resizes
without distorting, put the part that must not scale in a fixed-size `Grid` cell.** A notched
corner has no good alternative: painting the corner out with a background-coloured triangle
leaves a flat patch wherever the backdrop is textured, and stretching one notched `Path` to fill
the card turns the notch into a long shallow diagonal on a wide card. A two by two grid with an
18 pixel top row and an 18 pixel right column holds the cut at exactly 18 by 18 at every size,
and the fills and hairlines around it all stop at shared grid lines so they meet exactly.

Fonts named in a `FontFamily` fall back left to right, so listing faces that are not installed
is safe and is how that theme picks up Oxanium or Michroma if they are present and Bahnschrift
if they are not.

## Nothing visual is left in a window

Every colour, radius, font and metric the two windows draw now comes from a key in here. That is
checkable rather than aspirational, and worth rechecking after any markup change:

```
rg 'CornerRadius="[0-9]|(Background|BorderBrush|Foreground|Fill)="#' *.xaml
```

The only survivors should be the `CornerRadius="0"` on each window's `WindowChrome`, which is
native window geometry rather than appearance and has no business being themed.

## What a theme cannot change

Layout, wording, and which findings appear. Those are decided before anything is drawn, and
the report's honesty guarantees do not depend on the theme. The one place appearance carries a
guarantee is the `Unknown` band above.
