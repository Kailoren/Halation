# Halation theming

Every colour, font and metric the interface uses is a named key in
[`Theme.xaml`](Theme.xaml). Nothing visual is hardcoded in a window: if a value cannot be
changed from the theme, that is a bug in the theme rather than a preference of the window.

## The theme is compiled in

`Theme.xaml` is built into `Halation.exe`, along with every typeface it names. There is no
theme file beside the executable and no override read from disk, which is deliberate: what a
reader sees has to be what was built and tested, and a security tool whose interface can be
rearranged by a file in the user's profile is a security tool whose screenshots prove nothing.

**Changing the look means editing this file and rebuilding.** Every key below is read from here
and nowhere else.

An earlier version merged a loose theme file from the user's profile over this one, which
brought a validator with it: XAML is not a data format, it names types and the parser builds
them, and `ObjectDataProvider` exists to call a method. That whole surface, the loader, the
allowlist and the risk, went when the override did.

Keys are still referred to with `DynamicResource` rather than `StaticResource` throughout, which
now buys something narrower but still real: a style defined earlier in the file can name a brush
defined later, and editing one value changes everything built from it without hunting for
declaration order. `BasedOn` remains the exception and must stay `StaticResource`, because WPF
resolves style inheritance at load and throws on a dynamic reference.

## Fonts are bundled, not requested

Barlow, Oxanium and Cascadia Mono are compiled into the executable as resources and addressed by
pack URI. A `FontFamily` that merely names a face asks whichever machine it lands on, and a
machine without Barlow silently draws Segoe UI: the application opens, works, and looks like a
different program, with nothing in a screenshot to say why.

Two traps, both of which cost time here and are worth knowing before editing a font key:

- **Use the absolute pack URI**, `pack://application:,,,/Halation;component/Fonts/#Family`.
  A relative `./Fonts/#Family` resolves against the folder holding this dictionary, which is
  `Themes/`, so it finds nothing. A font URI that resolves to nothing does not throw. It falls
  back, and on a developer machine with the font installed the fallback is the correct font, so
  it looks perfect right up until somebody else runs it.
- **The name after the hash is the family's internal name**, not the file name, and the assembly
  is `Halation` rather than `Halation.App`.

`Fonts/README.md` lists each file, what it is used for, and its licence. `IconFont` is the one
exception: Segoe MDL2 Assets ships with Windows and is not ours to redistribute.

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

Translucent in the shipped theme, unlike most fills: they are held to the same opacity as its
panels so the animated backdrop reads through them. A theme is free to make them opaque instead,
which is the right call on a static background where a tint has nothing to tint.

These reach further than the severity bar. A finding row is outlined in its own severity too,
through the same converter and the same brush, so the outline can never disagree with the label
it surrounds. Changing one of these colours changes how loud a whole screen of findings is, not
just how a twelve pixel tag looks.

There is one margin here worth understanding before spending it. Colour is not the only carrier
of severity: every finding row prints the word beside the bar, and the score band prints its
label beside the number. So a theme that puts two neighbouring severities in the same family is
degrading a redundant signal rather than removing the only one.

The shipped theme does exactly that, and says so where it happens. Its `High` is red rather
than the conventional orange, because orange sat too close to the yellow the theme is built on
and stopped reading as a warning. `Critical` and `High` are then separated by hue alone, the
first carrying a blue cast and the second not. On a near-black background there is no third
option, since darkening one far enough to also separate it by lightness drops it below the
contrast a ten pixel label needs.

That is a defensible trade while the words are on screen. It stops being one the moment they are
not, so if the severity label is ever dropped from a finding row, every ramp has to be revisited
in the same change.

## Typography

| Key | Face | Notes |
|---|---|---|
| `UiFont` | Barlow, bundled | Body text, buttons, captions. Real Light, SemiBold and Bold faces, so none of those weights is synthesised |
| `DisplayFont` | Oxanium, bundled | The app name, card headings, the big screen titles, and the score. Separate from `UiFont` because display faces are usually wide and unreadable at paragraph size |
| `MonoFont` | Cascadia Mono, bundled | Evidence snippets, file paths, hashes |
| `IconFont` | Segoe MDL2 Assets, from Windows | Title bar glyphs. The one face not bundled, and not ours to redistribute. Changing this means changing the glyph codes in the window markup too |
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

### Looping animations

Start a looping animation from a `DataTrigger`, never from a `Loaded` `EventTrigger`, and give
the same trigger the `StopStoryboard`:

```xml
<DataTrigger Binding="{Binding IsMinimised}" Value="False">
    <DataTrigger.EnterActions>
        <BeginStoryboard x:Name="Sweeping">…</BeginStoryboard>
    </DataTrigger.EnterActions>
    <DataTrigger.ExitActions>
        <StopStoryboard BeginStoryboardName="Sweeping"/>
    </DataTrigger.ExitActions>
</DataTrigger>
```

That shape avoids three separate problems at once.

A `Loaded` `EventTrigger` in `ControlTemplate.Triggers` **does not work**, and fails in two
different ways depending on how the template was applied. Where the template is a local value it
silently never fires and the animation sits at its starting value forever. Where the template
came from a `Style` setter it throws on the first render, not at parse time, with
`'Pulse' name cannot be found in the name scope of ControlTemplate`. Neither failure is visible
in a screenshot, and the silent one survived a round of checking here because something else on
screen was moving and made consecutive frames differ.

`PauseStoryboard` and `ResumeStoryboard` need their `BeginStoryboard`'s name in the same trigger
collection. The collection that *does* work for `Loaded` is the root element's own `Triggers`,
and that one accepts nothing but `EventTrigger`s, so a pause can never sit beside the thing it
would pause. Starting from a `DataTrigger` puts the start and the stop in one place.

Anything that loops forever should also stop when nothing can see it, and carry
`Timeline.DesiredFrameRate` so it is cheap while it runs. A nine second drift gains nothing from
sixty frames a second; `20` looks identical and asks for a third of the work. `IsMinimised` is
published on the view model for exactly this, alongside `IsDragging`.

**Verify motion by reading the animated value, not by comparing screenshots.** A wash at six
percent alpha barely moves a pixel, so a frame diff measures whatever else happens to be moving.

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
| `SectionHeader` | The heading of a results section, and the arrow that folds it away |
| *(implicit)* `ScrollBar` | Every scroll bar in every window |
| `ScrollThumb` | The draggable part, used by the above |
| `ScrollPage` | The click-to-page halves of the track, used by the above |
| *(implicit)* `PasswordBox` | The API key field, including its focus ring |
| *(implicit)* `TextBox` | The endpoint and model fields, same field as above but read back |
| *(implicit)* `CheckBox` | The box, the tick, and the states of both |
| *(implicit)* `RadioButton` | The deep pass source choices. A round mark, otherwise the check box |

The input styles are templated in full for the reason that kept recurring while this file was being
written: **WPF's stock control templates take their colours from the framework's own theme
dictionary, which no palette here can reach.** The Aero2 mouse-over blue on a button, the light
grey scroll bar down the side of a dark window, the blue focus ring on a password box and the
white box of a check box were all the same defect, found four separate times, each time by
noticing something on screen that no key in this file could explain.

That is the tell worth remembering. If a control looks wrong and nothing in the palette accounts
for it, the control has no style here and is falling through to the framework. The fix is always
a template, and the templates above name no colours of their own beyond the palette keys, so a
theme that never mentions any of these still gets versions that match it.

> **Every clickable control needs a style here, including the ones that look fine without one.**
> The audience choices had none for a while, so they fell through to WPF's stock `Button`
> template and lit up in the Aero2 mouse-over blue. That blue lives in the framework's own theme
> dictionary, which made it the single colour in the application that no theme could reach and no
> palette could account for. An unstyled control is a hole in the theme, not a neutral default.

`Card` and `DropZone` are `ContentControl`s so that a theme can own their shape and not merely
their colour. A `Border` has exactly one child and no template, so the only thing a style could
ever say about one was what colour it was.

### `SectionHeader`

A `ToggleButton`, because a fold is a two-state control and WPF already gives one of those a
focus rectangle, a space bar and a name a screen reader can say. Each section on the results
screen has one, and the content below it is bound to `IsChecked`.

Three things it has to keep doing:

- **The heading is `Content` and the count is `Tag`, and both are read as text.** The template
  puts them in `TextBlock`s rather than a `ContentPresenter`, which is what lets the heading
  carry the `Heading` style, and means both must be strings.
- **Keep the count visible.** It is there so a section that is folded away still says how much
  it is holding. A closed "What could not be checked" with no count beside it looks exactly like
  a scan that had nothing it could not check, and that is the one thing this report may never
  look like.
- **Point the arrow at the content.** Down while the section is open, a quarter turn away when
  it is closed. The default draws it as a `Path` named `Arrow` and animates
  `RenderTransform.Angle` between `0` and `-90`, so restyling it is drawing a shape rather than
  hunting for a code point in whatever font `IconFont` names.

## The shipped theme as a worked example

`Theme.xaml` beside this file is worth reading as a model of the two things a theme has to get
right: it says why each colour is the colour it is, and it leaves `Unknown` alone.

It is also the worked example for everything above. It fills all three decoration slots, sets
all three glows, templates `Card`, `Btn` and `DropZone` outright, and animates a backdrop, and
none of it required a change to a window.

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
