# Fonts

These are compiled into `VibeCheck.exe` as resources and addressed from
[`Themes/Theme.xaml`](../Themes/Theme.xaml) by pack URI. Nothing here is installed on the
machine running the application, and nothing here is read from disk at runtime.

They are bundled rather than named because a `FontFamily` that names a face asks whichever
machine it lands on. A machine without Barlow draws Segoe UI instead: the application opens,
works, and looks like a different program, and no screenshot says why. Bundling turns a
question about the reader's machine into a fact about the build.

| File | Family, as WPF sees it | Used for | Licence |
|---|---|---|---|
| `Barlow-Light.ttf` | Barlow (300) | The score, at display size | SIL OFL 1.1 |
| `Barlow-Regular.ttf` | Barlow (400) | Body text, buttons, captions | SIL OFL 1.1 |
| `Barlow-SemiBold.ttf` | Barlow (600) | Card headings, emphasis | SIL OFL 1.1 |
| `Barlow-Bold.ttf` | Barlow (700) | Severity tags | SIL OFL 1.1 |
| `Oxanium-VariableFont_wght.ttf` | Oxanium (300–700) | App name, headings, the score | SIL OFL 1.1 |
| `CascadiaMono.ttf` | Cascadia Mono | Evidence, file paths, hashes | SIL OFL 1.1 |

Oxanium is a variable font and one file covers every weight the interface asks for; WPF reads
its named instances, so `FontWeight="Light"` and `FontWeight="SemiBold"` both resolve to real
instances rather than being synthesised.

**Segoe MDL2 Assets is deliberately absent.** It draws the title bar glyphs, it ships with
Windows 10 and 11, and it is not ours to redistribute.

## Where they came from

- **Barlow**, Jeremy Tribby: <https://github.com/jpt/barlow>
- **Oxanium**, Severin Meyer: <https://github.com/sevmeyer/oxanium>
- **Cascadia Mono**, Microsoft: <https://github.com/microsoft/cascadia-code>

All three are licensed under the SIL Open Font License 1.1, which permits bundling a font
inside an application provided the licence travels with it. `OFL-Barlow.txt`,
`OFL-Oxanium.txt` and `OFL-Cascadia.txt` beside this file are those licences, verbatim from
each project, and they are compiled into the executable alongside the fonts.

None of the files here are modified, which matters for Cascadia: its licence carries the
Reserved Font Name clause, so a modified copy could not keep the name.
