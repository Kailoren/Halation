using System.Xml;

namespace VibeCheck.Core.Theming;

/// <summary>
/// Decides whether a loose theme file is safe to hand to a XAML parser.
/// </summary>
/// <remarks>
/// <para>
/// XAML is not a data format. It names types and the parser constructs them, and a few of the
/// types reachable from the WPF namespace do more than describe a colour: the documented gadget
/// is <c>ObjectDataProvider</c>, which exists to call a method and will happily call one on
/// <c>Process</c>. A theme file was therefore an executable wearing a stylesheet's clothes, and
/// the application that reads it is the one whose entire purpose is talking people out of
/// running software they were handed by a stranger.
/// </para>
/// <para>
/// The threat here is social rather than local. Anyone who can already write to
/// <c>%LOCALAPPDATA%</c> can run code without going near a theme; what this closes is
/// "download this nice theme and drop it in your VibeCheck folder", where the reader believes
/// they are copying colours and is copying a program. That is the case worth defending, and it
/// is the case an allowlist actually covers.
/// </para>
/// <para>
/// So this is an allowlist, not a blocklist. Everything is refused unless it is one of the
/// element names, namespaces and markup extensions a theme genuinely needs, which means a type
/// added to WPF next year is refused by default rather than becoming a hole nobody noticed. The
/// list was taken from the vocabulary the two shipped themes actually use and then widened by
/// hand to the rest of the drawing and animation surface, so it is generous about brushes,
/// shapes, transforms and easing, and silent about everything that touches a file, a socket or
/// a method call.
/// </para>
/// <para>
/// It lives in Core rather than beside <c>ThemeLoader</c> in the WPF project for one reason:
/// the test project targets plain net10.0 and cannot reference a WPF assembly. Security code
/// that cannot be tested is not security code. Nothing in here touches WPF.
/// </para>
/// <para>
/// Worth being straight about the limits. This narrows a theme to a drawing vocabulary; it is
/// not a proof that the vocabulary is inert, and the only airtight answer is to not parse
/// untrusted XAML at all. It is enough to make installing a theme mean what a reader thinks it
/// means, which is what was broken.
/// </para>
/// </remarks>
public static class ThemeGuard
{
    /// <summary>Namespaces a theme may declare. Anything else cannot be named at all.</summary>
    /// <remarks>
    /// This is the load-bearing one. <c>clr-namespace:</c> is how arbitrary types are imported,
    /// so refusing every namespace but these three means an attacker cannot reach
    /// <c>System.Diagnostics</c> however they spell the prefix. Prefixes are resolved to their
    /// URI before checking, so renaming <c>x</c> to something else buys nothing.
    /// </remarks>
    private static readonly HashSet<string> Namespaces = new(StringComparer.Ordinal)
    {
        "http://schemas.microsoft.com/winfx/2006/xaml/presentation",
        "http://schemas.microsoft.com/winfx/2006/xaml",
        "clr-namespace:System;assembly=System.Runtime",
    };

    private const string Presentation = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
    private const string Xaml = "http://schemas.microsoft.com/winfx/2006/xaml";
    private const string System = "clr-namespace:System;assembly=System.Runtime";

    /// <summary>Types a theme may construct, by local name.</summary>
    private static readonly HashSet<string> Elements = new(StringComparer.Ordinal)
    {
        // Resources and styling.
        "ResourceDictionary", "Style", "Setter", "ControlTemplate", "DataTemplate",
        "ItemsPanelTemplate", "Trigger", "DataTrigger", "MultiTrigger", "MultiDataTrigger",
        "Condition", "EventTrigger", "BeginStoryboard", "StopStoryboard", "PauseStoryboard",
        "ResumeStoryboard",

        // Layout and the elements a template is built from.
        "Grid", "StackPanel", "DockPanel", "Canvas", "WrapPanel", "UniformGrid", "Border",
        "Viewbox", "Decorator", "ContentControl", "ContentPresenter", "ItemsPresenter",
        "RowDefinition", "ColumnDefinition", "TextBlock", "Run", "Separator",

        // Controls that appear inside the templates a theme replaces.
        "Button", "RepeatButton", "ToggleButton", "Thumb", "Track", "ScrollBar", "ProgressBar",

        // Shapes.
        "Rectangle", "Ellipse", "Line", "Path", "Polygon", "Polyline",

        // Brushes. No ImageBrush and no VisualBrush: the first takes a URI, which is a file read
        // or a network request depending on how it is spelled, and this application has an
        // isolate mode that promises neither happens.
        "SolidColorBrush", "LinearGradientBrush", "RadialGradientBrush", "DrawingBrush",
        "GradientStop", "GradientStopCollection", "Pen",

        // Drawings and geometry.
        "DrawingGroup", "GeometryDrawing", "GeometryGroup", "CombinedGeometry", "StreamGeometry",
        "RectangleGeometry", "EllipseGeometry", "LineGeometry", "PathGeometry", "PathFigure",
        "PathFigureCollection", "LineSegment", "PolyLineSegment", "BezierSegment",
        "PolyBezierSegment", "QuadraticBezierSegment", "ArcSegment",

        // Effects. No ShaderEffect: it loads a compiled shader from a URI.
        "DropShadowEffect", "BlurEffect",

        // Transforms.
        "TranslateTransform", "ScaleTransform", "RotateTransform", "SkewTransform",
        "MatrixTransform", "TransformGroup",

        // Animation.
        "Storyboard", "DoubleAnimation", "ColorAnimation", "PointAnimation", "ThicknessAnimation",
        "DoubleAnimationUsingKeyFrames", "ColorAnimationUsingKeyFrames", "KeySpline",
        "LinearDoubleKeyFrame", "DiscreteDoubleKeyFrame", "EasingDoubleKeyFrame",
        "SplineDoubleKeyFrame", "LinearColorKeyFrame", "DiscreteColorKeyFrame",
        "EasingColorKeyFrame", "BackEase", "BounceEase", "CircleEase", "CubicEase", "ElasticEase",
        "ExponentialEase", "PowerEase", "QuadraticEase", "QuarticEase", "QuinticEase", "SineEase",

        // Values.
        "Color", "FontFamily", "Thickness", "CornerRadius", "Duration", "Point", "Size", "Rect",
        "GridLength", "KeyTime", "Binding", "RelativeSource",
    };

    /// <summary>Types from the x namespace a theme may construct.</summary>
    /// <remarks>
    /// <c>Static</c> is absent on purpose. It reads an arbitrary static member, and a property
    /// getter is a method call however innocent it looks in markup.
    /// </remarks>
    private static readonly HashSet<string> XamlElements = new(StringComparer.Ordinal)
    {
        "Null", "Type",
    };

    /// <summary>Types from the System namespace a theme may construct.</summary>
    /// <remarks>
    /// Named individually rather than trusting the namespace. <c>System</c> in System.Runtime
    /// holds a great deal more than the primitives a theme wants, and a bare allow on the
    /// namespace would be an allow on all of it.
    /// </remarks>
    private static readonly HashSet<string> SystemElements = new(StringComparer.Ordinal)
    {
        "Double", "Int32", "String", "Boolean", "TimeSpan",
    };

    /// <summary>Markup extensions a theme may use, keyed by resolved namespace.</summary>
    private static readonly HashSet<string> PresentationExtensions = new(StringComparer.Ordinal)
    {
        "Binding", "StaticResource", "DynamicResource", "TemplateBinding", "RelativeSource",
    };

    private static readonly HashSet<string> XamlExtensions = new(StringComparer.Ordinal)
    {
        "Null", "Type",
    };

    /// <summary>
    /// Property names a theme may never set, whether as an attribute or a property element.
    /// </summary>
    /// <remarks>
    /// <c>Source</c> is the important one and it is easy to miss, because it is not a gadget.
    /// <c>&lt;ResourceDictionary Source="http://..."/&gt;</c> inside MergedDictionaries makes the
    /// parser fetch and parse a second document, which this validator never sees. Every check
    /// above it would be doing real work on a file that was not the one being loaded.
    /// </remarks>
    private static readonly HashSet<string> BlockedProperties = new(StringComparer.Ordinal)
    {
        "Source", "UriSource", "StreamSource", "PixelShader", "ShaderEffect",
    };

    /// <summary>
    /// Directives that construct or extend types rather than describing them.
    /// </summary>
    private static readonly HashSet<string> BlockedDirectives = new(StringComparer.Ordinal)
    {
        "FactoryMethod", "Arguments", "Class", "ClassModifier", "Subclass", "Code", "TypeArguments",
    };

    /// <summary>A theme deeper than this is not a theme.</summary>
    private const int MaxDepth = 64;

    /// <summary>
    /// Returns null when the document may be parsed, or a sentence naming the first thing wrong
    /// with it. The sentence is shown to whoever installed the theme, so it names the offending
    /// element rather than describing the rule it broke.
    /// </summary>
    public static string? Check(Stream xaml)
    {
        ArgumentNullException.ThrowIfNull(xaml);

        var settings = new XmlReaderSettings
        {
            // A theme has no legitimate use for a doctype, and entity expansion is a denial of
            // service before it is anything else.
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersFromEntities = 0,
            IgnoreComments = true,
            IgnoreWhitespace = true,
            IgnoreProcessingInstructions = true,
            CloseInput = false,
        };

        try
        {
            using var reader = XmlReader.Create(xaml, settings);

            while (reader.Read())
            {
                if (reader.NodeType != XmlNodeType.Element)
                {
                    continue;
                }

                if (reader.Depth > MaxDepth)
                {
                    return $"The theme nests elements more than {MaxDepth} deep and was ignored.";
                }

                if (CheckElement(reader) is { } elementProblem)
                {
                    return elementProblem;
                }

                if (CheckAttributes(reader) is { } attributeProblem)
                {
                    return attributeProblem;
                }
            }
        }
        catch (XmlException ex)
        {
            return $"The theme is not well-formed XML and was ignored.\n\n{ex.Message}";
        }

        return null;
    }

    private static string? CheckElement(XmlReader reader)
    {
        if (!Namespaces.Contains(reader.NamespaceURI))
        {
            return Unknown("namespace", reader.NamespaceURI);
        }

        var name = reader.LocalName;

        // A dotted element is property syntax: <Border.Effect>, <Track.Thumb>. The type before
        // the dot has to be allowed and the property after it must not be blocked, because
        // <ResourceDictionary.Source> reaches the same place the attribute does.
        var dot = name.LastIndexOf('.');

        if (dot > 0)
        {
            var property = name[(dot + 1)..];

            if (BlockedProperties.Contains(property))
            {
                return Blocked(name);
            }

            name = name[..dot];
        }

        var allowed = reader.NamespaceURI switch
        {
            Presentation => Elements.Contains(name),
            Xaml => XamlElements.Contains(name),
            System => SystemElements.Contains(name),
            _ => false,
        };

        return allowed ? null : Unknown("element", reader.LocalName);
    }

    private static string? CheckAttributes(XmlReader reader)
    {
        if (!reader.HasAttributes)
        {
            return null;
        }

        try
        {
            while (reader.MoveToNextAttribute())
            {
                // A namespace declaration is the one attribute whose value decides what the rest
                // of the document is allowed to name, so it is checked as a value not a name.
                if (reader.Prefix == "xmlns" || reader.Name == "xmlns")
                {
                    if (!Namespaces.Contains(reader.Value))
                    {
                        return Unknown("namespace", reader.Value);
                    }

                    continue;
                }

                if (reader.NamespaceURI == Xaml && BlockedDirectives.Contains(reader.LocalName))
                {
                    return Blocked("x:" + reader.LocalName);
                }

                var name = reader.LocalName;
                var dot = name.LastIndexOf('.');
                var property = dot > 0 ? name[(dot + 1)..] : name;

                if (BlockedProperties.Contains(property))
                {
                    return Blocked(reader.Name);
                }

                if (CheckValue(reader, reader.Value) is { } problem)
                {
                    return problem;
                }
            }
        }
        finally
        {
            reader.MoveToElement();
        }

        return null;
    }

    /// <summary>
    /// Walks an attribute value for markup extensions and checks each one.
    /// </summary>
    /// <remarks>
    /// Every brace is inspected rather than only a leading one, because extensions nest:
    /// <c>{Binding Foo, Converter={StaticResource Bar}}</c> has to be caught at both. Prefixes
    /// are resolved through the reader so that an extension cannot be smuggled in under a
    /// renamed prefix.
    /// </remarks>
    private static string? CheckValue(XmlReader reader, string value)
    {
        for (var i = value.IndexOf('{'); i >= 0; i = value.IndexOf('{', i + 1))
        {
            var start = i + 1;

            while (start < value.Length && char.IsWhiteSpace(value[start]))
            {
                start++;
            }

            // "{}" is XAML's escape for a value that merely begins with a brace, and an empty
            // pair names nothing.
            if (start >= value.Length || value[start] == '}')
            {
                continue;
            }

            var end = start;

            while (end < value.Length
                   && (char.IsLetterOrDigit(value[end]) || value[end] is '_' or '.' or ':'))
            {
                end++;
            }

            var token = value[start..end];

            if (token.Length == 0)
            {
                return Unknown("markup extension", value[i..Math.Min(i + 24, value.Length)]);
            }

            var colon = token.IndexOf(':');
            var prefix = colon > 0 ? token[..colon] : string.Empty;
            var local = colon > 0 ? token[(colon + 1)..] : token;

            // A markup extension may be written with or without its suffix.
            if (local.EndsWith("Extension", StringComparison.Ordinal))
            {
                local = local[..^"Extension".Length];
            }

            var ns = prefix.Length == 0
                ? reader.LookupNamespace(string.Empty) ?? Presentation
                : reader.LookupNamespace(prefix);

            var allowed = ns switch
            {
                Presentation => PresentationExtensions.Contains(local),
                Xaml => XamlExtensions.Contains(local),
                _ => false,
            };

            if (!allowed)
            {
                return Unknown("markup extension", token);
            }
        }

        return null;
    }

    private static string Unknown(string kind, string name) =>
        $"The theme uses a disallowed {kind}, and was ignored.\n\n"
        + $"Found: {name}\n\n"
        + "A theme may only use the colours, shapes, templates and animations listed in "
        + "THEME.md. Anything outside that is refused whether or not it is harmful, because a "
        + "theme file is not supposed to be able to do anything except describe an appearance.";

    private static string Blocked(string name) =>
        $"The theme sets {name}, which themes are not allowed to set, and was ignored.\n\n"
        + "That property can make the application read a file or fetch a document, which is "
        + "outside what describing an appearance requires.";
}
