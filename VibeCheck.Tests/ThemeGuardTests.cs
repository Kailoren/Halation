using System.Text;

using VibeCheck.Core.Theming;

namespace VibeCheck.Tests;

/// <summary>
/// A theme file is XAML, XAML constructs the types it names, and some of those types call
/// methods. These are the cases that decide whether installing a theme means what the person
/// installing it thinks it means.
/// </summary>
public class ThemeGuardTests
{
    private const string Open =
        """
        <ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                            xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
        """;

    private static string? Check(string xaml) =>
        ThemeGuard.Check(new MemoryStream(Encoding.UTF8.GetBytes(xaml)));

    // ---- What a theme is allowed to be ----------------------------------------

    /// <summary>
    /// The two themes that ship. If this fails the allowlist is too tight and the product is
    /// broken, which is the failure nothing else in the build would catch: the default theme is
    /// compiled into the assembly and never goes through the guard, so only the loose copy
    /// would break, and only on the machine that installed it.
    /// </summary>
    [Theory]
    [InlineData("Theme.xaml")]
    [InlineData("Cyberpunk2077.xaml")]
    public void ShippedThemes_AreAccepted(string file)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Themes", file);

        Assert.True(File.Exists(path), $"{path} was not copied to the test output.");

        using var stream = File.OpenRead(path);
        Assert.Null(ThemeGuard.Check(stream));
    }

    [Fact]
    public void PlainOverride_IsAccepted() =>
        Assert.Null(Check(
            $"""
             {Open}
                 <SolidColorBrush x:Key="Bg" Color="#0B0E14"/>
                 <FontFamily x:Key="UiFont">Segoe UI</FontFamily>
             </ResourceDictionary>
             """));

    /// <summary>
    /// Templates, triggers and animation are the whole point of the theming system, so the
    /// guard has to let a theme restyle a control rather than only recolour one.
    /// </summary>
    [Fact]
    public void TemplateWithAnimation_IsAccepted() =>
        Assert.Null(Check(
            $"""
             {Open}
                 <Style x:Key="Btn" TargetType="Button">
                     <Setter Property="Template">
                         <Setter.Value>
                             <ControlTemplate TargetType="Button">
                                 <Grid>
                                     <Border x:Name="Hot" Opacity="0">
                                         <Border.Effect>
                                             <DropShadowEffect Color="#F9F002" BlurRadius="12"/>
                                         </Border.Effect>
                                     </Border>
                                     <ContentPresenter/>
                                 </Grid>
                                 <ControlTemplate.Triggers>
                                     <Trigger Property="IsMouseOver" Value="True">
                                         <Trigger.EnterActions>
                                             <BeginStoryboard>
                                                 <Storyboard>
                                                     <DoubleAnimation Storyboard.TargetName="Hot"
                                                                      Storyboard.TargetProperty="Opacity"
                                                                      To="1" Duration="0:0:0.1"/>
                                                 </Storyboard>
                                             </BeginStoryboard>
                                         </Trigger.EnterActions>
                                     </Trigger>
                                 </ControlTemplate.Triggers>
                             </ControlTemplate>
                         </Setter.Value>
                     </Setter>
                 </Style>
             </ResourceDictionary>
             """));

    [Fact]
    public void NestedMarkupExtensions_AreAccepted() =>
        Assert.Null(Check(
            $$"""
              {{Open}}
                  <Style x:Key="S" TargetType="Border">
                      <Setter Property="Background" Value="{DynamicResource Panel}"/>
                      <Style.Triggers>
                          <DataTrigger Binding="{Binding IsDragging}" Value="True">
                              <Setter Property="BorderBrush" Value="{DynamicResource Accent}"/>
                          </DataTrigger>
                      </Style.Triggers>
                  </Style>
              </ResourceDictionary>
              """));

    // ---- Code execution -------------------------------------------------------

    /// <summary>
    /// The documented gadget. ObjectDataProvider exists to call a method, and it lives in the
    /// same namespace as every brush a theme legitimately needs, so no namespace rule catches
    /// it and it has to be absent from the element allowlist.
    /// </summary>
    [Fact]
    public void ObjectDataProvider_IsRefused() =>
        Assert.NotNull(Check(
            $$"""
              {{Open}}
                  <ObjectDataProvider x:Key="Bg" MethodName="Start" ObjectType="{x:Type Process}"/>
              </ResourceDictionary>
              """));

    /// <summary>
    /// clr-namespace is how any type in any assembly is imported, so refusing every namespace
    /// but the three a theme needs is what stops the whole class rather than one gadget.
    /// </summary>
    [Fact]
    public void ForeignClrNamespace_IsRefused() =>
        Assert.NotNull(Check(
            """
            <ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                                xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
                                xmlns:d="clr-namespace:System.Diagnostics;assembly=System.Diagnostics.Process">
                <d:Process x:Key="Bg"/>
            </ResourceDictionary>
            """));

    /// <summary>
    /// Prefixes are arbitrary labels, so the guard resolves them to their namespace before
    /// deciding anything. Calling the xaml namespace something other than x must not help.
    /// </summary>
    [Fact]
    public void RenamedPrefix_DoesNotHelp() =>
        Assert.NotNull(Check(
            """
            <ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                                xmlns:q="http://schemas.microsoft.com/winfx/2006/xaml">
                <SolidColorBrush q:Key="Bg" Color="{q:Static SystemColors.WindowColor}"/>
            </ResourceDictionary>
            """));

    /// <summary>x:Static reads a static member, and a property getter is a method call.</summary>
    [Fact]
    public void StaticExtension_IsRefused() =>
        Assert.NotNull(Check(
            $$"""
              {{Open}}
                  <SolidColorBrush x:Key="Bg" Color="{x:Static SystemColors.WindowColor}"/>
              </ResourceDictionary>
              """));

    /// <summary>
    /// An extension buried in the arguments of a permitted one is still an extension, so every
    /// brace in a value is inspected rather than only a leading one.
    /// </summary>
    /// <remarks>
    /// Written out rather than interpolated: the value ends in two closing braces, which no
    /// amount of raw-string escaping makes pleasant to read next to an interpolation.
    /// </remarks>
    [Fact]
    public void StaticExtension_NestedInsideBinding_IsRefused() =>
        Assert.NotNull(Check(
            """
            <ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                                xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
                <Style x:Key="S" TargetType="Border">
                    <Setter Property="Background"
                            Value="{Binding Path=Foo, Source={x:Static SystemColors.WindowColor}}"/>
                </Style>
            </ResourceDictionary>
            """));

    [Fact]
    public void FactoryMethod_IsRefused() =>
        Assert.NotNull(Check(
            $"""
             {Open}
                 <SolidColorBrush x:Key="Bg" x:FactoryMethod="Parse"/>
             </ResourceDictionary>
             """));

    // ---- Reaching outside the file --------------------------------------------

    /// <summary>
    /// The quiet one. A merged dictionary with a Source makes the parser fetch and parse a
    /// second document that this guard never sees, which would turn every other check in it
    /// into theatre.
    /// </summary>
    [Fact]
    public void MergedDictionaryWithSource_IsRefused() =>
        Assert.NotNull(Check(
            $"""
             {Open}
                 <ResourceDictionary.MergedDictionaries>
                     <ResourceDictionary Source="http://example.invalid/theme.xaml"/>
                 </ResourceDictionary.MergedDictionaries>
             </ResourceDictionary>
             """));

    /// <summary>The same reach, written as a property element instead of an attribute.</summary>
    [Fact]
    public void SourceAsPropertyElement_IsRefused() =>
        Assert.NotNull(Check(
            $"""
             {Open}
                 <ResourceDictionary.Source>http://example.invalid/theme.xaml</ResourceDictionary.Source>
             </ResourceDictionary>
             """));

    /// <summary>An ImageBrush takes a URI, which is a file read or a network request.</summary>
    [Fact]
    public void ImageBrush_IsRefused() =>
        Assert.NotNull(Check(
            $"""
             {Open}
                 <ImageBrush x:Key="Bg" ImageSource="\\attacker\share\probe.png"/>
             </ResourceDictionary>
             """));

    // ---- Malformed input ------------------------------------------------------

    [Fact]
    public void Doctype_IsRefused() =>
        Assert.NotNull(Check(
            """
            <!DOCTYPE root [<!ENTITY a "aaaaaaaaaa">]>
            <ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"/>
            """));

    [Fact]
    public void NotWellFormed_IsRefusedRatherThanThrown() =>
        Assert.NotNull(Check($"{Open}<SolidColorBrush"));

    /// <summary>
    /// The message is shown to whoever installed the theme, so it has to name what was found
    /// rather than only saying no.
    /// </summary>
    [Fact]
    public void Refusal_NamesTheOffendingConstruct()
    {
        var problem = Check(
            $"""
             {Open}
                 <ObjectDataProvider x:Key="Bg" MethodName="Start"/>
             </ResourceDictionary>
             """);

        Assert.NotNull(problem);
        Assert.Contains("ObjectDataProvider", problem, StringComparison.Ordinal);
    }
}
