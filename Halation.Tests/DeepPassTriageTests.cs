using Halation.Core.DeepPass;
using Halation.Core.Model;
using Halation.Core.Recovery;

namespace Halation.Tests;

/// <summary>
/// Which files triage hands to the deep pass.
/// </summary>
/// <remarks>
/// Written after a scan of a World of Warcraft addon, where four of the six files picked were
/// picked for words in their comments, no Lua call counted as taking data in, and the same
/// scan run over the whole repository spent 38 of its 40 files on test specs.
/// </remarks>
public class DeepPassTriageTests
{
    private static RecoveredFile File(string path, string content) => new()
    {
        RelativePath = path,
        Content = content,
        Language = RecoveredFile.LanguageOf(path),
    };

    private static Finding FindingIn(string path) => new()
    {
        RuleId = "VC-TEST-001",
        Title = "test finding",
        Severity = Severity.Medium,
        UserSeverity = Severity.Medium,
        Category = FindingCategory.CodeSafety,
        Description = "x",
        UserDescription = "x",
        FilePath = path,
    };

    private static bool Qualifies(string path, string content) =>
        DeepPassTriage.Triage([File(path, content)], []).Qualified == 1;

    private static List<string> Picked(TriageResult triage) =>
        [.. triage.Selected.Select(s => s.File.RelativePath)];

    // ---- Comments ------------------------------------------------------------

    /// <summary>
    /// A comment that names a call is not the call. The Lua line is the one that picked a file
    /// on the addon; the rest are the same mistake in each comment syntax.
    /// </summary>
    [Theory]
    [InlineData("Settings.cs", "// rounded first, so an unsafe value cannot reach the fetch (below)\nint Round(int x) => x;")]
    [InlineData("Settings.cs", "int x = 1; // HttpClient is configured elsewhere\nint y = 2;")]
    [InlineData("app.js", "/* fetch (url) happens in the worker,\n   which also uses child_process */\nconst a = 1;")]
    [InlineData("tool.py", "# never eval( anything typed in\nx = 1  # nor exec( it\n")]
    [InlineData("Core.lua", "-- multiplication is checked before ceil so an edited setting cannot round an unsafe value.\nlocal x = 1")]
    [InlineData("Core.lua", "--[[ loadstring( is not used here,\nand neither is io.open( ]]\nlocal x = 1")]
    [InlineData("Core.lua", "--[==[ a ]] inside does not end this: unsafe value, loadstring(s) ]==]\nlocal x = 1")]
    [InlineData("schema.sql", "-- read by the SqlCommand in the service\nSELECT 1;")]
    [InlineData("index.html", "<!-- fetch(url) is done by the script -->\n<p>Hello</p>")]
    [InlineData("build.ps1", "<# Starts the app with Process.Start #>\n$x = 1")]
    public void A_call_named_only_in_a_comment_does_not_qualify(string path, string content) =>
        Assert.False(Qualifies(path, content));

    /// <summary>The comment is blanked and the code after it is still read.</summary>
    [Theory]
    [InlineData("Client.cs", "// fetches the catalogue\nvar s = await http.GetStringAsync(u);")]
    [InlineData("client.js", "/* the worker */ const r = await fetch(url);")]
    [InlineData("tool.py", "x = 1  # the next line is the problem\neval(text)")]
    [InlineData("Core.lua", "--[[ decodes an import string ]]\nlocal t = LibDeflate:DecodeForPrint(s)")]
    public void A_call_after_a_comment_still_qualifies(string path, string content) =>
        Assert.True(Qualifies(path, content));

    /// <summary>
    /// A comment marker inside a string is part of the string. A URL is two slashes in
    /// quotation marks, and reading it as a comment would blank every call after it on its
    /// line, which in a minified bundle is every call in the file.
    /// </summary>
    /// <remarks>
    /// Each case would lose its call to a scan that missed one kind of string: a plain one, a
    /// C# verbatim string ending in a backslash, a C# interpolated string with a quoted URL in
    /// its hole, a template literal and one nested in another's hole, a regular expression
    /// holding a quote inside and outside a character class, Lua's quoted and long-bracket
    /// strings, and a Python triple-quoted string holding an escaped triple quote. The hole and
    /// the escaped quote were both found by checking this against real tokenizers on real code.
    /// </remarks>
    [Theory]
    [InlineData("Client.cs", "var u = \"https://x\"; var s = await http.GetStringAsync(u);")]
    [InlineData("Client.cs", "var p = @\"C:\\temp\\\"; var u = \"/*\"; var s = File.ReadAllText(p); var v = \"*/\";")]
    [InlineData("Client.cs", "var u = $\"[{Release(\"v1\", url: \"https://x\")}]\"; var s = await http.GetStringAsync(u);")]
    [InlineData("Client.cs", "var u = $@\"{Get(\"https://x\")}\\\"; var s = await http.GetStringAsync(u);")]
    [InlineData("Client.cs", "var u = $$\"\"\"{{Get(\"https://x\")}}\"\"\"; var s = await http.GetStringAsync(u);")]
    [InlineData("client.js", "const u = \"https://x\"; const r = await fetch(u);")]
    [InlineData("client.js", "const u = `https://${host}/api`; const r = await fetch(u);")]
    [InlineData("client.js", "const u = `${a ? `https://${b}/v1` : \"\"}`; fetch(u);")]
    [InlineData("client.js", "s = s.replace(/\"/g, '&quot;'); const u = \"https://x\"; fetch(u);")]
    [InlineData("client.js", "const re = /[/\"]/; const u = \"https://x\"; fetch(u);")]
    [InlineData("Core.lua", "local s = \"--not a comment\"; local f = loadstring(s)")]
    [InlineData("Core.lua", "local s = [[ -- still a string ]] local f = loadstring(s)")]
    [InlineData("tool.py", "u = \"see # below\"; eval(u)")]
    [InlineData("tool.py", "p = r\"\"\"\\\"\"\" # still the string \"\"\"; eval(p)")]
    public void A_comment_marker_inside_a_string_does_not_hide_the_call_after_it(string path, string content) =>
        Assert.True(Qualifies(path, content));

    /// <summary>The blanked copy keeps every string and every line break, and nothing else of the comments.</summary>
    [Fact]
    public void Blanking_keeps_strings_and_line_breaks()
    {
        var blanked = CommentBlanker.Blank(
            "var u = \"//x\"; // note\r\nvar v = 1; /* a\nb */ var w;", "a.cs");

        Assert.Equal(
            "var u = \"//x\"; " + new string(' ', 7) + "\r\nvar v = 1; " + new string(' ', 4)
            + "\n" + new string(' ', 4) + " var w;",
            blanked);
    }

    /// <summary>
    /// A block comment that never closes is left as it is. Blanking from it to the end of the
    /// file would hide every call after it on the strength of a scan that could not be sure.
    /// </summary>
    [Fact]
    public void An_unclosed_block_comment_is_not_blanked()
    {
        const string code = "const a = 1; /* never closed\nconst r = await fetch(url);";

        Assert.Same(code, CommentBlanker.Blank(code, "client.js"));
        Assert.True(Qualifies("client.js", code));
    }

    // ---- Lua -----------------------------------------------------------------

    /// <summary>
    /// The ways a Lua addon takes data in or runs it: chunks loaded from strings and files,
    /// chat and addon-channel events, an edit box being made or typed into, the standard
    /// library's file and shell calls, and an import string decoded and decompressed. None of
    /// these match the general list, so each is down to the Lua one.
    /// </summary>
    [Theory]
    [InlineData("local f = loadstring(code)")]
    [InlineData("local f = load(code)")]
    [InlineData("dofile(path)")]
    [InlineData("local chunk = loadfile(path)")]
    [InlineData("RunScript(text)")]
    [InlineData("frame:RegisterEvent(\"CHAT_MSG_WHISPER\")")]
    [InlineData("frame:RegisterEvent(\"BN_CHAT_MSG_ADDON\")")]
    [InlineData("C_ChatInfo.SendAddonMessage(prefix, payload, \"GUILD\")")]
    [InlineData("C_ChatInfo.RegisterAddonMessagePrefix(\"MyAddon\")")]
    [InlineData("self:RegisterComm(\"MyAddon\")")]
    [InlineData("local box = CreateFrame(\"EditBox\", nil, parent)")]
    [InlineData("local box = CreateFrame ( 'EditBox' , nil, parent)")]
    [InlineData("box:SetScript(\"OnEnterPressed\", submit)")]
    [InlineData("box:SetScript(\"OnTextChanged\", refresh)")]
    [InlineData("box:SetScript(\"OnEditFocusLost\", save)")]
    [InlineData("local box = CreateFrame(\"Frame\", nil, parent, \"InputBoxTemplate\")")]
    [InlineData("local search = CreateFrame(\"Frame\", nil, parent, \"SearchBoxTemplate\")")]
    [InlineData("local handle = io.open(path, \"r\")")]
    [InlineData("local line = io.read(\"*l\")")]
    [InlineData("for line in io.lines(path) do end")]
    [InlineData("local pipe = io.popen(command)")]
    [InlineData("os.execute(command)")]
    [InlineData("local data = LibDeflate:DecodeForPrint(imported)")]
    [InlineData("local data = LibDeflate:DecodeForWoWAddonChannel(message)")]
    [InlineData("local text = LibDeflate:DecompressDeflate(data)")]
    [InlineData("local text = LibDeflate:DecompressZlib(data)")]
    public void Each_lua_surface_call_qualifies_a_lua_file(string code) =>
        Assert.True(Qualifies("Import.lua", code));

    /// <summary>The Lua list is for Lua. The same words in C# or JavaScript are somebody's own names.</summary>
    [Theory]
    [InlineData("Addon.cs")]
    [InlineData("addon.js")]
    public void Lua_calls_do_not_qualify_a_file_in_another_language(string path) =>
        Assert.False(Qualifies(
            path,
            "var f = loadstring(code); os.execute(cmd); var b = CreateFrame(\"EditBox\"); RegisterEvent(\"CHAT_MSG_ADDON\");"));

    /// <summary>
    /// Reading text is not an edit box. <c>:GetText()</c> reads a label or a button just the same,
    /// and on an addon that sets text all over its interface it picked files with no box in them.
    /// </summary>
    [Fact]
    public void Reading_text_without_an_edit_box_does_not_qualify() =>
        Assert.False(Qualifies(
            "Row.lua",
            "row.hint:SetText(row.hint:GetText() or \"\")\nlocal label = button:GetText()"));

    /// <summary>Lua is case-sensitive, and a method that happens to be called load is not Lua's load.</summary>
    [Fact]
    public void A_method_or_a_capitalised_name_is_not_lua_load() =>
        Assert.False(Qualifies("Settings.lua", "local t = Settings:load(name)\nlocal u = Load(name)"));

    // ---- Test and example files ----------------------------------------------

    /// <summary>A test that makes surface calls is not picked for them; the code it tests is.</summary>
    [Fact]
    public void A_test_file_that_takes_in_outside_data_is_not_picked_for_it()
    {
        var triage = DeepPassTriage.Triage(
            [
                File("src/Client.cs", "var s = await http.GetStringAsync(u);"),
                File("Client.Tests/ClientTests.cs", "var s = await http.GetStringAsync(u);"),
                File("spec/import_spec.lua", "local f = loadstring(code)"),
                File("tests/test_client.py", "eval(text)"),
            ],
            findings: []);

        Assert.Equal(new[] { "src/Client.cs" }, Picked(triage));
        Assert.Equal(3, triage.TestFiles);
    }

    /// <summary>A test calls the code it tests by name, which is all the caller hop looks for.</summary>
    [Fact]
    public void A_test_file_that_calls_a_flagged_file_is_not_picked_as_a_caller()
    {
        var triage = DeepPassTriage.Triage(
            [
                File("src/ShipLockerReader.cs", "static string Normalize(string s) { }"),
                File("src/EdsmSource.cs", "var k = ShipLockerReader.Normalize(name);"),
                File("Reader.Tests/ShipLockerReaderTests.cs", "var k = ShipLockerReader.Normalize(name);"),
            ],
            findings: [FindingIn("src/ShipLockerReader.cs")]);

        Assert.Equal(new[] { "src/ShipLockerReader.cs", "src/EdsmSource.cs" }, Picked(triage));
    }

    /// <summary>
    /// And a flagged test brings in no callers of its own. Shipped code does not import a test,
    /// so a match on its name is a different file with the same one.
    /// </summary>
    [Fact]
    public void A_flagged_test_file_brings_in_no_callers()
    {
        var triage = DeepPassTriage.Triage(
            [
                File("test/helpers.js", "export const make = () => ({});"),
                File("src/app.js", "import { make } from './helpers';"),
            ],
            findings: [FindingIn("test/helpers.js")]);

        Assert.Equal(new[] { "test/helpers.js" }, Picked(triage));
    }

    /// <summary>
    /// A rule match in a test is still worth a look, but only in a slot the shipped code leaves
    /// over: after every file that ships, flagged, caller and surface alike, whatever the counts.
    /// </summary>
    [Fact]
    public void A_flagged_test_file_ranks_after_every_file_that_ships()
    {
        IReadOnlyList<RecoveredFile> files =
        [
            File("spec/import_spec.lua", "local x = 1"),
            File("src/Import.lua", "local y = 2"),
            File("src/Window.lua", "local rows = Import.Read()"),
            File("src/Comms.lua", "C_ChatInfo.SendAddonMessage(prefix, payload, \"GUILD\")"),
        ];

        IReadOnlyList<Finding> findings =
        [
            FindingIn("spec/import_spec.lua"),
            FindingIn("spec/import_spec.lua"),
            FindingIn("spec/import_spec.lua"),
            FindingIn("src/Import.lua"),
        ];

        var triage = DeepPassTriage.Triage(files, findings);

        Assert.Equal(
            new[] { "src/Import.lua", "src/Window.lua", "src/Comms.lua", "spec/import_spec.lua" },
            Picked(triage));
        Assert.Contains("test or example file", triage.Selected[3].Reason, StringComparison.Ordinal);

        // So a ceiling that the shipped code fills leaves the test out.
        Assert.DoesNotContain("spec/import_spec.lua", Picked(DeepPassTriage.Triage(files, findings, maxFiles: 3)));
    }

    // ---- Languages the lists are not written for ------------------------------

    [Fact]
    public void Names_the_languages_outside_the_tests_that_have_no_patterns()
    {
        var triage = DeepPassTriage.Triage(
            [
                File("cmd/main.go", "package main"),
                File("cmd/serve.go", "package main"),
                File("tools/report.py", "x = 1"),
                File("src/App.cs", "int x;"),
                File("ui/app.ts", "let x = 1;"),
                File("Core.lua", "local x = 1"),
                File("schema.sql", "SELECT 1;"),
                File("views/index.ejs", "<p></p>"),
                File("lib/parse_test.rb", "x = 1"),
            ],
            findings: []);

        Assert.Equal(new[] { "Go", "Python" }, triage.LanguagesWithoutPatterns);
    }
}
