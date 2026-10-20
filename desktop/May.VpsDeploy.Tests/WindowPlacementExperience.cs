using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

internal sealed partial class BoundaryTests
{
    private void WindowPlacementExperience()
    {
        var work = new WindowBounds(0, 0, 1920, 1080);
        Check(WindowPlacement.Resolve(work, 1) == new WindowBounds(320, 115, 1280, 850), "default window not centered at standard size");
        var negative = new WindowBounds(-1920, -640, 1920, 1080);
        Check(WindowPlacement.Resolve(negative, 1) == new WindowBounds(-1600, -525, 1280, 850), "negative display origin lost");
        var scaled = WindowPlacement.Resolve(new(0, 48, 2560, 1392), 1.5);
        Check(scaled == new WindowBounds(320, 106, 1920, 1275), "default size ignored current display DPI or taskbar");
        var small = WindowPlacement.Resolve(new(0, 0, 1366, 728), 1.5);
        Check(small == new WindowBounds(24, 24, 1318, 680), "default window escaped small work area");
        var saved = new SavedWindowPlacement("Example display", new(80, 90, 1000, 700), work, 1);
        Check(WindowPlacement.Resolve(work, 1, saved) == saved.Bounds, "valid saved placement changed");
        var narrow = saved with { Bounds = new(20, 30, 250, 180) };
        Check(WindowPlacement.Resolve(work, 1, narrow) == narrow.Bounds, "remembered dimensions gained an unsolicited minimum size");
        Check(WindowPlacement.Read(JsonNode.Parse(WindowPlacement.Write(saved).ToJsonString())) == saved, "saved placement did not survive disk JSON");
        var shifted = WindowPlacement.Resolve(new(-2560, -1440, 2560, 1440), 1.5, saved);
        Check(shifted == new WindowBounds(-2440, -1305, 1500, 1050), "monitor movement or scaling did not preserve relative placement");
        var offscreen = saved with { Bounds = new(-32000, -32000, 4000, 3000) };
        var clamped = WindowPlacement.Resolve(work, 1, offscreen);
        Check(clamped == new WindowBounds(0, 0, 1888, 1048), "oversized or offscreen remembered window remained inaccessible");
        var bottomRight = saved with { Bounds = new(5000, 4000, 1000, 700) };
        Check(WindowPlacement.Resolve(work, 1, bottomRight) == new WindowBounds(920, 380, 1000, 700), "saved window bottom or right escaped work area");
        for (var i = 0; i < 5; i++)
        {
            var bounds = WindowPlacement.Resolve(work, 1, saved);
            saved = saved with { Bounds = bounds };
            Check(bounds == new WindowBounds(80, 90, 1000, 700), "repeated reopen drifted window position");
        }
        foreach (var item in new JsonNode?[] { null, JsonValue.Create("invalid"), new JsonObject(), new JsonObject { ["Version"] = 9 } })
            Check(WindowPlacement.Read(item) == null, "unknown remembered layout was accepted");
        foreach (var mutation in new Action<JsonObject>[] {
            item => item["Scale"] = "invalid", item => item["Scale"] = 0, item => item["Scale"] = 9,
            item => item["Bounds"]!["Width"] = -1, item => item["Bounds"]!["Height"] = 0,
            item => item["Bounds"]!["X"] = int.MinValue, item => item["WorkArea"]!["Y"] = "invalid",
            item => item["Display"] = false })
        {
            var item = WindowPlacement.Write(saved); mutation(item);
            Check(WindowPlacement.Read(item) == null, "invalid stored placement prevented safe fallback");
        }
        Check(WindowPlacement.Resolve(work, 1, saved with { Scale = double.NaN }) == WindowPlacement.Resolve(work, 1), "invalid old DPI did not fall back to centered default");
    }
}
