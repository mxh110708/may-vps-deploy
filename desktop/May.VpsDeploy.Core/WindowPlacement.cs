using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public readonly record struct WindowBounds(int X, int Y, int Width, int Height);
public sealed record SavedWindowPlacement(string Display, WindowBounds Bounds, WindowBounds WorkArea, double Scale);

public static class WindowPlacement
{
    public const int DefaultWidth = 1280;
    public const int DefaultHeight = 850;

    public static WindowBounds Resolve(WindowBounds workArea, double scale, SavedWindowPlacement? saved = null)
    {
        if (!Valid(workArea) || !ValidScale(scale)) throw new ArgumentException("Invalid display work area or scale.");
        var margin = Math.Min((int)Math.Round(16 * scale), Math.Min(workArea.Width, workArea.Height) / 4);
        var availableWidth = workArea.Width - margin * 2;
        var availableHeight = workArea.Height - margin * 2;
        if (saved == null || !Valid(saved.Bounds) || !Valid(saved.WorkArea) || !ValidScale(saved.Scale))
        {
            var width = Math.Min((int)Math.Round(DefaultWidth * scale), availableWidth);
            var height = Math.Min((int)Math.Round(DefaultHeight * scale), availableHeight);
            return new(workArea.X + (workArea.Width - width) / 2, workArea.Y + (workArea.Height - height) / 2, width, height);
        }
        var factor = scale / saved.Scale;
        var restoredWidth = Math.Clamp((int)Math.Round(saved.Bounds.Width * factor), 1, availableWidth);
        var restoredHeight = Math.Clamp((int)Math.Round(saved.Bounds.Height * factor), 1, availableHeight);
        var x = workArea.X + (int)Math.Round((saved.Bounds.X - saved.WorkArea.X) * factor);
        var y = workArea.Y + (int)Math.Round((saved.Bounds.Y - saved.WorkArea.Y) * factor);
        // Position and size stay inside the current work area, including negative monitor origins.
        return new(Math.Clamp(x, workArea.X, workArea.X + workArea.Width - restoredWidth),
            Math.Clamp(y, workArea.Y, workArea.Y + workArea.Height - restoredHeight), restoredWidth, restoredHeight);
    }

    public static SavedWindowPlacement? Read(JsonNode? value)
    {
        if (value is not JsonObject item || !Integer(item["Version"], out var version) || version != 1 ||
            item["Display"] is not JsonValue display || !display.TryGetValue<string>(out var name) || string.IsNullOrWhiteSpace(name) || name.Length > 128 ||
            !Rectangle(item["Bounds"], out var bounds) || !Rectangle(item["WorkArea"], out var workArea) ||
            item["Scale"] is not JsonValue scale || !scale.TryGetValue<double>(out var factor) || !ValidScale(factor)) return null;
        return new(name, bounds, workArea, factor);
    }

    public static JsonObject Write(SavedWindowPlacement saved) => new()
    {
        ["Version"] = 1, ["Display"] = saved.Display, ["Bounds"] = Json(saved.Bounds),
        ["WorkArea"] = Json(saved.WorkArea), ["Scale"] = saved.Scale
    };
    public static JsonObject Json(WindowBounds bounds) => new() { ["X"] = bounds.X, ["Y"] = bounds.Y, ["Width"] = bounds.Width, ["Height"] = bounds.Height };
    private static bool Integer(JsonNode? item, out int value) { value = 0; return item is JsonValue number && number.TryGetValue<int>(out value); }
    private static bool Rectangle(JsonNode? item, out WindowBounds result)
    {
        result = default;
        if (item is not JsonObject rectangle || !Integer(rectangle["X"], out var x) || !Integer(rectangle["Y"], out var y) ||
            !Integer(rectangle["Width"], out var width) || !Integer(rectangle["Height"], out var height)) return false;
        result = new(x, y, width, height); return Valid(result);
    }
    private static bool Valid(WindowBounds bounds) => Math.Abs((long)bounds.X) <= 1000000 && Math.Abs((long)bounds.Y) <= 1000000 && bounds.Width is > 0 and <= 100000 && bounds.Height is > 0 and <= 100000;
    private static bool ValidScale(double scale) => double.IsFinite(scale) && scale is >= 0.5 and <= 8;
}
