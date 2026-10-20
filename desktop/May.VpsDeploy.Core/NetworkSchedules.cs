using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

// One-off application-owned jobs. No service, OS scheduler, or unattended credential prompts.
public static class NetworkSchedules
{
    public static DateTimeOffset NextPeak(DateTimeOffset now, JsonObject options)
    {
        NetworkTuning.ValidateMeasurement(options); var zone = NetworkTuning.Zone(options.Text("TimeZoneId"));
        var local = TimeZoneInfo.ConvertTime(now, zone); var next = DateTime.SpecifyKind(local.Date.AddHours(options.Number("PeakStartHour")), DateTimeKind.Unspecified);
        if (next <= local.DateTime) next = next.AddDays(1);
        while (zone.IsInvalidTime(next)) next = next.AddMinutes(30);
        return new DateTimeOffset(next, zone.GetUtcOffset(next)).ToUniversalTime();
    }
    public static JsonObject Create(string instance, JsonObject options, string sourceFingerprint, DateTimeOffset now)
    {
        var request = new OperationRequest(OperationKind.MeasureNetwork, instance, options); OperationPolicy.Validate(request);
        return new JsonObject { ["Id"] = Guid.NewGuid().ToString("N"), ["Instance"] = instance, ["Options"] = options.DeepClone(),
            ["SourceFingerprint"] = sourceFingerprint, ["CreatedAt"] = now.ToString("O"), ["DueAt"] = NextPeak(now, options).ToString("O"), ["Status"] = "Waiting" };
    }
    public static string StatusAt(JsonObject job, DateTimeOffset now, bool fromStartup = false)
    {
        var status = job.Text("Status");
        if (status == "Running") return fromStartup ? "Interrupted" : status;
        if (status != "Waiting") return status;
        if (!DateTimeOffset.TryParse(job.Text("DueAt"), out var due)) return "Invalid";
        if (fromStartup && now >= due) return "Missed";
        if (now > due.AddMinutes(30)) return "Missed";
        return now >= due ? "Due" : "Waiting";
    }
}
