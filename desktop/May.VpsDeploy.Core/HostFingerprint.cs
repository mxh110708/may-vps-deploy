using System.Text.RegularExpressions;

namespace May.VpsDeploy.Core;

public enum FingerprintComparison { Empty, Invalid, Match, Mismatch }

public static class HostFingerprint
{
    public static FingerprintComparison Compare(string reference, string observed)
    {
        if (string.IsNullOrWhiteSpace(reference)) return FingerprintComparison.Empty;
        var matches = Regex.Matches(reference, @"SHA256:[A-Za-z0-9+/]{43}(?![A-Za-z0-9+/=])");
        if (matches.Count != 1) return FingerprintComparison.Invalid;
        return string.Equals(matches[0].Value, observed, StringComparison.Ordinal) ? FingerprintComparison.Match : FingerprintComparison.Mismatch;
    }
}
