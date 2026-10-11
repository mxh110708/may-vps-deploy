using Mxh.VpsDeploy.Core;

internal sealed partial class BoundaryTests
{
    private void CloudflareCredentialExperience(Fixture fixture)
    {
        var value = "synthetic_token-for-test";
        foreach (var text in new[] { value, "\uFEFF" + value + "\r\n", "dns_cloudflare_api_token = " + value,
            "# private DNS credentials\n; comment\ndns_cloudflare_api_token = '" + value + "'\n" })
            Check(CloudflareCredentials.ParseToken(text) == value, "valid raw or INI DNS Token refused");
        foreach (var text in new[] { "", "# no value", "dns_cloudflare_api_token =", value + "\nother-token",
            "dns_cloudflare_api_token = " + value + "\ndns_cloudflare_api_token = " + value,
            "dns_cloudflare_api_key = " + value, "[default]\ndns_cloudflare_api_token = " + value,
            "dns_cloudflare_api_token = \"" + value, "dns_cloudflare_api_token = " + value + " # extra",
            "dns_cloudflare_api_token = placeholder with spaces", new string('x', 8193) })
            Refuses(() => CloudflareCredentials.ParseToken(text), "invalid or ambiguous credentials accepted");
        var file = fixture.Paths.Resolve("private/cloudflare-test.ini");
        File.WriteAllText(file, "dns_cloudflare_api_token = " + value);
        Check(CloudflareCredentials.ReadToken(file) == value, "INI file not loaded");
        File.WriteAllText(file, new string('x', 8193));
        Refuses(() => CloudflareCredentials.ReadToken(file), "oversized token file accepted");
    }
}
