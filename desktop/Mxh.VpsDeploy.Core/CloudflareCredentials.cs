using System.Text.RegularExpressions;

namespace Mxh.VpsDeploy.Core;

public static class CloudflareCredentials
{
    public static string ReadToken(string file)
    {
        SafePath.CheckLinks(file);
        if (new FileInfo(file).Length > 8192) throw Invalid();
        return ParseToken(File.ReadAllText(file));
    }

    public static string ParseToken(string content)
    {
        if (content.Length > 8192) throw Invalid();
        var lines = content.TrimStart('\uFEFF').Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.Trim()).Where(line => line.Length > 0 && !line.StartsWith('#') && !line.StartsWith(';')).ToArray();
        if (lines.Length != 1) throw Invalid();
        var token = lines[0];
        var separator = token.IndexOf('=');
        if (separator >= 0)
        {
            if (token[..separator].Trim() != "dns_cloudflare_api_token") throw Invalid();
            token = token[(separator + 1)..].Trim();
            if (token.Length >= 2 && token[0] is '\'' or '"' && token[^1] == token[0]) token = token[1..^1];
        }
        if (!Regex.IsMatch(token, @"\A[A-Za-z0-9_-]{1,256}\z")) throw Invalid();
        return token;
    }

    private static OperationException Invalid() => new("证书 Token 文件需要一行非空 Token，或唯一的 dns_cloudflare_api_token = Token；不能包含其他凭据或重复项。", code: "InvalidCloudflareTokenFile");
}
