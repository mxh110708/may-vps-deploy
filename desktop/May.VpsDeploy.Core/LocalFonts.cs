using System.Buffers.Binary;
using System.Text;
using System.Text.RegularExpressions;

namespace May.VpsDeploy.Core;

public sealed record LocalFont(string Id, string Family, string DisplayName, string FilePath);

// Storage and OpenType metadata remain portable; each frontend owns rendering.
public sealed class LocalFonts(AppPaths paths)
{
    public const int MaximumBytes = 64 * 1024 * 1024;
    private static readonly Regex FileName = new(@"^[a-f0-9]{64}\.(ttf|otf)$", RegexOptions.CultureInvariant);
    public LocalFont Import(string source)
    {
        var extension = Path.GetExtension(source).ToLowerInvariant();
        if (extension is not (".ttf" or ".otf")) throw new OperationException("请选择 TTF 或 OTF 字体文件。");
        var bytes = Read(source); var metadata = Names(bytes); var name = ArchiveStore.Digest(bytes) + extension;
        var target = paths.Resolve("private/fonts/" + name);
        if (File.Exists(target))
        {
            if (ArchiveStore.Digest(Read(target)) != ArchiveStore.Digest(bytes)) throw new OperationException("已导入的字体发生变化，请先核对本地文件。");
        }
        else ArchiveStore.AtomicWrite(target, bytes);
        return new("Custom:" + name, metadata.Family, metadata.DisplayName, target);
    }
    public LocalFont Resolve(string id)
    {
        var name = id.StartsWith("Custom:", StringComparison.Ordinal) ? id[7..] : "";
        if (!FileName.IsMatch(name)) throw new OperationException("字体选择无效。");
        var target = paths.Resolve("private/fonts/" + name); var bytes = Read(target);
        if (!name.StartsWith(ArchiveStore.Digest(bytes), StringComparison.Ordinal)) throw new OperationException("已导入的字体发生变化，请重新导入原文件。");
        var metadata = Names(bytes); return new(id, metadata.Family, metadata.DisplayName, target);
    }
    public IEnumerable<LocalFont> List()
    {
        var directory = paths.Resolve("private/fonts");
        if (!Directory.Exists(directory)) yield break;
        SafePath.CheckTree(directory);
        foreach (var file in Directory.EnumerateFiles(directory).OrderBy(Path.GetFileName, StringComparer.Ordinal))
        {
            if (!FileName.IsMatch(Path.GetFileName(file))) continue;
            LocalFont? font = null;
            try { font = Resolve("Custom:" + Path.GetFileName(file)); } catch (OperationException) { }
            if (font != null) yield return font;
        }
    }
    public static byte[] Read(string file)
    {
        try
        {
            SafePath.CheckLinks(file);
            using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (stream.Length is < 12 or > MaximumBytes) throw new OperationException("字体文件无效或超过 64 MiB。");
            var bytes = new byte[(int)stream.Length]; stream.ReadExactly(bytes); return bytes;
        }
        catch (IOException) { throw new OperationException("字体文件无法读取，请重新选择或导入。"); }
        catch (UnauthorizedAccessException) { throw new OperationException("字体文件无法读取，请重新选择或导入。"); }
    }
    public static string Family(byte[] data) => Names(data).Family;
    private static (string Family, string DisplayName) Names(byte[] data)
    {
        static OperationException Invalid() => new("字体内容无效；请选择完整的 TTF 或 OTF 文件。");
        if (data.Length is < 12 or > MaximumBytes) throw Invalid();
        ushort U16(int offset) => BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(offset, 2));
        uint U32(int offset) => BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(offset, 4));
        if (U32(0) is not (0x00010000 or 0x4F54544F)) throw Invalid();
        var count = U16(4); if (count is 0 or > 128 || 12 + count * 16 > data.Length) throw Invalid();
        var tables = new Dictionary<string, (int Offset, int Length)>();
        for (var i = 0; i < count; i++)
        {
            var entry = 12 + i * 16; var tag = Encoding.ASCII.GetString(data, entry, 4); var offset = U32(entry + 8); var length = U32(entry + 12);
            if (offset < 12 + count * 16 || (long)offset + length > data.Length || !tables.TryAdd(tag, ((int)offset, (int)length))) throw Invalid();
        }
        if (new[] { "cmap", "head", "hhea", "hmtx", "maxp", "name" }.Any(t => !tables.ContainsKey(t))) throw Invalid();
        if (tables["cmap"].Length < 4 || tables["head"].Length < 54 || tables["hhea"].Length < 36 || tables["hmtx"].Length < 4 || tables["maxp"].Length < 6) throw Invalid();
        if (U32(0) == 0x00010000 ? !tables.ContainsKey("glyf") : !tables.ContainsKey("CFF ") && !tables.ContainsKey("CFF2")) throw Invalid();
        var table = tables["name"]; if (table.Length < 6) throw Invalid();
        var names = U16(table.Offset + 2); var storage = U16(table.Offset + 4);
        if (names is 0 or > 1024 || 6 + names * 12 > table.Length || storage < 6 + names * 12 || storage > table.Length) throw Invalid();
        var candidates = new List<(string Name, int Rank, int Kind)>();
        for (var i = 0; i < names; i++)
        {
            var entry = table.Offset + 6 + i * 12; var platform = U16(entry); var encoding = U16(entry + 2); var language = U16(entry + 4); var kind = U16(entry + 6); var length = U16(entry + 8); var offset = U16(entry + 10);
            if ((long)storage + offset + length > table.Length) throw Invalid();
            if (kind is not (1 or 4 or 16) || length is 0 or > 512) continue;
            if (platform != 0 && !(platform == 3 && encoding is 1 or 10)) continue;
            if (length % 2 != 0) throw Invalid();
            var name = Encoding.BigEndianUnicode.GetString(data, table.Offset + storage + offset, length).Trim();
            if (name.Length == 0 || name.Any(c => char.IsControl(c) || c is '#' or ',' or '/' or '\\' or '?' or '\uFFFD')) continue;
            candidates.Add((name, (kind == 16 ? 100 : 0) + (language == 0x409 ? 20 : language == 0x804 ? 10 : 0) + (platform == 3 ? 2 : 1), kind));
        }
        var family = candidates.Where(c => c.Kind != 4).OrderByDescending(c => c.Rank).Select(c => c.Name).FirstOrDefault() ?? throw Invalid();
        var fullName = candidates.Where(c => c.Kind == 4).OrderByDescending(c => c.Rank).Select(c => c.Name).FirstOrDefault();
        return (family, fullName ?? family);
    }
}
