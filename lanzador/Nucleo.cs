// Réplica exacta de afdg-publicacion/afdg_crypto.py (open_unit). Mantener ambos sincronizados.
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC.Rfc8032;

namespace AulasFuturas;

public sealed class LaunchError(string code, string detalle = "") : Exception($"[{code}] {Mensajes[code]}")
{
    public static readonly Dictionary<string, string> Mensajes = new()
    {
        ["L01"] = "Esta licencia no corresponde a esta memoria USB.",
        ["L02"] = "La licencia está dañada o fue modificada.",
        ["L03"] = "Esta unidad fue reemplazada o dada de baja.",
        ["P01"] = "Un paquete de contenido está dañado. Use la copia de respaldo o contacte soporte.",
        ["P02"] = "Versión de contenido no autorizada para esta unidad o lanzador.",
        ["W01"] = "Falta Microsoft Edge WebView2 en esta computadora.",
    };
    public string Code { get; } = code;
    public string Detalle { get; } = detalle;
}

public sealed record Sello(string Perfil, Dictionary<string, byte[]> Lic, Dictionary<string, byte[]> Man,
                           byte[] Pepper, HashSet<string> Revocadas, int MinSeq);

public sealed record Paquete(string Id, string Titulo, string Icono, int? Grado, string Ver);

public sealed class Unidad
{
    public required string Id { get; init; }
    public required string Cliente { get; init; }
    public required List<Paquete> Paquetes { get; init; }
    public required Func<string, byte[]> Leer { get; init; }

    /// <summary>Descifra un paquete y devuelve sus archivos en memoria.</summary>
    public Dictionary<string, byte[]> Archivos(string pkg)
    {
        var zip = Leer(pkg);
        var d = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        try
        {
            using var za = new ZipArchive(new MemoryStream(zip), ZipArchiveMode.Read);
            foreach (var e in za.Entries)
            {
                if (e.FullName.EndsWith('/')) continue;
                using var s = e.Open();
                using var m = new MemoryStream();
                s.CopyTo(m);
                d[e.FullName] = m.ToArray();
            }
        }
        catch (InvalidDataException) { throw new LaunchError("P01", pkg); }
        return d;
    }
}

public static class Nucleo
{
    static readonly byte[] LicCtx = Encoding.ASCII.GetBytes("AFDG-LIC-v1\0");
    static readonly byte[] ManCtx = Encoding.ASCII.GetBytes("AFDG-MAN-v1\0");
    static readonly byte[] Magic = Encoding.ASCII.GetBytes("AFPK1");
    static readonly byte[] SealMagic = Encoding.ASCII.GetBytes("AFDGSEAL");
    static readonly byte[] SealObf = Encoding.ASCII.GetBytes("AFDG-SEAL-OBF-v1");
    const int Chunk = 64 * 1024;
    static readonly Regex Nombre = new("^[a-z0-9-]{1,48}$", RegexOptions.CultureInvariant);

    public static byte[] B64(string s)
    {
        s = s.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(s + new string('=', (4 - s.Length % 4) % 4));
    }

    static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    // ---------- Sello del lanzador ----------
    static byte[] Keystream(int n)
    {
        var out_ = new byte[n];
        var buf = new byte[SealObf.Length + 4];
        SealObf.CopyTo(buf, 0);
        for (int i = 0, pos = 0; pos < n; i++)
        {
            BitConverter.TryWriteBytes(buf.AsSpan(SealObf.Length), (uint)i); // little-endian en x64
            var h = SHA256.HashData(buf);
            var k = Math.Min(32, n - pos);
            h.AsSpan(0, k).CopyTo(out_.AsSpan(pos));
            pos += k;
        }
        return out_;
    }

    /// <summary>Busca el sello en el final del ejecutable (antes de la firma Authenticode).</summary>
    public static Sello? LeerSello(byte[] cola)
    {
        int pos = cola.AsSpan().LastIndexOf(SealMagic);
        if (pos < 4) return null;
        int n = BitConverter.ToInt32(cola, pos - 4);
        if (n <= 0 || n > pos - 4) return null;
        var obf = cola.AsSpan(pos - 4 - n, n).ToArray();
        var ks = Keystream(n);
        for (int i = 0; i < n; i++) obf[i] ^= ks[i];
        try
        {
            var r = JsonDocument.Parse(obf).RootElement;
            Dictionary<string, byte[]> Claves(JsonElement e) =>
                e.EnumerateObject().ToDictionary(p => p.Name, p => B64(p.Value.GetString()!));
            return new Sello(r.GetProperty("perfil").GetString()!,
                Claves(r.GetProperty("pub").GetProperty("lic")), Claves(r.GetProperty("pub").GetProperty("man")),
                B64(r.GetProperty("pepper").GetString()!),
                r.GetProperty("revocadas").EnumerateArray().Select(x => x.GetString()!).ToHashSet(),
                r.TryGetProperty("min_seq", out var ms) ? ms.GetInt32() : 1);
        }
        catch (Exception e) when (e is JsonException or KeyNotFoundException or FormatException or InvalidOperationException)
        {
            return null;
        }
    }

    // ---------- Tokens firmados ----------
    public static JsonElement VerificarToken(Dictionary<string, byte[]> pubs, byte[] ctx, string token, bool prod)
    {
        try
        {
            var partes = token.Trim().Split('.');
            if (partes.Length != 3) throw new LaunchError("L02");
            var kid = partes[0];
            if (prod && kid.StartsWith("test-", StringComparison.Ordinal)) throw new LaunchError("L02", "clave de prueba");
            if (!pubs.TryGetValue(kid, out var pk) || pk.Length != 32) throw new LaunchError("L02");
            var payload = B64(partes[1]);
            var sig = B64(partes[2]);
            if (sig.Length != 64) throw new LaunchError("L02");
            var msg = ctx.Concat(Encoding.ASCII.GetBytes(kid + ".")).Concat(payload).ToArray();
            if (!Ed25519.Verify(sig, 0, pk, 0, msg, 0, msg.Length)) throw new LaunchError("L02");
            var root = JsonDocument.Parse(payload).RootElement.Clone();
            if (root.ValueKind != JsonValueKind.Object) throw new LaunchError("L02");
            return root;
        }
        catch (Exception e) when (e is FormatException or JsonException or ArgumentException)
        {
            throw new LaunchError("L02");
        }
    }

    // ---------- Hardware y claves ----------
    public static string HuellaHw(string modelo, string serie) =>
        Hex(SHA256.HashData(Encoding.UTF8.GetBytes("AFDG-HW-v1\0" + modelo + "\0" + serie)));

    static byte[] Kek(string unidad, string fp, byte[] pepper) =>
        HKDF.DeriveKey(HashAlgorithmName.SHA256, Convert.FromHexString(fp).Concat(pepper).ToArray(), 32,
                       Encoding.UTF8.GetBytes(unidad), Encoding.ASCII.GetBytes("AFDG-KEK-v1"));

    static byte[] Aead(byte[] key, byte[] nonce, byte[] ct, int off, int len, byte[] aad)
    {
        var c = new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305(); // la de .NET no existe en Windows 10
        c.Init(false, new AeadParameters(new KeyParameter(key), 128, nonce, aad));
        var out_ = new byte[c.GetOutputSize(len)];
        int n = c.ProcessBytes(ct, off, len, out_, 0);
        n += c.DoFinal(out_, n); // lanza InvalidCipherTextException si la etiqueta no coincide
        return n == out_.Length ? out_ : out_[..n];
    }

    static byte[] Desenvolver(byte[] kek, string wrap, string unidad, string pkg, string ver)
    {
        var w = B64(wrap);
        if (w.Length < 12 + 16) throw new LaunchError("L02", pkg);
        try { return Aead(kek, w[..12], w, 12, w.Length - 12, Encoding.UTF8.GetBytes($"{unidad}|{pkg}|{ver}")); }
        catch (InvalidCipherTextException) { throw new LaunchError("L02", pkg); }
    }

    public static byte[] DescifrarPaquete(byte[] blob, byte[] cek, string pkg, string ver)
    {
        if (blob.Length < 7 || !blob.AsSpan(0, 5).SequenceEqual(Magic)) throw new LaunchError("P01", "cabecera");
        int ml = (blob[5] << 8) | blob[6];
        int hlen = 7 + ml + 7;
        if (blob.Length < hlen + 16) throw new LaunchError("P01", "cabecera");
        try
        {
            var meta = JsonDocument.Parse(blob.AsMemory(7, ml)).RootElement;
            if (meta.EnumerateObject().Count() != 2 || meta.GetProperty("pkg").GetString() != pkg ||
                meta.GetProperty("ver").GetString() != ver)
                throw new LaunchError("P01", "paquete distinto");
        }
        catch (Exception e) when (e is JsonException or KeyNotFoundException or InvalidOperationException)
        {
            throw new LaunchError("P01", "cabecera");
        }
        var prefix = blob[(7 + ml)..hlen];
        var aad = SHA256.HashData(blob.AsSpan(0, hlen));
        int body = blob.Length - hlen, step = Chunk + 16;
        int count = Math.Max(1, (body + step - 1) / step);
        using var out_ = new MemoryStream(Math.Max(0, body - count * 16));
        var nonce = new byte[12];
        prefix.CopyTo(nonce, 0);
        for (int i = 0; i < count; i++)
        {
            nonce[7] = (byte)(i >> 24); nonce[8] = (byte)(i >> 16); nonce[9] = (byte)(i >> 8); nonce[10] = (byte)i;
            nonce[11] = (byte)(i == count - 1 ? 1 : 0);
            int off = hlen + i * step, len = Math.Min(step, blob.Length - off);
            try { out_.Write(Aead(cek, nonce, blob, off, len, aad)); }
            catch (Exception e) when (e is InvalidCipherTextException or ArgumentException)
            {
                throw new LaunchError("P01", $"bloque {i}");
            }
        }
        return out_.ToArray();
    }

    static int[] Ver(string v) => v.Split('.').Select(int.Parse).ToArray();

    static int CompararVersion(string a, string b)
    {
        var x = Ver(a); var y = Ver(b);
        for (int i = 0; i < Math.Max(x.Length, y.Length); i++)
        {
            int p = i < x.Length ? x[i] : 0, q = i < y.Length ? y[i] : 0;
            if (p != q) return p.CompareTo(q);
        }
        return 0;
    }

    static bool IgualesTiempoConstante(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));

    // ---------- Apertura ----------
    /// <summary>Valida en orden fijo: hardware, licencia, revocación, manifiesto. Falla cerrado.</summary>
    public static Unidad Abrir(string raiz, (string Bus, string Modelo, string Serie) id, Sello sello, string versionLanzador)
    {
        bool prod = sello.Perfil == "prod";
        if (id.Bus != "USB" || string.IsNullOrEmpty(id.Serie)) throw new LaunchError("L01", "no es USB con serie");
        var fp = HuellaHw(id.Modelo, id.Serie);
        string licT, manT;
        try
        {
            licT = File.ReadAllText(Path.Combine(raiz, "license.afl"), Encoding.UTF8);
            manT = File.ReadAllText(Path.Combine(raiz, "manifest.afm"), Encoding.UTF8);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { throw new LaunchError("L02", "faltan archivos"); }

        var lic = VerificarToken(sello.Lic, LicCtx, licT, prod);
        string unidad, cliente;
        int maxSeq;
        Dictionary<string, (string Ver, string Wrap)> claves;
        try
        {
            if (lic.GetProperty("typ").GetString() != "afdg-license" || lic.GetProperty("v").GetInt32() != 1)
                throw new LaunchError("L02");
            if (lic.TryGetProperty("exp", out var exp) && exp.ValueKind == JsonValueKind.String &&
                string.CompareOrdinal(DateTime.Today.ToString("yyyy-MM-dd"), exp.GetString()) > 0)
                throw new LaunchError("L02", "vencida");
            if (!IgualesTiempoConstante(lic.GetProperty("hw").GetProperty("fp").GetString() ?? "", fp))
                throw new LaunchError("L01");
            unidad = lic.GetProperty("unit_id").GetString()!;
            cliente = lic.TryGetProperty("customer_ref", out var c) ? c.GetString() ?? "" : "";
            maxSeq = lic.GetProperty("max_seq").GetInt32();
            claves = lic.GetProperty("keys").EnumerateArray().ToDictionary(
                k => k.GetProperty("pkg").GetString()!, k => (k.GetProperty("ver").GetString()!, k.GetProperty("wrap").GetString()!));
        }
        catch (Exception e) when (e is KeyNotFoundException or InvalidOperationException or FormatException or ArgumentException)
        {
            throw new LaunchError("L02");
        }
        if (sello.Revocadas.Contains(unidad)) throw new LaunchError("L03");

        var man = VerificarToken(sello.Man, ManCtx, manT, prod);
        int seq;
        string minLanzador;
        JsonElement pkgs;
        try
        {
            seq = man.GetProperty("seq").GetInt32();
            pkgs = man.GetProperty("pkgs");
            minLanzador = man.TryGetProperty("min_launcher", out var ml) ? ml.GetString()! : "0.0.0";
            if (pkgs.ValueKind != JsonValueKind.Object) throw new LaunchError("L02");
        }
        catch (Exception e) when (e is KeyNotFoundException or InvalidOperationException or FormatException)
        {
            throw new LaunchError("L02");
        }
        if (seq < sello.MinSeq || seq > maxSeq || CompararVersion(minLanzador, versionLanzador) > 0)
            throw new LaunchError("P02");

        var kek = Kek(unidad, fp, sello.Pepper);
        var lista = new List<Paquete>();
        foreach (var p in pkgs.EnumerateObject())
        {
            if (!Nombre.IsMatch(p.Name) || !claves.ContainsKey(p.Name)) continue;
            var e = p.Value;
            string Str(string k, string def) => e.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString()! : def;
            int? grado = e.TryGetProperty("grado", out var g) && g.ValueKind == JsonValueKind.Number ? g.GetInt32() : null;
            lista.Add(new Paquete(p.Name, Str("titulo", p.Name), Str("icono", "📘"), grado, Str("ver", "")));
        }

        byte[] Leer(string pkg)
        {
            if (!Nombre.IsMatch(pkg) || !pkgs.TryGetProperty(pkg, out var e) || !claves.TryGetValue(pkg, out var k))
                throw new LaunchError("P02", pkg);
            var ver = e.GetProperty("ver").GetString()!;
            if (k.Ver != ver) throw new LaunchError("P02", pkg);
            byte[] blob;
            try { blob = File.ReadAllBytes(Path.Combine(raiz, "pkgs", pkg + ".afpk")); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { throw new LaunchError("P01", pkg); }
            if (!IgualesTiempoConstante(Hex(SHA256.HashData(blob)), e.GetProperty("sha256").GetString() ?? ""))
                throw new LaunchError("P01", pkg);
            return DescifrarPaquete(blob, Desenvolver(kek, k.Wrap, unidad, pkg, ver), pkg, ver);
        }

        return new Unidad { Id = unidad, Cliente = cliente, Paquetes = lista, Leer = Leer };
    }
}
