// Uso: dotnet run -- <carpeta_usb> <modelo> <serie> <esperado.json>
using System.Security.Cryptography;
using System.Text.Json;
using AulasFuturas;

var (raiz, modelo, serie) = (args[0], args[1], args[2]);
var esperado = JsonSerializer.Deserialize<Dictionary<string, Dictionary<string, string>>>(File.ReadAllText(args[3]))!;
var sello = Nucleo.LeerSello(File.ReadAllBytes(Path.Combine(raiz, "AulasFuturas.exe")))!;
int ok = 0, total = 0;
var tmp = Directory.CreateTempSubdirectory("afdg-cs-").FullName;

void Caso(string nombre, Func<bool> f)
{
    total++;
    bool r;
    try { r = f(); } catch (Exception e) { Console.WriteLine($"   excepción: {e.GetType().Name}: {e.Message}"); r = false; }
    if (r) ok++;
    Console.WriteLine($"{(r ? "OK   " : "FALLA")} {nombre}");
}

string Codigo(Action a) { try { a(); return "abrió"; } catch (LaunchError e) { return e.Code; } }

string Copia(Action<string>? alterar = null)
{
    var d = Path.Combine(tmp, Guid.NewGuid().ToString("N"));
    foreach (var f in Directory.GetFiles(raiz, "*", SearchOption.AllDirectories))
    {
        var t = Path.Combine(d, Path.GetRelativePath(raiz, f));
        Directory.CreateDirectory(Path.GetDirectoryName(t)!);
        File.Copy(f, t);
    }
    alterar?.Invoke(d);
    return d;
}

var id = ("USB", modelo, serie);
Caso("Abre y el contenido coincide con Python", () =>
{
    var u = Nucleo.Abrir(raiz, id, sello, "1.0.0");
    foreach (var p in u.Paquetes)
    {
        var real = u.Archivos(p.Id).ToDictionary(k => k.Key, k => Convert.ToHexString(SHA256.HashData(k.Value)).ToLowerInvariant());
        if (!esperado[p.Id].OrderBy(x => x.Key).SequenceEqual(real.OrderBy(x => x.Key))) return false;
    }
    return u.Paquetes.Count == esperado.Count;
});
Caso("Otra USB → L01", () => Codigo(() => Nucleo.Abrir(raiz, ("USB", modelo, serie + "X"), sello, "1.0.0")) == "L01");
Caso("Disco no USB → L01", () => Codigo(() => Nucleo.Abrir(raiz, ("SATA", modelo, serie), sello, "1.0.0")) == "L01");
Caso("Licencia alterada → L02", () => Codigo(() => Nucleo.Abrir(Copia(d =>
{
    var t = File.ReadAllText(Path.Combine(d, "license.afl")).Split('.');
    var pl = Nucleo.B64(t[1]); pl[^2] ^= 1;
    t[1] = Convert.ToBase64String(pl).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    File.WriteAllText(Path.Combine(d, "license.afl"), string.Join('.', t));
}), id, sello, "1.0.0")) == "L02");
Caso("Licencia vacía → L02", () => Codigo(() => Nucleo.Abrir(Copia(d => File.WriteAllText(Path.Combine(d, "license.afl"), "")), id, sello, "1.0.0")) == "L02");
Caso("Manifiesto basura → L02", () => Codigo(() => Nucleo.Abrir(Copia(d => File.WriteAllText(Path.Combine(d, "manifest.afm"), "a.b.c")), id, sello, "1.0.0")) == "L02");
Caso("Clave de prueba en lanzador de producción → L02", () => Codigo(() => Nucleo.Abrir(raiz, id, sello with { Perfil = "prod" }, "1.0.0")) == "L02");
Caso("Unidad revocada → L03", () =>
{
    var u = Nucleo.Abrir(raiz, id, sello, "1.0.0").Id;
    return Codigo(() => Nucleo.Abrir(raiz, id, sello with { Revocadas = [u] }, "1.0.0")) == "L03";
});
Caso("Retroceso de versión → P02", () => Codigo(() => Nucleo.Abrir(raiz, id, sello with { MinSeq = 99 }, "1.0.0")) == "P02");
Caso("Lanzador antiguo → P02", () => Codigo(() => Nucleo.Abrir(raiz, id, sello, "0.1.0")) == "P02");
foreach (var (nombre, alt) in new (string, Func<byte[], byte[]>)[] {
    ("Byte alterado", b => { b[b.Length / 2] ^= 1; return b; }),
    ("Paquete truncado", b => b[..^20]),
})
{
    Caso($"{nombre} → P01", () =>
    {
        var u = Nucleo.Abrir(Copia(d =>
        {
            var f = Directory.GetFiles(Path.Combine(d, "pkgs")).OrderBy(x => x).Last();
            File.WriteAllBytes(f, alt(File.ReadAllBytes(f)));
        }), id, sello, "1.0.0");
        return u.Paquetes.Select(p => Codigo(() => u.Archivos(p.Id))).Contains("P01");
    });
}
Caso("Paquete de otro curso renombrado → P01", () =>
{
    var u = Nucleo.Abrir(Copia(d =>
    {
        var fs = Directory.GetFiles(Path.Combine(d, "pkgs")).OrderBy(x => x).ToArray();
        File.Copy(fs[1], fs[0], true);
    }), id, sello, "1.0.0");
    return Codigo(() => u.Archivos(u.Paquetes.OrderBy(p => p.Id).First().Id)) == "P01";
});
Caso("Sello del lanzador real se lee al final del .exe", () => args.Length < 5 || Nucleo.LeerSello(File.ReadAllBytes(args[4])) != null);
if (Environment.GetEnvironmentVariable("AFDG_PORTAL_HTML") is { } salida)
    File.WriteAllText(salida, Portal.Html(Nucleo.Abrir(raiz, id, sello, "1.0.0"), "1.0.0") + "<script>" +
        Portal.ScriptActividad(Nucleo.Abrir(raiz, id, sello, "1.0.0"), Portal.Url) + "</script>");
Directory.Delete(tmp, true);
Console.WriteLine($"\n{ok}/{total} pruebas del núcleo C#");
return ok == total ? 0 : 1;
