"""Demostración automática en perfil de prueba: no toca nada real.

Crea proyecto, almacén, lanzador simulado y USB simuladas en una carpeta temporal."""
import contextlib, io, json, os, pathlib, shutil, sys, tempfile

tmp = pathlib.Path(tempfile.mkdtemp(prefix="afdg-demo-"))
os.environ.update(AFDG_VAULT=str(tmp / "almacen"), AFDG_PASSPHRASE="frase-de-prueba-demo")
USB = {}


def usb(nombre, modelo="Kingston DataTraveler", serie=None):
    d = tmp / "usb" / nombre
    d.mkdir(parents=True, exist_ok=True)
    USB[str(d.resolve())] = f"{modelo}|{serie or 'SN' + nombre.upper()}"
    os.environ["AFDG_FAKE_USB"] = json.dumps(USB)
    return d


import afdg_crypto as ac  # noqa: E402
import afdg_emisor as em  # noqa: E402
import afdg_publicar as pub  # noqa: E402


def silencio(fn, *a):
    with contextlib.redirect_stdout(io.StringIO()):
        try:
            return fn(*a)
        except SystemExit as e:
            return e.code


def ultimo_informe(sub):
    fs = sorted((tmp / "salida" / sub).glob("*/informe.json"), key=lambda f: f.stat().st_mtime)
    return json.loads(fs[-1].read_text("utf-8"))


def fallidas(inf): return {p["codigo"]: p["detalle"] for p in inf["pruebas"] if p["resultado"] == "FALLIDA"}


def main():
    origen = tmp / "proyecto"
    for pkg, extra in (("g1-demo-lectura", 0), ("g2-demo-numeros", 200_000)):
        (origen / pkg).mkdir(parents=True)
        (origen / pkg / "index.html").write_text(f"<!doctype html><title>{pkg}</title><h1>{pkg}</h1>", "utf-8")
        (origen / pkg / "datos.json").write_text(json.dumps({"relleno": "x" * extra}), "utf-8")
    base = tmp / "AulasFuturas-base.exe"
    base.write_bytes(b"MZ" + b"\x00" * 62 + b"PE\x00\x00" + os.urandom(4000))
    al = em.Almacen("test")
    silencio(al.init, tmp / "claves_publicas.test.json")
    al.sellar_lanzador(base, tmp / "AulasFuturas.exe")
    import struct, zlib
    fila = b"\x00" + b"\x1d\x4e\xd8\xff" * 32
    chunk = lambda t, d: struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))
    (tmp / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 32, 32, 8, 6, 0, 0, 0))
                                   + chunk(b"IDAT", zlib.compress(fila * 32)) + chunk(b"IEND", b""))
    cfg_path = tmp / "config" / "publicacion.prueba.json"
    cfg_path.parent.mkdir()
    cfg_path.write_text(json.dumps({"perfil": "test", "origen": str(origen), "lanzador": str(tmp / "AulasFuturas.exe"), "logo": str(tmp / "logo.png"),
                                    "salida": str(tmp / "salida"), "version": "2026.1", "secuencia": 1,
                                    "capacidad_usb_gb": 16, "lanzador_minimo": "1.0.0"}), "utf-8")
    cfg = pub.cargar_config(cfg_path)
    args = lambda **k: type("A", (), {"cliente": "C-DEMO", "edicion": "completa", "grados": "1,2",
                                      "sustituye": None, "reemitir": None, **k})
    r = []

    def check(n, desc, ok):
        r.append(ok)
        print(f"{n:2}. {'OK   ' if ok else 'FALLA'} {desc}")

    check(1, "Revisión del origen aprobada", silencio(pub.cmd_revisar, cfg))
    check(2, "Copia maestra APROBADA con logo y autorun.inf", silencio(pub.cmd_maestra, cfg)
          and all((next((tmp / "salida" / "maestras").iterdir()) / "usb" / n).is_file() for n in ("logo.ico", "autorun.inf")))
    maestra = next((tmp / "salida" / "maestras").iterdir())
    u1, u2 = usb("u1"), usb("u2")
    check(3, "Unidad 1 aprobada (grados 1 y 2)", silencio(pub.cmd_unidad, cfg, args(maestra=maestra, destino=u1)))
    check(4, "Unidad 2 aprobada (solo grado 1)",
          silencio(pub.cmd_unidad, cfg, args(maestra=maestra, destino=u2, grados="1")))
    check(5, "Verificación de soporte de la unidad 1", silencio(pub.cmd_verificar, cfg, args(destino=u1)))

    u3 = usb("u3")
    (u3 / "foto.jpg").write_bytes(b"x")
    ok = not silencio(pub.cmd_unidad, cfg, args(maestra=maestra, destino=u3)) and "U04" in fallidas(ultimo_informe("unidades"))
    check(6, "Rechazo: USB no vacía (U04)", ok)

    u1b = usb("u1b", serie="SNU1")  # mismo hardware que u1
    ok = not silencio(pub.cmd_unidad, cfg, args(maestra=maestra, destino=u1b)) and "U00" in fallidas(ultimo_informe("unidades"))
    check(7, "Rechazo: USB ya registrada (U00)", ok)

    def copia(nombre, serie, alterar=None):
        d = usb(nombre, serie=serie)
        shutil.rmtree(d)
        shutil.copytree(u1, d)
        if alterar:
            alterar(d)
        silencio(pub.cmd_verificar, cfg, args(destino=d))
        return fallidas(ultimo_informe("verificaciones"))

    f = copia("u4", "SNOTRA")
    check(8, "Rechazo: copia en otra USB (L01)", "[L01]" in f.get("V01", ""))

    def alterar_pkg(d):
        p = next((d / "pkgs").glob("*.afpk"))
        b = bytearray(p.read_bytes())
        b[len(b) // 2] ^= 1
        p.write_bytes(bytes(b))
    f = copia("u5", "SNU1", alterar_pkg)
    check(9, "Rechazo: paquete alterado (P01)", "(P01)" in f.get("V02", ""))

    def alterar_lic(d):
        kid, p, s = (d / "license.afl").read_text().split(".")
        lic = json.loads(ac.b64d(p))
        lic["grades"] = [1, 2, 3, 4, 5, 6]
        (d / "license.afl").write_text(f"{kid}.{ac.b64e(ac.payload_bytes(lic))}.{s}")
    f = copia("u6", "SNU1", alterar_lic)
    check(10, "Rechazo: licencia alterada (L02)", "[L02]" in f.get("V01", ""))

    m2 = tmp / "salida" / "maestras" / "alterada"
    shutil.copytree(maestra, m2)
    (m2 / "usb" / "LEEME.txt").write_text("alterado")
    ok = not silencio(pub.cmd_unidad, cfg, args(maestra=m2, destino=usb("u7"))) and "U02" in fallidas(ultimo_informe("unidades"))
    check(11, "Rechazo: maestra alterada (U02)", ok)

    origen2 = tmp / "proyecto2"
    shutil.copytree(origen, origen2)
    (origen2 / "g1-demo-lectura" / "clave.pem").write_text("-----BEGIN PRIVATE KEY-----")
    cfg2 = dict(cfg, origen=origen2)
    check(12, "Rechazo: archivo prohibido en el origen (R01)", not silencio(pub.cmd_revisar, cfg2))

    uid2 = json.loads(ac.b64d((u2 / "license.afl").read_text().split(".")[1]))["unit_id"]
    al.marcar(uid2, "revocada", "demo")
    silencio(pub.cmd_verificar, cfg, args(destino=u2))
    check(13, "Rechazo: unidad dada de baja (L03)", "[L03]" in fallidas(ultimo_informe("verificaciones")).get("V01", ""))

    sello = ac.read_seal((u1 / "AulasFuturas.exe").read_bytes())
    try:
        ac.open_unit(u1, sello["pub"], ac.b64d(sello["pepper"]), prod=True, identity=ac.usb_identity(u1, True))
        ok = False
    except ac.LaunchError as e:
        ok = e.code == "L02"
    check(14, "Rechazo: clave de prueba en lanzador de producción (L02)", ok)

    exp = os.environ.get("AFDG_DEMO_EXPORT")  # datos para las pruebas cruzadas del lanzador (lanzador/pruebas)
    if exp:
        lic, _, read = ac.open_unit(u1, sello["pub"], ac.b64d(sello["pepper"]), prod=False, identity=ac.usb_identity(u1, True))
        pathlib.Path(exp).write_text(json.dumps({"usb": str(u1), "modelo": "Kingston DataTraveler", "serie": "SNU1",
                                                 "esperado": {k["pkg"]: ac.zip_inventory(read(k["pkg"])) for k in lic["keys"]}}))
    print(f"\n{sum(r)}/{len(r)} comprobaciones correctas")
    print(f"Archivos de la demostración: {tmp}")
    return 0 if all(r) else 1


if __name__ == "__main__":
    sys.exit(main())
