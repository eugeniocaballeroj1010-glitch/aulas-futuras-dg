"""Generador: revisar el origen, crear la copia maestra, preparar unidades y verificar USB."""
import argparse, ctypes, io, json, os, pathlib, re, shutil, struct, subprocess, sys, traceback
from datetime import datetime
import afdg_crypto as ac
from afdg_emisor import Almacen, EmisorError, comprobar_sello

EXT_OK = {".html", ".htm", ".css", ".js", ".mjs", ".json", ".txt", ".png", ".jpg", ".jpeg", ".gif", ".svg",
          ".webp", ".ico", ".mp3", ".ogg", ".wav", ".m4a", ".mp4", ".webm", ".woff", ".woff2", ".ttf", ".otf"}
PROHIBIDOS = re.compile(r"(\.pem|\.key|\.p12|\.pfx|\.env|\.exe|\.dll|\.bat|\.cmd|\.ps1|\.vbs|\.msi|\.lnk|\.scr)$"
                        r"|^(pepper.*|ceks.*|registro\.jsonl|id_rsa.*)$", re.I)
IGNORAR = {"thumbs.db", "desktop.ini", ".ds_store"}
EXTERNO_FALLA = re.compile(r"<(?:script|link)\b[^>]*\b(?:src|href)\s*=\s*[\"']https?://|@import\s+(?:url\()?[\"']?https?://"
                           r"|url\(\s*[\"']?https?://", re.I)
EXTERNO_AVISO = re.compile(r"[\"'](https?://(?!www\.w3\.org)[^\"'\s]+)", re.I)
SISTEMA_USB = {"system volume information", "$recycle.bin"}
LANZADOR = "AulasFuturas.exe"
OCULTOS = ("autorun.inf", "logo.ico", "logo.png", "license.afl", "manifest.afm", "pkgs")  # en la USB solo se ven el .exe y LEEME


def ahora(): return datetime.now().strftime("%Y%m%d-%H%M%S")


# ---------------- Configuración ----------------

def cargar_config(ruta):
    cfg = {k: v for k, v in json.loads(pathlib.Path(ruta).read_text("utf-8")).items() if not k.startswith("_")}
    base = pathlib.Path(ruta).resolve().parent.parent
    for k in ("origen", "lanzador", "salida"):
        p = pathlib.Path(os.path.expandvars(cfg[k]))
        cfg[k] = (p if p.is_absolute() else base / p).resolve()
    if cfg["perfil"] not in ("test", "prod"):
        raise SystemExit("perfil debe ser test o prod")
    if cfg["salida"] == cfg["origen"] or cfg["origen"] in cfg["salida"].parents:
        raise SystemExit("La salida no puede estar dentro del origen.")
    cfg.setdefault("lanzador_minimo", "1.0.0")
    cfg.setdefault("capacidad_usb_gb", 16)
    cfg.setdefault("exigir_firma_lanzador", cfg["perfil"] == "prod")
    cfg["secuencia"] = int(cfg["secuencia"])
    if cfg.get("logo"):
        p = pathlib.Path(os.path.expandvars(cfg["logo"]))
        cfg["logo"] = (p if p.is_absolute() else base / p).resolve()
    return cfg


# ---------------- Informes ----------------

class Informe:
    def __init__(self, titulo, carpeta):
        self.titulo, self.carpeta, self.pruebas, self.datos, self.avisos = titulo, pathlib.Path(carpeta), [], {}, []

    def prueba(self, codigo, desc, fn):
        """Ejecuta fn(); devuelve su resultado o None. Cualquier excepción = FALLIDA."""
        try:
            r = fn()
            ok, det = (r if isinstance(r, tuple) else (r is not False, ""))
        except (ac.LaunchError, EmisorError, OSError, ValueError, KeyError, RuntimeError) as e:
            ok, det, r = False, str(e), None
        except Exception as e:  # defecto inesperado: se registra y falla
            ok, det, r = False, f"{type(e).__name__}: {e}", None
            traceback.print_exc()
        self.pruebas.append({"codigo": codigo, "prueba": desc, "resultado": "APROBADA" if ok else "FALLIDA",
                             "detalle": det})
        print(f"  {codigo} {'APROBADA' if ok else 'FALLIDA '}  {desc}" + (f" — {det}" if det else ""))
        return ok

    @property
    def aprobado(self): return bool(self.pruebas) and all(p["resultado"] == "APROBADA" for p in self.pruebas)

    def escribir(self, cierre=""):
        self.carpeta.mkdir(parents=True, exist_ok=True)
        estado = "APROBADA" if self.aprobado else "RECHAZADA"
        md = [f"# {self.titulo}", "", f"**Estado: {estado}**", ""]
        md += [f"- {k}: {v}" for k, v in self.datos.items()]
        md += ["", "| Código | Prueba | Resultado | Detalle |", "|---|---|---|---|"]
        md += [f"| {p['codigo']} | {p['prueba']} | {p['resultado']} | {p['detalle'].replace('|', '/')} |"
               for p in self.pruebas]
        if self.avisos:
            md += ["", "## Advertencias", ""] + [f"- {a}" for a in self.avisos]
        if cierre:
            md += ["", f"**{cierre}**"]
        (self.carpeta / "informe.md").write_text("\n".join(md) + "\n", "utf-8")
        (self.carpeta / "informe.json").write_text(json.dumps(
            {"titulo": self.titulo, "estado": estado, "datos": self.datos, "pruebas": self.pruebas,
             "advertencias": self.avisos}, indent=2, ensure_ascii=False, default=str), "utf-8")
        return estado


# ---------------- Revisión del origen ----------------

def titulo_de(carpeta):
    meta = carpeta / "paquete.json"
    d = json.loads(meta.read_text("utf-8")) if meta.exists() else {}
    if "titulo" not in d:
        m = re.search(r"<title>([^<]+)</title>", (carpeta / "index.html").read_text("utf-8", "replace"), re.I)
        d["titulo"] = m.group(1).strip() if m else carpeta.name
    return {"titulo": d["titulo"], "icono": d.get("icono", "📘")}


def revisar_origen(origen):
    """Devuelve (problemas, avisos, inventario {pkg: {ruta: sha256}}, metadatos)."""
    origen, prob, avisos, inv, meta = pathlib.Path(origen), [], [], {}, {}
    if not origen.is_dir():
        return [f"No existe el origen {origen}"], avisos, inv, meta
    for item in sorted(origen.iterdir()):
        if item.is_file():
            avisos.append(f"Archivo suelto en la raíz ignorado: {item.name}")
            continue
        if item.is_symlink():
            prob.append(f"{item.name}: enlace simbólico no permitido")
            continue
        try:
            ac.check_name(item.name)
        except ValueError:
            prob.append(f"{item.name}: nombre inválido (minúsculas, números y guiones; ej. g1-matematicas)")
            continue
        if not (item / "index.html").is_file():
            prob.append(f"{item.name}: falta index.html")
        archivos = {}
        for f in sorted(item.rglob("*")):
            rel = f.relative_to(item).as_posix()
            if f.is_symlink():
                prob.append(f"{item.name}/{rel}: enlace simbólico no permitido")
                continue
            if f.is_dir():
                if f.name.lower() in (".git", "__pycache__", "node_modules"):
                    prob.append(f"{item.name}/{rel}: carpeta prohibida")
                continue
            if f.name.lower() in IGNORAR:
                avisos.append(f"{item.name}/{rel}: archivo del sistema, se debe borrar")
                prob.append(f"{item.name}/{rel}: archivo del sistema no permitido")
                continue
            if PROHIBIDOS.search(f.name):
                prob.append(f"{item.name}/{rel}: archivo prohibido")
                continue
            if f.suffix.lower() not in EXT_OK:
                prob.append(f"{item.name}/{rel}: extensión no permitida ({f.suffix or 'sin extensión'})")
                continue
            if any(p.startswith(".") for p in f.relative_to(item).parts):
                prob.append(f"{item.name}/{rel}: archivo oculto no permitido")
                continue
            data = f.read_bytes()
            archivos[rel] = ac.sha256(data)
            if f.suffix.lower() in (".html", ".htm", ".css", ".js", ".mjs"):
                txt = data.decode("utf-8", "replace")
                if EXTERNO_FALLA.search(txt):
                    prob.append(f"{item.name}/{rel}: carga recursos de internet (no funciona sin conexión)")
                for u in sorted(set(EXTERNO_AVISO.findall(txt)))[:3]:
                    avisos.append(f"{item.name}/{rel}: enlace externo {u[:70]}")
        inv[item.name] = archivos
        if (item / "index.html").is_file():
            try:
                meta[item.name] = titulo_de(item)
            except ValueError as e:
                prob.append(f"{item.name}/paquete.json: {e}")
    if not inv:
        prob.append("El origen no tiene paquetes")
    return prob, avisos, inv, meta


def cmd_revisar(cfg):
    carpeta = cfg["salida"] / "revisiones" / ahora()
    inf = Informe("Revisión del proyecto fuente", carpeta)
    inf.datos.update(origen=str(cfg["origen"]))
    res = {}

    def r01():
        prob, avisos, inv, meta = revisar_origen(cfg["origen"])
        inf.avisos += avisos
        res.update(inv=inv)
        inf.datos.update(paquetes=len(inv), archivos=sum(len(v) for v in inv.values()))
        return (not prob, "; ".join(prob[:12]) + (f" (+{len(prob) - 12})" if len(prob) > 12 else ""))
    inf.prueba("R01", "Estructura, nombres, extensiones y archivos prohibidos", r01)
    carpeta.mkdir(parents=True, exist_ok=True)
    (carpeta / "inventario.json").write_text(json.dumps(res.get("inv", {}), indent=2), "utf-8")
    estado = inf.escribir()
    print(f"\nRevisión: {estado}. Informe: {carpeta / 'informe.md'}")
    return inf.aprobado


# ---------------- Utilidades de imagen ----------------

def inventario_dir(d):
    """{ruta: sha256} sin entrar en carpetas del sistema de Windows (la raíz de la USB las tiene)."""
    d, out = pathlib.Path(d), {}
    for raiz, dirs, files in os.walk(d):
        dirs[:] = sorted(x for x in dirs if x.lower() not in SISTEMA_USB)
        for f in files:
            p = pathlib.Path(raiz) / f
            out[p.relative_to(d).as_posix()] = ac.sha256_file(p)
    return dict(sorted(out.items()))


def buscar_secretos(carpeta, secretos):
    patrones = [b"PRIVATE KEY"]
    for s in secretos:
        import base64
        patrones += [s, ac.b64e(s).encode(), base64.b64encode(s), s.hex().encode(), s.hex().upper().encode()]
    hallados = []
    for f in sorted(pathlib.Path(carpeta).rglob("*")):
        if f.is_file():
            data = f.read_bytes()
            if any(p in data for p in patrones):
                hallados.append(f.relative_to(carpeta).as_posix())
    return hallados


def authenticode_valida(exe):
    if os.name != "nt":
        return False, "solo puede verificarse en Windows"
    ps = f"(Get-AuthenticodeSignature -LiteralPath '{exe}').Status"
    r = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True, timeout=60)
    st = r.stdout.strip()
    return st == "Valid", f"estado de la firma: {st or r.stderr.strip()[:80]}"


def preparar_logo(data):
    """Devuelve (png_256, ico, lado_original). Con Pillow acepta PNG/JPG de cualquier tamaño:
    recorta el margen blanco, lo centra en un cuadrado y genera el ícono en 16–256 px."""
    try:
        from PIL import Image, ImageChops
    except ImportError:
        return _logo_sin_pillow(data)
    try:
        im = Image.open(io.BytesIO(data)).convert("RGBA")
    except Exception:
        raise ValueError("el logo debe ser una imagen PNG o JPG")
    fondo = Image.new("RGBA", im.size, (255, 255, 255, 255))
    caja = ImageChops.difference(Image.alpha_composite(fondo, im).convert("RGB"), fondo.convert("RGB")).getbbox()
    if caja:
        im = im.crop(caja)
    lado = max(im.size)
    cuadro = Image.new("RGBA", (lado, lado), (0, 0, 0, 0))
    cuadro.paste(im, ((lado - im.width) // 2, (lado - im.height) // 2))
    cuadro = cuadro.resize((256, 256), Image.LANCZOS)
    png, ico = io.BytesIO(), io.BytesIO()
    cuadro.save(png, "PNG", optimize=True)
    cuadro.save(ico, "ICO", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    return png.getvalue(), ico.getvalue(), lado


def _logo_sin_pillow(data):
    """PNG cuadrado de 16 a 256 px incrustado tal cual en el ICO (Windows Vista o superior)."""
    if data[:8] != b"\x89PNG\r\n\x1a\n" or data[12:16] != b"IHDR":
        raise ValueError("el logo debe ser PNG (o instale Pillow: python -m pip install pillow)")
    w, h = struct.unpack(">II", data[16:24])
    if w != h or not 16 <= w <= 256:
        raise ValueError(f"sin Pillow el logo debe ser cuadrado de 16 a 256 px (mide {w}×{h}); instale Pillow")
    lado = 0 if w == 256 else w
    ico = struct.pack("<HHH", 0, 1, 1) + struct.pack("<BBBBHHII", lado, lado, 0, 0, 1, 32, len(data), 22) + data
    return data, ico, w


AUTORUN = "[autorun]\r\nicon=logo.ico\r\nlabel=Aulas Futuras DG\r\n"


def ocultar(destino):
    """Oculta en la USB todo menos el lanzador y LEEME (solo Windows; en otros sistemas no aplica)."""
    if os.name != "nt":
        return
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    for n in OCULTOS:
        p = pathlib.Path(destino) / n
        if p.exists():
            attrs = 0x2 | (0x4 | 0x1 if n == "autorun.inf" else 0)  # oculto (+ sistema y solo lectura en autorun.inf)
            k32.SetFileAttributesW(str(p), attrs | (0x10 if p.is_dir() else 0))


def leeme(cfg):
    return f"""AULAS FUTURAS DG — Contenido educativo en USB
Versión {cfg['version']} · publicación {cfg['secuencia']}

CÓMO ABRIR
1. Conecte esta memoria USB a una computadora con Windows 10 u 11.
2. Abra la memoria y haga doble clic en {LANZADOR}.
3. Elija una actividad en el menú. El progreso se guarda en esta computadora.

No necesita internet. No copie los archivos a otra memoria ni al disco:
la licencia está atada a esta memoria USB y solo funciona desde ella.

SI APARECE UN MENSAJE
- "Windows protegió su PC": pulse "Más información" y luego "Ejecutar de todas formas".
- Código L01: ejecute el programa desde la memoria USB original.
- Código L02 o P01: algún archivo se dañó. Contacte a soporte con su número de unidad.
- Código W01: falta Microsoft Edge WebView2. Instálelo desde
  https://go.microsoft.com/fwlink/p/?LinkId=2124703 (una sola vez por computadora).

Soporte: indique el número de unidad que aparece en la etiqueta de la memoria.
"""


# ---------------- Copia maestra ----------------

def maestras_existentes(cfg):
    out = []
    for f in (cfg["salida"] / "maestras").glob("*/compilacion.json"):
        try:
            out.append(json.loads(f.read_text("utf-8")))
        except ValueError:
            pass
    return out


def cmd_maestra(cfg):
    comp_id = f"{cfg['version']}-s{cfg['secuencia']:03d}-{datetime.now().strftime('%Y%m%d-%H%M%S-%f')[:-3]}"
    carpeta = cfg["salida"] / "maestras" / comp_id
    usb = carpeta / "usb"
    inf = Informe(f"Copia maestra {comp_id}", carpeta)
    inf.datos.update(perfil=cfg["perfil"], version=cfg["version"], secuencia=cfg["secuencia"],
                     origen=str(cfg["origen"]), lanzador=str(cfg["lanzador"]))
    print(f"Copia maestra {comp_id}")
    st = {}
    for m in maestras_existentes(cfg):
        if m.get("perfil") == cfg["perfil"] and m.get("secuencia") == cfg["secuencia"] and m.get("estado") == "APROBADA":
            sys.exit(f"ERROR: la secuencia {cfg['secuencia']} ya se publicó en {m['id']}. Súbala en la configuración.")
    al = Almacen(cfg["perfil"])

    def m00():
        st["pub"] = al.publicas()
        return True
    if not inf.prueba("M00", "Almacén del emisor disponible", m00):
        inf.escribir("Copia maestra RECHAZADA.")
        return False

    def m01():
        prob, avisos, inv, meta = revisar_origen(cfg["origen"])
        inf.avisos += avisos
        st.update(inv=inv, meta=meta)
        return (not prob, "; ".join(prob[:10]))
    ok = inf.prueba("M01", "Estructura del origen", m01)

    if ok:
        usb.mkdir(parents=True)
        (usb / "pkgs").mkdir()
        ceks = al.claves_contenido(comp_id, sorted(st["inv"]), cfg["version"])
        pkgs = {}
        for pkg in sorted(st["inv"]):
            data, inv = ac.zip_folder(cfg["origen"] / pkg)
            st.setdefault("zip_inv", {})[pkg] = inv
            blob = ac.encrypt_bytes(data, ceks[pkg], pkg, cfg["version"])
            (usb / "pkgs" / f"{pkg}.afpk").write_bytes(blob)
            g = pkg.split("-", 1)[0]
            pkgs[pkg] = {"ver": cfg["version"], "size": len(blob), "sha256": ac.sha256(blob),
                         "grado": int(g[1:]) if g[:1] == "g" and g[1:].isdigit() else None, **st["meta"].get(pkg, {})}
        man = {"v": 1, "seq": cfg["secuencia"], "min_launcher": cfg["lanzador_minimo"], "pkgs": pkgs}
        (usb / "manifest.afm").write_text(al.firmar_manifiesto(man), "utf-8")
        if cfg["lanzador"].is_file():
            shutil.copy2(cfg["lanzador"], usb / LANZADOR)
        (usb / "LEEME.txt").write_text(leeme(cfg), "utf-8")
        if cfg.get("logo") and cfg["logo"].is_file():
            try:
                png, ico, _ = preparar_logo(cfg["logo"].read_bytes())
                (usb / "logo.ico").write_bytes(ico)
                (usb / "logo.png").write_bytes(png)
                (usb / "autorun.inf").write_bytes(AUTORUN.encode("ascii"))
            except ValueError:
                pass  # M09 lo informa
        st["ceks"] = ceks

        def m02():
            exe = usb / LANZADOR
            if not exe.exists():
                return False, f"no se encontró el lanzador {cfg['lanzador']}"
            data = exe.read_bytes()
            if data[:2] != b"MZ" or b"PE\x00\x00" not in data[:4096]:
                return False, "no es un ejecutable de Windows"
            prob = comprobar_sello(data, st["pub"])
            if prob:
                return False, "; ".join(prob)
            if cfg["exigir_firma_lanzador"]:
                return authenticode_valida(exe)
            inf.avisos.append("Lanzador sin verificación Authenticode (exigir_firma_lanzador = false).")
            return True, "sin firma Authenticode (permitido por configuración)"
        inf.prueba("M02", "Lanzador de Windows, sellado y firmado", m02)

        def m03():
            m = ac.verify_token(st["pub"]["man"], ac.MAN_CTX, (usb / "manifest.afm").read_text("utf-8"),
                                cfg["perfil"] == "prod")
            files = {f.stem for f in (usb / "pkgs").glob("*.afpk")}
            if set(m["pkgs"]) != files or set(m["pkgs"]) != set(st["inv"]):
                return False, "entradas del manifiesto distintas a los paquetes"
            for p, e in m["pkgs"].items():
                f = usb / "pkgs" / f"{p}.afpk"
                if ac.sha256_file(f) != e["sha256"] or f.stat().st_size != e["size"]:
                    return False, f"hash de {p} no coincide"
            return True, f"{len(files)} paquetes"
        inf.prueba("M03", "Manifiesto firmado y con entradas correctas", m03)

        def m04():
            for p in st["inv"]:
                data = ac.decrypt_bytes((usb / "pkgs" / f"{p}.afpk").read_bytes(), ceks[p], p, cfg["version"])
                if ac.zip_inventory(data) != st["inv"][p]:
                    return False, f"{p}: contenido distinto al inventario"
            return True
        inf.prueba("M04", "Cada paquete se descifra y coincide con el inventario", m04)

        def m05():
            p = sorted(st["inv"])[0]
            blob = bytearray((usb / "pkgs" / f"{p}.afpk").read_bytes())
            casos = []
            alt = bytearray(blob)
            alt[len(alt) // 2 + 20] ^= 0x01
            casos.append(("byte alterado", bytes(alt)))
            casos.append(("truncado", bytes(blob[:-(min(len(blob) - 40, ac.CHUNK + 16))])))
            casos.append(("último bloque quitado", bytes(blob[:-16])))
            for nombre, b in casos:
                try:
                    ac.decrypt_bytes(b, ceks[p], p, cfg["version"])
                    return False, f"no se detectó: {nombre}"
                except ac.LaunchError:
                    pass
            return True
        inf.prueba("M05", "Un byte alterado y un paquete truncado son detectados", m05)

        def m06():
            h = buscar_secretos(usb, al.secretos_crudos())
            return (not h, ("secretos en: " + ", ".join(h)) if h else "")
        inf.prueba("M06", "Ninguna clave, pepper ni clave de contenido en la imagen", m06)

        def m07():
            total = sum(f.stat().st_size for f in usb.rglob("*") if f.is_file())
            lim = cfg["capacidad_usb_gb"] * 1e9 * 0.9
            inf.datos["tamano_mb"] = round(total / 1e6, 1)
            return total < lim, f"{total / 1e6:.1f} MB de {lim / 1e6:.0f} MB permitidos"
        inf.prueba("M07", "La imagen ocupa menos del 90 % de la USB", m07)

        def m09():
            if not cfg.get("logo"):
                inf.avisos.append("Sin logo: la USB se verá con el ícono genérico de Windows.")
                return True, "sin logo configurado"
            if not cfg["logo"].is_file():
                return False, f"no existe {cfg['logo']}"
            return True, f"logo de {preparar_logo(cfg['logo'].read_bytes())[2]} px → ícono 16–256 px y nombre de la USB"
        inf.prueba("M09", "Marca: logo, ícono y nombre de la USB", m09)

    def m08():
        _, _, inv2, _ = revisar_origen(cfg["origen"])
        return inv2 == st.get("inv"), ""
    inf.prueba("M08", "El origen no cambió durante la compilación", m08)

    estado = "APROBADA" if inf.aprobado else "RECHAZADA"
    comp = {"id": comp_id, "perfil": cfg["perfil"], "version": cfg["version"], "secuencia": cfg["secuencia"],
            "fecha": datetime.now().isoformat(timespec="seconds"), "estado": estado,
            "pruebas": inf.pruebas, "archivos": inventario_dir(usb) if usb.exists() else {},
            "contenido": st.get("inv", {}), "paquetes": sorted(st.get("inv", {}))}
    carpeta.mkdir(parents=True, exist_ok=True)
    data = json.dumps(comp, indent=2, ensure_ascii=False).encode()
    (carpeta / "compilacion.json").write_bytes(data)
    (carpeta / "compilacion.afb").write_text(al.firmar_compilacion(data), "utf-8")
    inf.escribir(f"Estado: {estado}")
    print(f"\nCopia maestra {estado}: {carpeta}")
    return inf.aprobado


# ---------------- Unidad ----------------

def ruta_es_raiz(p):
    p = pathlib.Path(p).resolve()
    return p == pathlib.Path(p.anchor)


def contenido_destino(d):
    return [x.name for x in pathlib.Path(d).iterdir() if x.name.lower() not in SISTEMA_USB]


def copiar_seguro(src, dst):
    src, dst = pathlib.Path(src), pathlib.Path(dst)
    for f in sorted(src.rglob("*")):
        t = dst / f.relative_to(src)
        if f.is_dir():
            t.mkdir(parents=True, exist_ok=True)
            continue
        t.parent.mkdir(parents=True, exist_ok=True)
        with open(f, "rb") as i, open(t, "wb") as o:
            shutil.copyfileobj(i, o, 1 << 20)
            o.flush()
            os.fsync(o.fileno())


def abrir_como_lanzador(root, identidad, exe_dir=None):
    """Abre la unidad con los parámetros sellados en su propio lanzador."""
    sello = ac.read_seal((pathlib.Path(exe_dir or root) / LANZADOR).read_bytes())
    if not sello:
        raise ac.LaunchError("L02", "lanzador sin sello")
    return ac.open_unit(root, sello["pub"], ac.b64d(sello["pepper"]), sello.get("min_seq", 1),
                        prod=sello["perfil"] == "prod", identity=identidad, revoked=sello.get("revocadas", []),
                        launcher_ver="999.0.0")


def leer_todo(read, lic, contenido):
    """Abre cada paquete autorizado y compara su contenido con el inventario de la maestra."""
    for k in lic["keys"]:
        if ac.zip_inventory(read(k["pkg"])) != contenido.get(k["pkg"]):
            raise ac.LaunchError("P01", f"{k['pkg']}: contenido distinto")
    return True


def cmd_unidad(cfg, a):
    perfil, prod = cfg["perfil"], cfg["perfil"] == "prod"
    if a.maestra == "ultima":
        ok = sorted((m for m in maestras_existentes(cfg) if m.get("perfil") == perfil and m.get("estado") == "APROBADA"),
                    key=lambda m: m["fecha"])
        if not ok:
            sys.exit("ERROR: no hay ninguna copia maestra APROBADA para este perfil.")
        a.maestra = str(cfg["salida"] / "maestras" / ok[-1]["id"])
    maestra = pathlib.Path(a.maestra).resolve()
    destino = pathlib.Path(a.destino)
    grados = [int(g) for g in a.grados.split(",") if g.strip()]
    stage = cfg["salida"] / "unidades" / f"pendiente-{ahora()}"
    inf = Informe("Preparación de unidad", stage)
    inf.datos.update(perfil=perfil, maestra=maestra.name, destino=str(destino), cliente=a.cliente,
                     edicion=a.edicion, grados=grados)
    al, st = Almacen(perfil), {}
    print("Preparación de unidad")

    def u01():
        st["comp"] = al.verificar_compilacion(maestra)
        return True, st["comp"]["id"]

    def u02():
        real = inventario_dir(maestra / "usb")
        return real == st["comp"]["archivos"], "" if real == st["comp"]["archivos"] else "archivos alterados"

    def u03():
        st["id"] = ac.usb_identity(destino, allow_fake=not prod)
        bus, modelo, serie = st["id"]
        inf.datos.update(bus=bus, modelo=modelo, serie=serie)
        return bus == "USB" and bool(serie), f"{bus} · {modelo} · {serie or 'SIN SERIE'}"

    def u04():
        if not destino.is_dir():
            return False, "el destino no existe"
        if prod and not ruta_es_raiz(destino):
            return False, "el destino debe ser la raíz de la USB (ej. E:\\)"
        resto = contenido_destino(destino)
        if resto:
            return False, f"la USB no está vacía ({', '.join(resto[:4])})"
        need = sum(f.stat().st_size for f in (maestra / "usb").rglob("*") if f.is_file()) * 1.05 + 2e6
        free = shutil.disk_usage(destino).free
        return free >= need, f"libre {free / 1e6:.0f} MB, necesario {need / 1e6:.0f} MB"

    pasos = [("U01", "Maestra firmada como APROBADA y del mismo perfil", u01),
             ("U02", "Archivos de la maestra sin cambios", u02),
             ("U03", "Bus USB y número de serie legibles", u03),
             ("U04", "USB vacía, en la raíz y con espacio", u04)]
    for c, d, fn in pasos:
        if not inf.prueba(c, d, fn):
            return cerrar_unidad(inf, al, None, stage)

    def u00():
        _, modelo, serie = st["id"]
        st["unidad"], st["lic"] = al.emitir(maestra, modelo, serie, a.cliente, a.edicion, grados,
                                            a.sustituye, a.reemitir)
        inf.datos["unidad"] = st["unidad"]
        return True, st["unidad"]
    if not inf.prueba("U00", "Licencia emitida por la herramienta autorizada", u00):
        return cerrar_unidad(inf, al, None, stage)
    unidad = st["unidad"]
    img = stage / "usb"
    shutil.copytree(maestra / "usb", img)
    (img / "license.afl").write_text(st["lic"], "utf-8")
    contenido = st["comp"]["contenido"]

    def u05():
        pub = al.publicas()
        lic = ac.verify_token(pub["lic"], ac.LIC_CTX, st["lic"], prod)
        _, modelo, serie = st["id"]
        if lic["unit_id"] != unidad or lic["hw"]["fp"] != ac.hw_fp(modelo, serie):
            return False, "número o huella incorrectos"
        st["pkgs_lic"] = [k["pkg"] for k in lic["keys"]]
        return True, f"{len(lic['keys'])} paquetes autorizados"

    def u06():
        lic, man, read = abrir_como_lanzador(img, st["id"])
        return leer_todo(read, lic, contenido), f"{len(st['pkgs_lic'])} paquetes abiertos"

    def u07():
        _, modelo, serie = st["id"]
        try:
            abrir_como_lanzador(img, ("USB", modelo, serie + "-OTRA"))
        except ac.LaunchError as e:
            return e.code == "L01", e.code
        return False, "la licencia abrió en otra USB"

    def u08():
        h = buscar_secretos(img, al.secretos_crudos())
        return (not h, ("secretos en: " + ", ".join(h)) if h else "")

    for c, d, fn in [("U05", "Licencia firmada, número y huella correctos", u05),
                     ("U06", "Apertura completa antes de copiar", u06),
                     ("U07", "La licencia es rechazada en otra USB", u07),
                     ("U08", "Ninguna clave, pepper ni clave de contenido en la imagen", u08)]:
        if not inf.prueba(c, d, fn):
            print("Nada se copió a la USB.")
            return cerrar_unidad(inf, al, unidad, stage)

    print("  Copiando a la USB…")
    try:
        copiar_seguro(img, destino)
        ocultar(destino)
    except OSError as e:
        inf.prueba("U09", "Copia idéntica en la USB", lambda: (False, f"error de escritura: {e}"))
        return cerrar_unidad(inf, al, unidad, stage)

    def u09():
        return inventario_dir(destino) == inventario_dir(img), ""

    def u10():
        ident = ac.usb_identity(destino, allow_fake=not prod)
        lic, man, read = abrir_como_lanzador(destino, ident)
        return leer_todo(read, lic, contenido)

    inf.prueba("U09", "Copia idéntica en la USB", u09)
    inf.prueba("U10", "Apertura completa desde la USB", u10)
    return cerrar_unidad(inf, al, unidad, stage, sustituye=a.sustituye)


def cerrar_unidad(inf, al, unidad, stage, sustituye=None):
    ok = inf.aprobado
    if unidad:
        al.marcar(unidad, "verificada" if ok else "fallida", "" if ok else
                  "; ".join(p["codigo"] for p in inf.pruebas if p["resultado"] == "FALLIDA"))
        if ok and sustituye:
            al.marcar(sustituye, "sustituida", f"reemplazada por {unidad}")
    cierre = "Entregar la unidad." if ok else "NO entregar esta unidad."
    inf.escribir(cierre)
    final = stage
    if unidad:
        final = stage.parent / unidad
        if final.exists():
            final = stage.parent / f"{unidad}-{ahora()}"
        shutil.rmtree(stage / "usb", ignore_errors=True)
        stage.rename(final)
    print(f"\n{'APROBADA' if ok else 'RECHAZADA'}" + (f" · unidad {unidad}" if unidad else "") +
          f"\nInforme: {final / 'informe.md'}\n{cierre}")
    if ok and sustituye:
        print("Exporte las claves públicas y vuelva a sellar el lanzador para la próxima maestra.")
    return ok


# ---------------- Verificación de soporte ----------------

def cmd_verificar(cfg, a):
    destino = pathlib.Path(a.destino)
    inf = Informe("Verificación de USB", cfg["salida"] / "verificaciones" / ahora())
    st = {}

    def v01():
        ident = ac.usb_identity(destino, allow_fake=cfg["perfil"] == "test")
        inf.datos.update(bus=ident[0], modelo=ident[1], serie=ident[2])
        st["lic"], st["man"], st["read"] = abrir_como_lanzador(destino, ident)
        u = st["lic"]["unit_id"]
        inf.datos["unidad"] = u
        reg = Almacen(cfg["perfil"], frase="").unidades().get(u)
        if reg and reg.get("estado") in ("sustituida", "revocada"):
            raise ac.LaunchError("L03", reg["estado"])
        return True, u + (f" · registro: {reg['estado']}" if reg else " · no está en este registro")

    def v02():
        dañados = []
        for p in st["man"]["pkgs"]:
            try:
                st["read"](p)
            except ac.LaunchError as e:
                if e.code != "P02":
                    dañados.append(f"{p} ({e.code})")
        return (not dañados, ", ".join(dañados) or "todos los paquetes abren")

    if inf.prueba("V01", "La licencia corresponde a este hardware", v01):
        inf.prueba("V02", "Paquetes íntegros", v02)
    inf.escribir()
    print(f"\nInforme: {inf.carpeta / 'informe.md'}")
    return inf.aprobado


def main(argv=None):
    p = argparse.ArgumentParser(prog="afdg_publicar")
    p.add_argument("--config", required=True)
    s = p.add_subparsers(dest="cmd", required=True)
    s.add_parser("revisar")
    s.add_parser("maestra")
    u = s.add_parser("unidad")
    u.add_argument("--maestra", required=True, help='Carpeta de la maestra o "ultima"')
    u.add_argument("--destino", required=True)
    u.add_argument("--cliente", required=True, help="Referencia interna (no nombre ni cédula)")
    u.add_argument("--edicion", default="completa")
    u.add_argument("--grados", default="1,2,3,4,5,6")
    g = u.add_mutually_exclusive_group()
    g.add_argument("--sustituye")
    g.add_argument("--reemitir")
    v = s.add_parser("verificar")
    v.add_argument("--destino", required=True)
    a = p.parse_args(argv)
    cfg = cargar_config(a.config)
    try:
        ok = {"revisar": lambda: cmd_revisar(cfg), "maestra": lambda: cmd_maestra(cfg),
              "unidad": lambda: cmd_unidad(cfg, a), "verificar": lambda: cmd_verificar(cfg, a)}[a.cmd]()
    except EmisorError as e:
        print(f"ERROR: {e}")
        ok = False
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
