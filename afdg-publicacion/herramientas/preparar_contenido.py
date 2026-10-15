"""Convierte las actividades (HTML de un solo archivo) en paquetes offline para la USB.

Uso:  python herramientas/preparar_contenido.py <carpeta_html> <carpeta_contenido>
  <carpeta_html> contiene <paquete>.html (uno por actividad de ACTIVIDADES, descargados de sus artifacts).
Requiere internet una vez (descarga fuentes y librerías para incluirlas)."""
import json, pathlib, re, sys, urllib.request

# paquete: (artifact de origen, título en el menú, ícono)
ACTIVIDADES = {
    "g1-tareas-en-casa": ("https://claude.ai/artifact/XwZ6mJ31N6zLw855DaPdmN", "Tareas en Casa", "🏡"),
    "g1-fichas-de-trabajo": ("https://claude.ai/artifact/AjSKWvCyV7fmERuqpS9rXd", "Fichas de trabajo", "📄"),
    "g1-aprendo-a-leer": ("https://claude.ai/artifact/Tgspx8ei5pP6AcLWamKaAd", "Aprendo a leer", "🔤"),
    "g1-sumo-y-resto-vertical": ("https://claude.ai/artifact/8LpMscF5TpkvXLswYkfSUE", "Sumo y resto en vertical", "➕"),
    "g1-leo-formo-escribo": ("https://claude.ai/artifact/Q8iE84DYjDa1nbKUN2peKh", "Leo, formo y escribo", "✏️"),
    "g1-sumo-resto-pienso": ("https://claude.ai/artifact/LzNoy8sCoQRbn5uzND8bzU", "Sumo, resto y pienso", "🧮"),
    "todos-los-tres-barquitos": ("https://claude.ai/artifact/PKnNq9MYuSdMSzXSxKV9Xi", "Los Tres Barquitos", "⛵"),
    "g1-ruta-de-1492": ("https://claude.ai/artifact/SpFigyv1z4C1KzYoR7exCd", "La Ruta de 1492", "🧭"),
    "g1-escucha-y-toca": ("https://claude.ai/artifact/KBAs726TkQrBoNVzGNg17s", "Escucha y toca", "👂"),
}
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
LIBS = {"https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.js": "vendor/qrcode.js",
        "https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js": "vendor/jsQR.js"}
_cache = {}


def get(url):
    if url not in _cache:
        req = urllib.request.Request(url.replace("&amp;", "&"), headers={"User-Agent": UA})
        _cache[url] = urllib.request.urlopen(req, timeout=60).read()
    return _cache[url]


def fuentes(css_url, dest):
    css, out = get(css_url).decode(), []
    for subset, b in re.findall(r"/\* ([\w-]+) \*/\s*(@font-face\s*{[^}]+})", css):
        if subset not in ("latin", "latin-ext"):
            continue
        url = re.search(r"url\((https://[^)]+)\)", b).group(1)
        fam = re.search(r"font-family:\s*'([^']+)'", b).group(1)
        name = f"{fam.lower().replace(' ', '')}-{re.search(r'font-weight:\s*(\d+)', b).group(1)}-{subset}.woff2"
        (dest / name).write_bytes(get(url))
        out.append(b.replace(url, name))
    (dest / "fonts.css").write_text("\n".join(out) + "\n", "utf-8")


def preparar(src, out):
    for pkg, (_, titulo, icono) in ACTIVIDADES.items():
        html = (src / f"{pkg}.html").read_text("utf-8")
        d = out / pkg
        (d / "fonts").mkdir(parents=True, exist_ok=True)
        links = re.findall(r"<link[^>]+fonts\.(?:googleapis|gstatic)\.com[^>]*>", html)
        css = [l for l in links if "stylesheet" in l]
        if css:
            fuentes(re.search(r'href="([^"]+)"', css[0]).group(1), d / "fonts")
        for l in links:
            html = html.replace(l, '<link rel="stylesheet" href="fonts/fonts.css">' if css and l == css[0] else "", 1)
        for url, local in LIBS.items():
            if url in html:
                (d / "vendor").mkdir(exist_ok=True)
                (d / local).write_bytes(get(url))
                html = html.replace(url, local)
        # Nunca vender datos reales de estudiantes: lista genérica editable desde "Editar lista"
        html, n = re.subn(r"LISTA0=\[\[.*?\]\]\.map",
                          "LISTA0=[" + ",".join(f"['{i}','ESTUDIANTE']" for i in range(1, 6)) + "].map", html, flags=re.S)
        (d / "index.html").write_text(html, "utf-8")
        (d / "paquete.json").write_text(json.dumps({"titulo": titulo, "icono": icono}, ensure_ascii=False), "utf-8")
        print(f"{pkg}: listo" + (" (lista de estudiantes anonimizada)" if n else ""))


if __name__ == "__main__":
    preparar(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]))
