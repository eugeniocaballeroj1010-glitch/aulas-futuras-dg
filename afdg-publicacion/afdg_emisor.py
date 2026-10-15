"""Herramienta autorizada: la única que usa claves privadas, pepper y claves de contenido."""
import argparse, getpass, json, os, pathlib, secrets, sys
from datetime import datetime, date
import afdg_crypto as ac

PERFILES = ("test", "prod")
ESTADO = {"emitida": "pendiente", "reemitida": "pendiente", "verificada": "activa", "fallida": "fallida",
          "sustituida": "sustituida", "revocada": "revocada"}
BLOQUEA_HW = {"pendiente", "activa", "sustituida", "revocada"}


class EmisorError(Exception):
    pass


def vault_root():
    return pathlib.Path(os.environ.get("AFDG_VAULT", pathlib.Path.home() / ".afdg-vault"))


def pedir_frase(confirmar=False):
    f = os.environ.get("AFDG_PASSPHRASE")
    if f:
        return f
    f = getpass.getpass("Frase de paso del almacén: ")
    if confirmar and getpass.getpass("Repítala: ") != f:
        raise EmisorError("Las frases no coinciden.")
    return f


def _escribir_atomico(p, data):
    p = pathlib.Path(p)
    tmp = p.with_suffix(p.suffix + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, p)


class Almacen:
    def __init__(self, perfil, frase=None):
        if perfil not in PERFILES:
            raise EmisorError(f"Perfil desconocido: {perfil}")
        self.perfil, self.dir = perfil, vault_root() / perfil
        self._frase, self._cache = frase, {}

    # --- utilidades ---
    @property
    def frase(self):
        if self._frase is None:
            self._frase = pedir_frase()
        return self._frase

    def kid(self, nombre): return f"{self.perfil}-{nombre}-1"

    def existe(self): return (self.dir / "lic.pem").exists()

    def _sk(self, nombre):
        if nombre not in self._cache:
            if not self.existe():
                raise EmisorError(f"No existe el almacén {self.dir}. Ejecute: afdg_emisor.py --perfil {self.perfil} init")
            try:
                self._cache[nombre] = ac.load_private_pem((self.dir / f"{nombre}.pem").read_bytes(), self.frase)
            except (ValueError, TypeError):
                raise EmisorError("Frase de paso incorrecta.")
        return self._cache[nombre]

    def pepper(self):
        try:
            return ac.open_secret((self.dir / "pepper.bin").read_bytes(), self.frase)
        except ValueError as e:
            raise EmisorError(str(e))

    def publicas(self):
        return {"perfil": self.perfil,
                "lic": {self.kid("lic"): ac.raw_public(self._sk("lic"))},
                "man": {self.kid("man"): ac.raw_public(self._sk("man"))},
                "revocadas": self.revocadas()}

    def secretos_crudos(self):
        """Para la prueba M06/U08: bytes que nunca deben aparecer en la USB."""
        out = [ac.raw_private(self._sk("lic")), ac.raw_private(self._sk("man")), self.pepper()]
        for f in (self.dir / "ceks").glob("*.json"):
            for c in json.loads(ac.open_secret(f.read_bytes(), self.frase)).values():
                out.append(ac.b64d(c["cek"]))
        return out

    # --- init ---
    def init(self, salida_publica):
        if self.existe():
            raise EmisorError(f"El almacén {self.dir} ya existe; no se sobrescribe.")
        frase = self._frase or pedir_frase(confirmar=True)
        if len(frase) < 12:
            raise EmisorError("La frase de paso debe tener al menos 12 caracteres.")
        self._frase = frase
        (self.dir / "ceks").mkdir(parents=True, exist_ok=True)
        for n in ("lic", "man"):
            sk, pem = ac.new_private_pem(frase)
            _escribir_atomico(self.dir / f"{n}.pem", pem)
            self._cache[n] = sk
        _escribir_atomico(self.dir / "pepper.bin", ac.seal_secret(secrets.token_bytes(32), frase))
        (self.dir / "registro.jsonl").touch()
        self.exportar_publicas(salida_publica)

    def exportar_publicas(self, salida):
        p = pathlib.Path(salida)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.publicas(), indent=2), "utf-8")
        return p

    # --- firmas ---
    def firmar_manifiesto(self, obj):
        return ac.sign_token(self._sk("man"), self.kid("man"), ac.MAN_CTX, obj)

    def firmar_compilacion(self, data):
        return ac.sign_detached(self._sk("man"), self.kid("man"), ac.BLD_CTX, data)

    def claves_contenido(self, compilacion, paquetes, version):
        dest = self.dir / "ceks" / f"{compilacion}.json"
        if dest.exists():
            raise EmisorError(f"Ya existen claves de contenido para {compilacion}.")
        ceks = {p: {"ver": version, "cek": ac.b64e(secrets.token_bytes(32))} for p in paquetes}
        _escribir_atomico(dest, ac.seal_secret(json.dumps(ceks).encode(), self.frase))
        return {p: ac.b64d(c["cek"]) for p, c in ceks.items()}

    def _ceks(self, compilacion):
        try:
            return json.loads(ac.open_secret((self.dir / "ceks" / f"{compilacion}.json").read_bytes(), self.frase))
        except FileNotFoundError:
            raise EmisorError(f"No hay claves de contenido para la compilación {compilacion}.")

    def verificar_compilacion(self, carpeta):
        carpeta = pathlib.Path(carpeta)
        data = (carpeta / "compilacion.json").read_bytes()
        pub = self.publicas()["man"]
        if not ac.verify_detached(pub, ac.BLD_CTX, data, (carpeta / "compilacion.afb").read_text()):
            raise EmisorError("La firma del registro de compilación no es válida.")
        comp = json.loads(data)
        if comp.get("perfil") != self.perfil:
            raise EmisorError("La maestra pertenece a otro perfil.")
        if comp.get("estado") != "APROBADA":
            raise EmisorError("La maestra está RECHAZADA: no se emiten licencias con ella.")
        return comp

    # --- registro ---
    def _registro_path(self): return self.dir / "registro.jsonl"

    def eventos(self):
        p = self._registro_path()
        if not p.exists():
            return []
        return [json.loads(l) for l in p.read_text("utf-8").splitlines() if l.strip()]

    def agregar_evento(self, **ev):
        ev = {"ts": datetime.now().isoformat(timespec="seconds"), **ev}
        with open(self._registro_path(), "a", encoding="utf-8") as f:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())

    def unidades(self):
        u = {}
        for e in self.eventos():
            d = u.setdefault(e["unidad"], {"unidad": e["unidad"]})
            for k in ("serie", "modelo", "fp", "cliente", "edicion", "grados", "maestra", "reemplaza"):
                if e.get(k) is not None:
                    d[k] = e[k]
            if e["evento"] in ("emitida",):
                d["fecha"] = e["ts"][:10]
            d["estado"] = ESTADO.get(e["evento"], d.get("estado"))
        return u

    def revocadas(self):
        return sorted(k for k, v in self.unidades().items() if v["estado"] in ("sustituida", "revocada"))

    def _nuevo_id(self):
        yy = date.today().strftime("%y")
        pref = ("AFDG" if self.perfil == "prod" else "TEST") + f"-{yy}-"
        n = max([int(k.rsplit("-", 1)[1]) for k in self.unidades() if k.startswith(pref)] or [0])
        return f"{pref}{n + 1:06d}"

    def marcar(self, unidad, evento, detalle=""):
        if unidad not in self.unidades():
            raise EmisorError(f"Unidad desconocida: {unidad}")
        self.agregar_evento(evento=evento, unidad=unidad, detalle=detalle)

    # --- emisión ---
    def emitir(self, maestra, modelo, serie, cliente, edicion, grados, sustituye=None, reemitir=None):
        comp = self.verificar_compilacion(maestra)
        if not serie:
            raise EmisorError("La USB no tiene número de serie.")
        fp = ac.hw_fp(modelo, serie)
        unidades = self.unidades()
        if reemitir:
            prev = unidades.get(reemitir)
            if not prev:
                raise EmisorError(f"Unidad desconocida: {reemitir}")
            if prev.get("fp") != fp:
                raise EmisorError("Para reemitir debe usarse la misma USB física (la serie no coincide).")
            if prev["estado"] in ("sustituida", "revocada"):
                raise EmisorError(f"La unidad {reemitir} está {prev['estado']}.")
            unidad = reemitir
        else:
            for u in unidades.values():
                if u.get("fp") == fp and u["estado"] in BLOQUEA_HW:
                    raise EmisorError(f"Esta USB ya está registrada como {u['unidad']} ({u['estado']}). "
                                      "Use --reemitir con ese número o márquela fallida.")
            if sustituye:
                prev = unidades.get(sustituye)
                if not prev or prev["estado"] != "activa":
                    raise EmisorError(f"Solo se sustituye una unidad activa ({sustituye}).")
            unidad = self._nuevo_id()
        kek = ac.unit_kek(unidad, fp, self.pepper())
        ceks = self._ceks(comp["id"])
        grados = sorted(set(grados))
        keys = []
        for pkg, c in sorted(ceks.items()):
            g = pkg.split("-", 1)[0]
            if g[:1] == "g" and g[1:].isdigit() and int(g[1:]) not in grados:
                continue
            keys.append({"pkg": pkg, "ver": c["ver"],
                         "wrap": ac.wrap_cek(kek, ac.b64d(c["cek"]), unidad, pkg, c["ver"])})
        if not keys:
            raise EmisorError("Ningún paquete corresponde a los grados indicados.")
        lic = {"v": 1, "typ": "afdg-license", "unit_id": unidad, "customer_ref": cliente, "edition": edicion,
               "grades": grados, "hw": {"method": "usb-serial-v1", "fp": fp}, "iat": date.today().isoformat(),
               "exp": None, "max_seq": comp["secuencia"], "replaces": sustituye, "keys": keys}
        token = ac.sign_token(self._sk("lic"), self.kid("lic"), ac.LIC_CTX, lic)
        self.agregar_evento(evento="reemitida" if reemitir else "emitida", unidad=unidad, serie=serie,
                            modelo=modelo, fp=fp, cliente=cliente, edicion=edicion, grados=grados,
                            maestra=comp["id"], reemplaza=sustituye)
        return unidad, token

    # --- lanzador ---
    def sellar_lanzador(self, entrada, salida, min_seq=1):
        exe = pathlib.Path(entrada).read_bytes()
        if exe[:2] != b"MZ":
            raise EmisorError("El archivo de entrada no es un ejecutable de Windows.")
        if ac.read_seal(exe):
            raise EmisorError("El lanzador de entrada ya está sellado; use el lanzador base sin sellar.")
        pub = self.publicas()
        sello = {"v": 1, "perfil": self.perfil, "pub": {"lic": pub["lic"], "man": pub["man"]},
                 "pepper": ac.b64e(self.pepper()), "revocadas": pub["revocadas"], "min_seq": min_seq}
        salida = pathlib.Path(salida)
        salida.parent.mkdir(parents=True, exist_ok=True)
        _escribir_atomico(salida, exe + ac.seal_blob(sello))
        return salida


def comprobar_sello(exe_bytes, publicas):
    """Devuelve lista de problemas del sello frente a las claves públicas del perfil."""
    s = ac.read_seal(exe_bytes)
    if not s:
        return ["el lanzador no está sellado (afdg_emisor.py sellar-lanzador)"]
    prob = []
    if s.get("perfil") != publicas["perfil"]:
        prob.append(f"sellado para el perfil {s.get('perfil')}")
    if s.get("pub", {}).get("lic") != publicas["lic"] or s.get("pub", {}).get("man") != publicas["man"]:
        prob.append("sus claves públicas no coinciden con el almacén")
    faltan = set(publicas["revocadas"]) - set(s.get("revocadas", []))
    if faltan:
        prob.append(f"no incluye revocaciones recientes: {', '.join(sorted(faltan))} (vuelva a sellar)")
    return prob


def main(argv=None):
    p = argparse.ArgumentParser(prog="afdg_emisor", description="Herramienta autorizada de Aulas Futuras DG")
    p.add_argument("--perfil", required=True, choices=PERFILES)
    s = p.add_subparsers(dest="cmd", required=True)
    c = s.add_parser("init", help="Crea el almacén y exporta las claves públicas")
    c.add_argument("--salida-publica", required=True)
    c = s.add_parser("exportar-publicas", help="Exporta claves públicas con la lista de revocación")
    c.add_argument("--salida-publica", required=True)
    s.add_parser("registro", help="Lista unidades")
    c = s.add_parser("marcar", help="Agrega un evento al registro")
    c.add_argument("--unidad", required=True)
    c.add_argument("--evento", required=True, choices=["verificada", "fallida", "revocada"])
    c.add_argument("--detalle", default="")
    c = s.add_parser("sellar-lanzador", help="Inserta claves públicas, pepper y revocaciones en el lanzador")
    c.add_argument("--entrada", required=True, help="Lanzador base sin sellar")
    c.add_argument("--salida", required=True)
    c.add_argument("--min-seq", type=int, default=1)
    a = p.parse_args(argv)
    al = Almacen(a.perfil)
    try:
        if a.cmd == "init":
            al.init(a.salida_publica)
            print(f"Almacén creado en {al.dir}\nClaves públicas: {a.salida_publica}\nRespalde el almacén ahora.")
        elif a.cmd == "exportar-publicas":
            print(f"Exportado: {al.exportar_publicas(a.salida_publica)} (revocadas: {len(al.revocadas())})")
        elif a.cmd == "registro":
            us = al.unidades().values()
            print(f"{'Unidad':<16} {'Estado':<11} {'Serie':<24} {'Cliente':<10} {'Fecha':<10} Reemplaza")
            for u in us:
                print(f"{u['unidad']:<16} {u.get('estado',''):<11} {u.get('serie',''):<24} "
                      f"{u.get('cliente',''):<10} {u.get('fecha',''):<10} {u.get('reemplaza') or ''}")
            print(f"Total: {len(us)}")
        elif a.cmd == "marcar":
            al.marcar(a.unidad, a.evento, a.detalle)
            print(f"{a.unidad}: {a.evento}")
            if a.evento == "revocada":
                print("Vuelva a exportar las claves públicas y a sellar el lanzador para la próxima maestra.")
        elif a.cmd == "sellar-lanzador":
            print(f"Lanzador sellado ({a.perfil}): {al.sellar_lanzador(a.entrada, a.salida, a.min_seq)}")
            if a.perfil == "prod":
                print("Ahora fírmelo con Authenticode (signtool) antes de usarlo en una maestra.")
    except EmisorError as e:
        sys.exit(f"ERROR: {e}")


if __name__ == "__main__":
    main()
