"""Núcleo criptográfico de Aulas Futuras DG USB.

Implementación de referencia: el lanzador (lanzador/Nucleo.cs) replica exactamente
estos formatos. Cualquier cambio aquí debe reflejarse allá.
"""
import base64, ctypes, hashlib, hmac, io, json, os, pathlib, re, struct, zipfile
from datetime import date
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

LIC_CTX, MAN_CTX, BLD_CTX = b"AFDG-LIC-v1\x00", b"AFDG-MAN-v1\x00", b"AFDG-BLD-v1\x00"
MAGIC, CHUNK = b"AFPK1", 64 * 1024
SEAL_MAGIC, SEAL_OBF = b"AFDGSEAL", b"AFDG-SEAL-OBF-v1"
NAME = re.compile(r"^[a-z0-9-]{1,48}$")
RESERVED = {"portal", "www"}
MSG = {
    "L01": "Esta licencia no corresponde a esta memoria USB.",
    "L02": "La licencia está dañada o fue modificada.",
    "L03": "Esta unidad fue reemplazada o dada de baja.",
    "P01": "Un paquete de contenido está dañado.",
    "P02": "Versión de contenido no autorizada para esta unidad o lanzador.",
}


class LaunchError(Exception):
    def __init__(self, code, detail=""):
        super().__init__(f"[{code}] {MSG[code]}" + (f" ({detail})" if detail else ""))
        self.code, self.detail = code, detail


def b64e(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def b64d(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def sha256(b): return hashlib.sha256(b).hexdigest()


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def check_name(n):
    if not NAME.match(n) or n in RESERVED:
        raise ValueError(f"nombre de paquete inválido: {n!r}")
    return n


def version_tuple(v): return tuple(int(x) for x in str(v).split("."))


# ---------- Tokens firmados: kid.payload.firma (base64url) ----------

def payload_bytes(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()


def sign_token(sk, kid, ctx, obj):
    pb = payload_bytes(obj)
    sig = sk.sign(ctx + kid.encode() + b"." + pb)
    return f"{kid}.{b64e(pb)}.{b64e(sig)}"


def verify_token(pubs, ctx, token, prod):
    """pubs = {kid: clave pública base64url}. Falla cerrado con L02."""
    try:
        kid, p, s = token.strip().split(".")
        if prod and kid.startswith("test-"):
            raise LaunchError("L02", "clave de prueba en producción")
        pk = Ed25519PublicKey.from_public_bytes(b64d(pubs[kid]))
        pb = b64d(p)
        pk.verify(b64d(s), ctx + kid.encode() + b"." + pb)
        obj = json.loads(pb)
        if not isinstance(obj, dict):
            raise ValueError
        return obj
    except LaunchError:
        raise
    except (KeyError, ValueError, InvalidSignature, UnicodeDecodeError, TypeError):
        raise LaunchError("L02")


def sign_detached(sk, kid, ctx, data):
    return f"{kid}.{b64e(sk.sign(ctx + kid.encode() + b'.' + data))}"


def verify_detached(pubs, ctx, data, sig_token):
    try:
        kid, s = sig_token.strip().split(".")
        Ed25519PublicKey.from_public_bytes(b64d(pubs[kid])).verify(b64d(s), ctx + kid.encode() + b"." + data)
        return kid
    except (KeyError, ValueError, InvalidSignature):
        return None


def raw_public(sk):
    return b64e(sk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw))


def raw_private(sk):
    return sk.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())


# ---------- Hardware y claves por unidad ----------

def hw_fp(model, serial):
    return sha256(b"AFDG-HW-v1\x00" + model.encode() + b"\x00" + serial.encode())


def unit_kek(unit, fp, pepper):
    return HKDF(hashes.SHA256(), 32, unit.encode(), b"AFDG-KEK-v1").derive(bytes.fromhex(fp) + pepper)


def _wrap_aad(unit, pkg, ver): return f"{unit}|{pkg}|{ver}".encode()


def wrap_cek(kek, cek, unit, pkg, ver):
    n = os.urandom(12)
    return b64e(n + ChaCha20Poly1305(kek).encrypt(n, cek, _wrap_aad(unit, pkg, ver)))


def unwrap_cek(kek, wrap, unit, pkg, ver):
    w = b64d(wrap)
    return ChaCha20Poly1305(kek).decrypt(w[:12], w[12:], _wrap_aad(unit, pkg, ver))


# ---------- Secretos en reposo (almacén) ----------

def seal_secret(data, passphrase):
    salt, n = os.urandom(16), os.urandom(12)
    k = Scrypt(salt, 32, 2**15, 8, 1).derive(passphrase.encode())
    return b"AFDGV1" + salt + n + ChaCha20Poly1305(k).encrypt(n, data, b"AFDG-VAULT")


def open_secret(blob, passphrase):
    if blob[:6] != b"AFDGV1":
        raise ValueError("formato de secreto desconocido")
    salt, n = blob[6:22], blob[22:34]
    k = Scrypt(salt, 32, 2**15, 8, 1).derive(passphrase.encode())
    try:
        return ChaCha20Poly1305(k).decrypt(n, blob[34:], b"AFDG-VAULT")
    except InvalidTag:
        raise ValueError("frase de paso incorrecta")


# ---------- Paquetes cifrados (*.afpk) ----------

def zip_folder(folder):
    """ZIP determinista de una carpeta; devuelve (bytes, {ruta: sha256})."""
    folder, buf, inv = pathlib.Path(folder), io.BytesIO(), {}
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for f in sorted(p for p in folder.rglob("*") if p.is_file()):
            rel = f.relative_to(folder).as_posix()
            data = f.read_bytes()
            inv[rel] = sha256(data)
            zi = zipfile.ZipInfo(rel, (2026, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(zi, data)
    return buf.getvalue(), inv


def zip_inventory(data):
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        return {n: sha256(z.read(n)) for n in z.namelist() if not n.endswith("/")}


def _header(pkg, ver, prefix):
    meta = json.dumps({"pkg": pkg, "ver": ver}, separators=(",", ":")).encode()
    return MAGIC + struct.pack(">H", len(meta)) + meta + prefix


# Nonce = prefijo(7) + contador(4) + final(1): detecta truncado y reordenamiento
def encrypt_bytes(data, cek, pkg, ver):
    prefix = os.urandom(7)
    header = _header(pkg, ver, prefix)
    aad, aead = hashlib.sha256(header).digest(), ChaCha20Poly1305(cek)
    out = bytearray(header)
    blocks = [data[i:i + CHUNK] for i in range(0, len(data), CHUNK)] or [b""]
    for i, b in enumerate(blocks):
        out += aead.encrypt(prefix + struct.pack(">IB", i, i == len(blocks) - 1), b, aad)
    return bytes(out)


def decrypt_bytes(blob, cek, pkg, ver):
    if blob[:5] != MAGIC or len(blob) < 7:
        raise LaunchError("P01", "cabecera")
    (ml,) = struct.unpack(">H", blob[5:7])
    hlen = 7 + ml + 7
    if len(blob) < hlen + 16:
        raise LaunchError("P01", "cabecera")
    try:
        meta = json.loads(blob[7:7 + ml])
    except ValueError:
        raise LaunchError("P01", "cabecera")
    if meta != {"pkg": pkg, "ver": ver}:
        raise LaunchError("P01", "paquete distinto")
    prefix, aad = blob[7 + ml:hlen], hashlib.sha256(blob[:hlen]).digest()
    aead, body, out = ChaCha20Poly1305(cek), blob[hlen:], bytearray()
    step = CHUNK + 16
    count = max(1, -(-len(body) // step))
    try:
        for i in range(count):
            out += aead.decrypt(prefix + struct.pack(">IB", i, i == count - 1), body[i * step:(i + 1) * step], aad)
    except InvalidTag:
        raise LaunchError("P01", f"bloque {i}")
    return bytes(out)


# ---------- Identidad física de la USB ----------

def _fake_identity(root):
    v = os.environ.get("AFDG_FAKE_USB")
    if not v:
        return None
    if v.lstrip().startswith("{"):
        m = json.loads(v)
        key = str(pathlib.Path(root).resolve())
        v = m.get(key)
        if v is None:
            return ("SATA", "DISCO LOCAL", "SIN-SERIE")
    model, serial = v.split("|", 1)
    return ("USB", model.strip(), serial.strip())


def usb_identity(root, allow_fake=False):
    """Devuelve (bus, modelo, serie) del disco que contiene `root`."""
    if allow_fake:
        f = _fake_identity(root)
        if f:
            return f
    elif os.environ.get("AFDG_FAKE_USB"):
        raise RuntimeError("AFDG_FAKE_USB no está permitido en este perfil")
    if os.name != "nt":
        raise RuntimeError("La lectura de la USB física requiere Windows (o AFDG_FAKE_USB en perfil test)")
    return _win_identity(root)


WS = " \t\r\n\x00"  # mismo recorte que Usb.cs
BUS_NAMES = {1: "SCSI", 2: "ATAPI", 3: "ATA", 7: "USB", 8: "RAID", 10: "SAS", 11: "SATA", 12: "SD", 13: "MMC", 17: "NVME"}


def _win_identity(root):
    from ctypes import wintypes as wt
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.restype = wt.HANDLE
    k32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p, wt.DWORD, wt.DWORD, wt.HANDLE]
    k32.DeviceIoControl.argtypes = [wt.HANDLE, wt.DWORD, ctypes.c_void_p, wt.DWORD, ctypes.c_void_p, wt.DWORD,
                                    ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
    k32.GetVolumePathNameW.argtypes = [wt.LPCWSTR, wt.LPWSTR, wt.DWORD]
    INVALID = wt.HANDLE(-1).value

    def open_dev(path):
        h = k32.CreateFileW(path, 0, 3, None, 3, 0, None)
        if h == INVALID or h is None:
            raise OSError(ctypes.get_last_error(), f"no se pudo abrir {path}")
        return h

    def ioctl(h, code, inbuf, outsize):
        out, ret = ctypes.create_string_buffer(outsize), wt.DWORD()
        ib = ctypes.create_string_buffer(inbuf) if inbuf else None
        ok = k32.DeviceIoControl(h, code, ib, len(inbuf) if inbuf else 0, out, outsize, ctypes.byref(ret), None)
        if not ok:
            raise OSError(ctypes.get_last_error(), f"DeviceIoControl 0x{code:X}")
        return out.raw[:ret.value]

    vol = ctypes.create_unicode_buffer(260)
    if not k32.GetVolumePathNameW(str(pathlib.Path(root).resolve()), vol, 260):
        raise OSError(ctypes.get_last_error(), "GetVolumePathName")
    letter = vol.value.rstrip("\\")
    h = open_dev(f"\\\\.\\{letter}")
    try:
        _, number, _ = struct.unpack("<IIi", ioctl(h, 0x2D1080, None, 12))  # IOCTL_STORAGE_GET_DEVICE_NUMBER
    finally:
        k32.CloseHandle(h)
    h = open_dev(f"\\\\.\\PhysicalDrive{number}")
    try:
        query = struct.pack("<II", 0, 0) + b"\x00" * 4  # StorageDeviceProperty, PropertyStandardQuery
        d = ioctl(h, 0x2D1400, query, 4096)  # IOCTL_STORAGE_QUERY_PROPERTY
    finally:
        k32.CloseHandle(h)
    vend_o, prod_o, _, ser_o, bus = struct.unpack_from("<IIIII", d, 12)
    return (BUS_NAMES.get(bus, f"BUS{bus}"), *identity_strings(d, vend_o, prod_o, ser_o))


def _cstr(d, off):
    if not off or off >= len(d):
        return ""
    end = d.find(b"\x00", off)
    return d[off:end if end >= 0 else len(d)].decode("ascii", "replace").replace("\ufffd", "?").strip(WS)


def identity_strings(d, vend_o, prod_o, ser_o):
    model = f"{_cstr(d, vend_o)} {_cstr(d, prod_o)}".strip(WS)
    return model, _cstr(d, ser_o)


# ---------- Sello del lanzador ----------

def _keystream(n):
    out, i = bytearray(), 0
    while len(out) < n:
        out += hashlib.sha256(SEAL_OBF + struct.pack("<I", i)).digest()
        i += 1
    return bytes(out[:n])


def seal_blob(obj):
    raw = payload_bytes(obj)
    obf = bytes(a ^ b for a, b in zip(raw, _keystream(len(raw))))
    return obf + struct.pack("<I", len(obf)) + SEAL_MAGIC


def read_seal(exe_bytes):
    """Busca el sello en los últimos 2 MiB (la firma Authenticode va después)."""
    start = max(0, len(exe_bytes) - (2 << 20))
    pos = exe_bytes.rfind(SEAL_MAGIC, start)
    if pos < 4:
        return None
    (n,) = struct.unpack("<I", exe_bytes[pos - 4:pos])
    obf = exe_bytes[pos - 4 - n:pos - 4]
    try:
        return json.loads(bytes(a ^ b for a, b in zip(obf, _keystream(n))))
    except ValueError:
        return None


# ---------- Apertura (referencia del lanzador) ----------

def open_unit(root, pub, pepper, min_seq=1, prod=True, identity=None, revoked=(), launcher_ver="1.0.0", today=None):
    """Valida la unidad en el mismo orden que el lanzador.

    Devuelve (licencia, manifiesto, leer(pkg) -> bytes del ZIP)."""
    root = pathlib.Path(root)
    bus, model, serial = identity
    if bus != "USB" or not serial:
        raise LaunchError("L01", "no es una memoria USB con número de serie")
    fp = hw_fp(model, serial)
    try:
        lic_t = (root / "license.afl").read_text("utf-8")
        man_t = (root / "manifest.afm").read_text("utf-8")
    except (OSError, UnicodeDecodeError):
        raise LaunchError("L02", "faltan archivos de licencia")
    lic = verify_token(pub["lic"], LIC_CTX, lic_t, prod)
    try:
        if lic["typ"] != "afdg-license" or lic["v"] != 1:
            raise LaunchError("L02")
        if lic.get("exp") and (today or date.today().isoformat()) > lic["exp"]:
            raise LaunchError("L02", "licencia vencida")
        if not hmac.compare_digest(str(lic["hw"]["fp"]), fp):
            raise LaunchError("L01")
        unit = lic["unit_id"]
        keys = {k["pkg"]: k for k in lic["keys"]}
        max_seq = int(lic["max_seq"])
    except (KeyError, TypeError, ValueError):
        raise LaunchError("L02")
    if unit in set(revoked):
        raise LaunchError("L03")
    man = verify_token(pub["man"], MAN_CTX, man_t, prod)
    try:
        seq, pkgs = int(man["seq"]), man["pkgs"]
        min_launcher = man.get("min_launcher", "0.0.0")
    except (KeyError, TypeError, ValueError):
        raise LaunchError("L02")
    if seq < min_seq or seq > max_seq or version_tuple(min_launcher) > version_tuple(launcher_ver):
        raise LaunchError("P02")
    kek = unit_kek(unit, fp, pepper)

    def read(pkg):
        if not NAME.match(pkg) or pkg not in pkgs or pkg not in keys:
            raise LaunchError("P02", pkg)
        ver = pkgs[pkg]["ver"]
        if keys[pkg]["ver"] != ver:
            raise LaunchError("P02", pkg)
        try:
            blob = (root / "pkgs" / f"{pkg}.afpk").read_bytes()
        except OSError:
            raise LaunchError("P01", pkg)
        if not hmac.compare_digest(sha256(blob), pkgs[pkg]["sha256"]):
            raise LaunchError("P01", pkg)
        try:
            cek = unwrap_cek(kek, keys[pkg]["wrap"], unit, pkg, ver)
        except (InvalidTag, ValueError):
            raise LaunchError("L02", pkg)
        return decrypt_bytes(blob, cek, pkg, ver)

    return lic, man, read


def load_private_pem(data, passphrase):
    return ser.load_pem_private_key(data, passphrase.encode())


def new_private_pem(passphrase):
    sk = Ed25519PrivateKey.generate()
    return sk, sk.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8,
                                ser.BestAvailableEncryption(passphrase.encode()))
