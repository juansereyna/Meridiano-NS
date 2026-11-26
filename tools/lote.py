#!/usr/bin/env python3
"""Meridiano · lotes cifrados con llave pública (la barrida automática NO necesita la clave).

Esquema
  data/alertas.enc.json  base cifrada con la clave (PBKDF2 + AES-GCM), igual que siempre.
  data/llave.pub.json    llave pública RSA-OAEP-3072 (no es secreta).
  data/llave.enc.json    llave privada cifrada con la clave; solo el navegador la abre.
  data/lotes.json        índice: lista de lotes, huellas SHA-256 de ids (para no duplicar) y última barrida.
  data/lotes/*.json      cada barrida: llave AES aleatoria envuelta con la llave pública + datos AES-GCM.

Comandos
  crear-llaves  <dir_data>                       (una vez; usa MERIDIANO_CLAVE)
  rehuellas     <dir_data>                       (recalcula huellas desde la base; usa MERIDIANO_CLAVE)
  existe        <lotes.json> <id> [<id> ...]     (dice qué ids ya existen: actualización vs nueva)
  agregar       <dir_data> <nuevas.json> <meta.json>   (sin clave: sella el lote y actualiza el índice)
"""
import base64, hashlib, json, os, sys, datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ITER = 600_000
OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
b64 = lambda b: base64.b64encode(b).decode()
ub64 = base64.b64decode


def _clave():
    c = os.environ.get("MERIDIANO_CLAVE", "")
    if len(c) < 12:
        sys.exit("Falta MERIDIANO_CLAVE.")
    return c


def _kdf(clave, salt):
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(clave.encode())


def _leer(p, defecto=None):
    if defecto is not None and not os.path.exists(p):
        return defecto
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def _escribir(p, o):
    os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(o, f, ensure_ascii=False, indent=1)
        f.write("\n")


def huella(i):
    return hashlib.sha256(("meridiano:" + str(i)).encode()).hexdigest()[:24]


def ahora():
    return datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=-5))).isoformat(timespec="seconds")


def crear_llaves(d):
    clave = _clave()
    priv = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    der = priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    pub = priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    salt, iv = os.urandom(16), os.urandom(12)
    ct = AESGCM(_kdf(clave, salt)).encrypt(iv, der, None)
    _escribir(f"{d}/llave.enc.json", {"v": 1, "app": "Meridiano", "uso": "llave privada de lotes", "kdf": "PBKDF2-SHA256", "iter": ITER, "salt": b64(salt), "iv": b64(iv), "ct": b64(ct)})
    _escribir(f"{d}/llave.pub.json", {"v": 1, "alg": "RSA-OAEP-3072-SHA256", "spki": b64(pub)})
    print("Llaves creadas.")


def _abrir_base(d):
    env = _leer(f"{d}/alertas.enc.json")
    pt = AESGCM(_kdf(_clave(), ub64(env["salt"]))).decrypt(ub64(env["iv"]), ub64(env["ct"]), None)
    return json.loads(pt)


def rehuellas(d):
    base = _abrir_base(d)
    idx = _leer(f"{d}/lotes.json", {"v": 1, "lotes": [], "huellas": []})
    hs = set(idx.get("huellas", []))
    hs |= {huella(a["id"]) for a in base.get("alertas", [])} | {huella(s["id"]) for s in base.get("senales", [])}
    idx["huellas"] = sorted(hs)
    idx.setdefault("ultima", (base.get("barrida") or {}).get("ultima"))
    _escribir(f"{d}/lotes.json", idx)
    print(f"Huellas: {len(hs)}")


def existe(p, ids):
    hs = set(_leer(p).get("huellas", []))
    for i in ids:
        print(("EXISTE  " if huella(i) in hs else "NUEVA   ") + i)


def agregar(d, nuevas_p, meta_p):
    nuevas = _leer(nuevas_p)
    if isinstance(nuevas, list):
        nuevas = {"alertas": nuevas, "senales": []}
    meta = _leer(meta_p)
    for x in nuevas.get("alertas", []) + nuevas.get("senales", []):
        if "id" not in x:
            sys.exit("Cada alerta y señal necesita 'id'.")
        for k in ("estado", "notas"):
            x.pop(k, None)
    pub = serialization.load_der_public_key(ub64(_leer(f"{d}/llave.pub.json")["spki"]))
    idx = _leer(f"{d}/lotes.json", {"v": 1, "lotes": [], "huellas": []})
    hs = set(idx.get("huellas", []))
    nue = sum(1 for x in nuevas.get("alertas", []) if huella(x["id"]) not in hs)
    act = len(nuevas.get("alertas", [])) - nue
    payload = json.dumps({"alertas": nuevas.get("alertas", []), "senales": nuevas.get("senales", []), "barrida": meta}, ensure_ascii=False).encode()
    k, iv = AESGCM.generate_key(256), os.urandom(12)
    lote = {"v": 1, "alg": "RSA-OAEP-256+AES-GCM", "ek": b64(pub.encrypt(k, OAEP)), "iv": b64(iv), "ct": b64(AESGCM(k).encrypt(iv, payload, None))}
    sello = ahora()
    nombre = "lotes/" + sello[:16].replace(":", "").replace("T", "-") + ".json"
    _escribir(f"{d}/{nombre}", lote)
    hs |= {huella(x["id"]) for x in nuevas.get("alertas", []) + nuevas.get("senales", [])}
    idx["huellas"] = sorted(hs)
    idx["lotes"].append({"archivo": nombre, "sellado": sello, "nuevas": nue, "actualizadas": act, "senales": len(nuevas.get("senales", []))})
    idx["ultima"] = meta.get("ultima", sello)
    _escribir(f"{d}/lotes.json", idx)
    print(f"Lote {nombre}: {nue} nuevas, {act} actualizadas, {len(nuevas.get('senales', []))} señales. Lotes en total: {len(idx['lotes'])}.")
    if len(idx["lotes"]) > 150:
        print("AVISO: más de 150 lotes; conviene consolidarlos en la base.")
    return nombre


if __name__ == "__main__":
    a = sys.argv[1:]
    if not a:
        sys.exit(__doc__)
    c = a[0]
    if c == "crear-llaves" and len(a) == 2: crear_llaves(a[1])
    elif c == "rehuellas" and len(a) == 2: rehuellas(a[1])
    elif c == "existe" and len(a) >= 3: existe(a[1], a[2:])
    elif c == "agregar" and len(a) == 4: agregar(a[1], a[2], a[3])
    else: sys.exit(__doc__)
