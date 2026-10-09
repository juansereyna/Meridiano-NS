#!/usr/bin/env python3
"""Meridiano · sellado de datos.

Cifra y descifra el archivo de alertas de Meridiano (data/alertas.enc.json).
Formato compatible con la página: PBKDF2-SHA256 (600.000 iteraciones) + AES-256-GCM.

La clave NUNCA se guarda en el repositorio. Se lee de la variable de entorno
MERIDIANO_CLAVE (y MERIDIANO_CLAVE_NUEVA para rotar).

Uso:
  python3 tools/sellar.py abrir   data/alertas.enc.json  salida.json
  python3 tools/sellar.py sellar  entrada.json           data/alertas.enc.json
  python3 tools/sellar.py agregar data/alertas.enc.json  nuevas.json   [meta.json]
  python3 tools/sellar.py rotar   data/alertas.enc.json
  python3 tools/sellar.py verificar data/alertas.enc.json

Requiere: pip install cryptography
"""
import base64
import json
import os
import sys
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ITER = 600_000
BOGOTA = timezone(timedelta(hours=-5))
CAMPOS_SOCIOS = ("estado", "notas")  # nunca se sobrescriben desde una barrida


def _clave(var="MERIDIANO_CLAVE"):
    c = os.environ.get(var, "")
    if len(c) < 12:
        sys.exit(f"Falta {var} (mínimo 12 caracteres).")
    return c


def _derivar(clave, salt, it=ITER):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=it)
    return kdf.derive(clave.encode("utf-8"))


def sellar_obj(obj, clave):
    salt, iv = os.urandom(16), os.urandom(12)
    pt = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ct = AESGCM(_derivar(clave, salt)).encrypt(iv, pt, None)
    b64 = lambda b: base64.b64encode(b).decode()
    return {"v": 1, "app": "Meridiano", "kdf": "PBKDF2-SHA256", "iter": ITER,
            "salt": b64(salt), "iv": b64(iv), "ct": b64(ct)}


def abrir_obj(env, clave):
    d = lambda k: base64.b64decode(env[k])
    try:
        pt = AESGCM(_derivar(clave, d("salt"), env.get("iter", ITER))).decrypt(d("iv"), d("ct"), None)
    except Exception:
        sys.exit("Clave incorrecta o archivo dañado.")
    return json.loads(pt)


def _leer(p):
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def _escribir(p, obj):
    os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)
    os.replace(tmp, p)


def ahora():
    return datetime.now(BOGOTA).isoformat(timespec="seconds")


def agregar(base, nuevas, meta=None):
    """Fusiona alertas por id. Las existentes se actualizan sin tocar estado/notas."""
    por_id = {a["id"]: a for a in base.get("alertas", [])}
    n_nuevas = n_act = 0
    for a in nuevas:
        if "id" not in a:
            sys.exit("Cada alerta nueva necesita un campo 'id'.")
        if a["id"] in por_id:
            viejo = por_id[a["id"]]
            for k, v in a.items():
                if k in CAMPOS_SOCIOS:
                    continue
                if k == "fuentes":
                    urls = {f.get("url") for f in viejo.get("fuentes", [])}
                    viejo.setdefault("fuentes", []).extend(f for f in v if f.get("url") not in urls)
                else:
                    viejo[k] = v
            viejo["actualizado"] = ahora()
            n_act += 1
        else:
            a.setdefault("estado", "Nueva")
            por_id[a["id"]] = a
            n_nuevas += 1
    base["alertas"] = sorted(por_id.values(), key=lambda x: x.get("fecha", ""), reverse=True)
    if meta:
        base["barrida"] = meta
    base["generado"] = ahora()
    return n_nuevas, n_act


def main(a):
    if len(a) < 2:
        sys.exit(__doc__)
    cmd = a[0]
    if cmd == "abrir":
        _escribir(a[2], abrir_obj(_leer(a[1]), _clave()))
        print("Abierto en", a[2])
    elif cmd == "sellar":
        obj = _leer(a[1])
        obj.setdefault("generado", ahora())
        _escribir(a[2], sellar_obj(obj, _clave()))
        print("Sellado en", a[2])
    elif cmd == "agregar":
        clave = _clave()
        base = abrir_obj(_leer(a[1]), clave) if os.path.exists(a[1]) else {"alertas": []}
        nuevas = _leer(a[2])
        if isinstance(nuevas, dict):
            nuevas = nuevas.get("alertas", [])
        meta = _leer(a[3]) if len(a) > 3 else None
        n, u = agregar(base, nuevas, meta)
        _escribir(a[1], sellar_obj(base, clave))
        print(f"{n} nuevas, {u} actualizadas, {len(base['alertas'])} en total.")
    elif cmd == "rotar":
        obj = abrir_obj(_leer(a[1]), _clave())
        nueva = _clave("MERIDIANO_CLAVE_NUEVA")
        obj["clave_rotada"] = ahora()
        _escribir(a[1], sellar_obj(obj, nueva))
        print("Clave rotada. Actualice la clave en la tarea programada y avise al equipo.")
    elif cmd == "verificar":
        obj = abrir_obj(_leer(a[1]), _clave())
        print(f"OK · {len(obj.get('alertas', []))} alertas · generado {obj.get('generado')}")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
