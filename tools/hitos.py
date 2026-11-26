#!/usr/bin/env python3
"""Meridiano · hechos clave (hitos) históricos, sellados con la LLAVE PÚBLICA.

Cada entrega se guarda como un paquete nuevo (data/hitos/*.json) y se anota en
data/hitos.idx.json. No hace falta la clave para agregar: el navegador los abre y
los fusiona por id (un paquete posterior corrige a uno anterior con el mismo id).

Formato de entrada: {"hitos": [{id, fecha AAAA-MM-DD, titulo, departamento, municipio,
                     tipo, actor, resumen, fuentes: [{nombre, url}]}]}

Uso:  python3 tools/hitos.py agregar data hitos.json
"""
import base64, datetime, hashlib, json, os, sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
b64 = lambda b: base64.b64encode(b).decode()
OBLIG = ("id", "fecha", "titulo", "resumen", "fuentes")


def agregar(d, entrada):
    hitos = json.load(open(entrada))["hitos"]
    for h in hitos:
        falta = [k for k in OBLIG if not h.get(k)]
        if falta:
            sys.exit(f"{h.get('id', '?')}: faltan {falta}")
        datetime.date.fromisoformat(h["fecha"])
        if not all(str(f.get("url", "")).startswith("https://") for f in h["fuentes"]):
            sys.exit(f"{h['id']}: cada fuente necesita un enlace https")
    pub = serialization.load_der_public_key(base64.b64decode(json.load(open(f"{d}/llave.pub.json"))["spki"]))
    payload = json.dumps({"hitos": hitos}, ensure_ascii=False).encode()
    k, iv = AESGCM.generate_key(256), os.urandom(12)
    paquete = {"v": 1, "alg": "RSA-OAEP-256+AES-GCM", "ek": b64(pub.encrypt(k, OAEP)), "iv": b64(iv),
               "ct": b64(AESGCM(k).encrypt(iv, payload, None))}
    sello = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=-5))).isoformat(timespec="seconds")
    nombre = "hitos/" + sello[:16].replace(":", "").replace("T", "-") + ".json"
    os.makedirs(f"{d}/hitos", exist_ok=True)
    json.dump(paquete, open(f"{d}/{nombre}", "w"))
    p = f"{d}/hitos.idx.json"
    idx = json.load(open(p)) if os.path.exists(p) else {"v": 1, "paquetes": []}
    idx["paquetes"].append({"archivo": nombre, "sellado": sello, "n": len(hitos),
                            "huellas": [hashlib.sha256(h["id"].encode()).hexdigest()[:24] for h in hitos]})
    json.dump(idx, open(p, "w"), ensure_ascii=False, indent=1)
    print(f"Paquete {nombre}: {len(hitos)} hitos. Paquetes en total: {len(idx['paquetes'])}.")


if __name__ == "__main__":
    a = sys.argv[1:]
    if len(a) == 3 and a[0] == "agregar":
        agregar(a[1], a[2])
    else:
        sys.exit(__doc__)
