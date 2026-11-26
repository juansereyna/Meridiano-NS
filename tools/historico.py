#!/usr/bin/env python3
"""Meridiano · histórico oficial 2022 → hoy (corre en GitHub Actions, sin clave).

Descarga de datos.gov.co las cifras oficiales por departamento y mes, las valida y las
sella con la LLAVE PÚBLICA (igual que los lotes de barrida). Solo el navegador, con la
clave, las abre.

Salidas
  data/historico.enc.json      cifras por indicador → mes → departamento (cifrado)
  data/historico.resumen.json  fuentes, fechas de corte y totales NACIONALES por año
                               (cifras oficiales públicas; sirven para auditar la carga)

Uso:  python3 tools/historico.py [dir_data]
"""
import base64, json, os, sys, time, datetime, urllib.parse, urllib.request
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DESDE = 2022
BASE = "https://www.datos.gov.co"
OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
b64 = lambda b: base64.b64encode(b).decode()

# Código DANE de departamento → clave del mapa (data/colombia.json)
DEP = {"05": "antioquia", "08": "atlantico", "11": "bogota d c", "13": "bolivar", "15": "boyaca", "17": "caldas",
       "18": "caqueta", "19": "cauca", "20": "cesar", "23": "cordoba", "25": "cundinamarca", "27": "choco",
       "41": "huila", "44": "la guajira", "47": "magdalena", "50": "meta", "52": "narino", "54": "norte de santander",
       "63": "quindio", "66": "risaralda", "68": "santander", "70": "sucre", "73": "tolima", "76": "valle del cauca",
       "81": "arauca", "85": "casanare", "86": "putumayo",
       "88": "archipielago de san andres providencia y santa catalina", "91": "amazonas", "94": "guainia",
       "95": "guaviare", "97": "vaupes", "99": "vichada"}

MDN = "Ministerio de Defensa Nacional"
# Fuentes fijas, verificadas a mano en datos.gov.co (noviembre de 2026)
FUENTES = [
    {"id": "secuestro", "nombre": "Secuestro", "unidad": "registros", "ds": "d7zw-hpf4", "entidad": MDN, "modo": "mdn"},
    {"id": "extorsion", "nombre": "Extorsión", "unidad": "casos", "ds": "q2ib-t9am", "entidad": MDN, "modo": "mdn"},
    {"id": "fp_asesinados", "nombre": "Fuerza Pública asesinada", "unidad": "uniformados", "ds": "8rpn-wpty",
     "entidad": MDN, "modo": "mdn", "filtro": "accion='ASESINADO'"},
    {"id": "fp_heridos", "nombre": "Fuerza Pública herida", "unidad": "uniformados", "ds": "8rpn-wpty",
     "entidad": MDN, "modo": "mdn", "filtro": "accion='HERIDO'"},
    {"id": "terrorismo", "nombre": "Terrorismo", "unidad": "casos", "ds": "yi5j-5fe9", "entidad": MDN, "modo": "mdn"},
    {"id": "homicidio", "nombre": "Homicidio", "unidad": "víctimas", "ds": "m8fd-ahd9", "entidad": MDN, "modo": "mdn"},
    {"id": "pirateria", "nombre": "Piratería terrestre", "unidad": "casos", "ds": "sutf-7dyz", "entidad": MDN, "modo": "mdn"},
]
# Exploración informativa: lista los conjuntos del MinDefensa con el mismo formato (no se cargan solos)
ATTR = "Ministerio de Defensa Nacional - MinDefensa"


def get(url, intentos=4):
    for i in range(intentos):
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "Meridiano-NS/1.0"})
            with urllib.request.urlopen(req, timeout=120) as r:
                return json.load(r)
        except Exception as e:
            if i == intentos - 1:
                raise
            print(f"  reintento {i + 1}: {e}")
            time.sleep(5 * (i + 1))


def soql(ds, q):
    return get(f"{BASE}/resource/{ds}.json?" + urllib.parse.urlencode({"$query": q}))


def meta_ds(ds):
    try:
        m = get(f"{BASE}/api/views/{ds}.json")
        return {"titulo": m.get("name"), "actualizado": datetime.datetime.fromtimestamp(
            m.get("rowsUpdatedAt") or m.get("viewLastModified") or 0, datetime.timezone.utc).date().isoformat()}
    except Exception:
        return {}


def dep_de(cod):
    c = "".join(ch for ch in str(cod or "") if ch.isdigit())
    if not c:
        return "sin_depto"
    if len(c) in (1, 4, 7):  # se perdió el cero inicial (p. ej. Antioquia 05)
        c = "0" + c
    return DEP.get(c[:2], "sin_depto")


def cargar_mdn(f):
    w = f"fecha_hecho >= '{DESDE}-01-01T00:00:00'" + (f" AND {f['filtro']}" if f.get("filtro") else "")
    rows = soql(f["ds"], "SELECT cod_depto, date_extract_y(fecha_hecho) AS y, date_extract_m(fecha_hecho) AS m, "
                         f"sum(cantidad) AS n WHERE {w} GROUP BY cod_depto, y, m LIMIT 50000")
    corte = soql(f["ds"], "SELECT max(fecha_hecho) AS mx" + (f" WHERE {f['filtro']}" if f.get("filtro") else ""))[0]["mx"][:10]
    serie = {}
    for r in rows:
        mes = f"{int(r['y'])}-{int(r['m']):02d}"
        k = dep_de(r.get("cod_depto"))
        serie.setdefault(mes, {})
        serie[mes][k] = serie[mes].get(k, 0) + int(float(r["n"]))
    # Control: total nacional calculado por el servidor
    tot = soql(f["ds"], f"SELECT sum(cantidad) AS n WHERE {w}")[0]["n"]
    return serie, corte, int(float(tot))


def cargar_policia(f):
    # fecha_hecho viene como texto dd/mm/aaaa
    hoy = datetime.date.today().year
    serie, corte, filas = {}, "", 0
    for y in range(DESDE, hoy + 1):
        off = 0
        while True:
            rows = soql(f["ds"], f"SELECT codigo_dane, fecha_hecho, cantidad WHERE fecha_hecho like '%/{y}' "
                                 f"ORDER BY :id LIMIT 50000 OFFSET {off}")
            for r in rows:
                d, mth, yy = r["fecha_hecho"].split("/")
                mes = f"{yy}-{int(mth):02d}"
                k = dep_de(r.get("codigo_dane"))
                serie.setdefault(mes, {})
                serie[mes][k] = serie[mes].get(k, 0) + int(float(r.get("cantidad") or 1))
                iso = f"{yy}-{int(mth):02d}-{int(d):02d}"
                corte = max(corte, iso)
            filas += len(rows)
            if len(rows) < 50000:
                break
            off += 50000
    tot = sum(v for m in serie.values() for v in m.values())
    return serie, corte, tot


def descubrir():
    """Lista los conjuntos del MinDefensa con formato fecha_hecho/cod_depto/cantidad (para revisión humana)."""
    vistos, off = [], 0
    while off < 400:
        try:
            res = get("https://api.us.socrata.com/api/catalog/v1?" + urllib.parse.urlencode(
                {"domains": "www.datos.gov.co", "search_context": "www.datos.gov.co", "attribution": ATTR,
                 "only": "dataset", "limit": 100, "offset": off}))
        except Exception as e:
            print(f"  catálogo: {e}")
            break
        rs = res.get("results", [])
        for it in rs:
            r = it.get("resource", {})
            cols = set(r.get("columns_field_name") or [])
            vistos.append({"id": r.get("id"), "nombre": r.get("name"), "columnas": sorted(cols)[:12],
                           "apto": {"fecha_hecho", "cantidad"} <= cols, "actualizado": (r.get("data_updated_at") or "")[:10]})
        if len(rs) < 100:
            break
        off += 100
    return vistos


def main(d="data"):
    pub = serialization.load_der_public_key(base64.b64decode(json.load(open(f"{d}/llave.pub.json"))["spki"]))
    vistos = descubrir()
    extra = []
    out = {"v": 1, "desde": f"{DESDE}-01", "generado": datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=-5))).isoformat(timespec="seconds"),
           "fuentes": [], "series": {}}
    resumen = {"generado": out["generado"], "fuentes": [], "totales": {}, "errores": [], "catalogo": vistos}
    for f in FUENTES + extra:
        print(f"· {f['nombre']} ({f['ds']})")
        try:
            serie, corte, control = (cargar_policia if f["modo"] == "policia" else cargar_mdn)(f)
        except Exception as e:
            print(f"  ERROR: {e}")
            resumen["errores"].append({"id": f["id"], "ds": f["ds"], "error": str(e)[:300]})
            continue
        suma = sum(v for m in serie.values() for v in m.values())
        if suma != control:
            resumen["errores"].append({"id": f["id"], "ds": f["ds"], "error": f"suma por departamento {suma} ≠ total {control}"})
            print(f"  ERROR de control: {suma} ≠ {control}")
            continue
        md = meta_ds(f["ds"])
        info = {"id": f["id"], "nombre": f["nombre"], "unidad": f["unidad"], "entidad": f["entidad"], "dataset": f["ds"],
                "titulo": md.get("titulo") or f.get("titulo_ds"), "url": f"{BASE}/d/{f['ds']}",
                "actualizado": md.get("actualizado"), "corte": corte}
        out["fuentes"].append(info)
        out["series"][f["id"]] = dict(sorted(serie.items()))
        anual = {}
        for mes, deps in serie.items():
            anual[mes[:4]] = anual.get(mes[:4], 0) + sum(deps.values())
        resumen["fuentes"].append(info)
        resumen["totales"][f["id"]] = dict(sorted(anual.items()))
        print(f"  OK · corte {corte} · {anual}")
    if not out["series"]:
        json.dump(resumen, open(f"{d}/historico.resumen.json", "w"), ensure_ascii=False, indent=1)
        sys.exit("Ninguna fuente se pudo cargar.")
    payload = json.dumps(out, ensure_ascii=False, separators=(",", ":")).encode()
    k, iv = AESGCM.generate_key(256), os.urandom(12)
    sellado = {"v": 1, "alg": "RSA-OAEP-256+AES-GCM", "ek": b64(pub.encrypt(k, OAEP)), "iv": b64(iv),
               "ct": b64(AESGCM(k).encrypt(iv, payload, None))}
    json.dump(sellado, open(f"{d}/historico.enc.json", "w"))
    json.dump(resumen, open(f"{d}/historico.resumen.json", "w"), ensure_ascii=False, indent=1)
    print(f"Histórico sellado: {len(out['series'])} indicadores.")


if __name__ == "__main__":
    main(*(sys.argv[1:2] or ["data"]))
