#!/usr/bin/env python3
"""Genera data/colombia.json (trazos SVG de los departamentos) a partir del
GeoJSON del DANE · Marco Geoestadístico Nacional 2018.

Uso: python3 tools/mapa.py dptos.geojson data/colombia.json
"""
import json, math, sys, unicodedata

W = 560          # ancho del mapa continental en unidades SVG
LAT0 = 4.5       # latitud de referencia para corregir la escala este-oeste
TOL = 0.9        # tolerancia de simplificación (unidades SVG)
SAI = "88"       # San Andrés y Providencia: va en un recuadro aparte


def norm(s):
    s = unicodedata.normalize("NFD", s).encode("ascii", "ignore").decode().lower()
    return " ".join(s.replace(",", " ").replace(".", " ").split())


def rings(geom):
    if geom["type"] == "Polygon":
        return [geom["coordinates"]]
    return geom["coordinates"]


def rdp(pts, tol):
    if len(pts) < 4:
        return pts
    keep = [False] * len(pts); keep[0] = keep[-1] = True
    stack = [(0, len(pts) - 1)]
    while stack:
        a, b = stack.pop()
        (x1, y1), (x2, y2) = pts[a], pts[b]
        dx, dy = x2 - x1, y2 - y1; L = math.hypot(dx, dy) or 1e-9
        best, idx = 0, None
        for i in range(a + 1, b):
            x, y = pts[i]
            d = abs(dy * x - dx * y + x2 * y1 - y2 * x1) / L
            if d > best:
                best, idx = d, i
        if idx is not None and best > tol:
            keep[idx] = True; stack += [(a, idx), (idx, b)]
    return [p for p, k in zip(pts, keep) if k]


def main(src, out):
    feats = json.load(open(src, encoding="utf-8"))["features"]
    k = math.cos(math.radians(LAT0))
    proj = lambda lon, lat: (lon * k, -lat)
    main_pts = [proj(*c) for f in feats if f["properties"]["DPTO_CCDGO"] != SAI
                for poly in rings(f["geometry"]) for ring in poly for c in ring]
    minx = min(p[0] for p in main_pts); maxx = max(p[0] for p in main_pts)
    miny = min(p[1] for p in main_pts); maxy = max(p[1] for p in main_pts)
    s = W / (maxx - minx); H = round((maxy - miny) * s)
    sai_pts = [proj(*c) for f in feats if f["properties"]["DPTO_CCDGO"] == SAI
               for poly in rings(f["geometry"]) for ring in poly for c in ring]
    # Recuadro de San Andrés: esquina superior izquierda, 70x90 unidades
    bx0, by0, bw, bh = 12, 12, 70, 90
    sx0 = min(p[0] for p in sai_pts); sx1 = max(p[0] for p in sai_pts)
    sy0 = min(p[1] for p in sai_pts); sy1 = max(p[1] for p in sai_pts)
    ss = min((bw - 16) / (sx1 - sx0), (bh - 22) / (sy1 - sy0))

    out_feats = []
    for f in feats:
        p = f["properties"]; code = p["DPTO_CCDGO"]
        if code == SAI:
            tf = lambda x, y: (bx0 + 8 + (x - sx0) * ss, by0 + 14 + (y - sy0) * ss)
            tol = 0.2
        else:
            tf = lambda x, y: ((x - minx) * s, (y - miny) * s)
            tol = TOL
        parts, area_pts = [], []
        for poly in rings(f["geometry"]):
            for ring in poly:
                raw = [tf(*proj(*c)) for c in ring]
                pts = rdp(raw, tol)
                if len(pts) < 4:
                    pts = raw
                if len(pts) < 4:
                    continue
                area_pts += pts
                parts.append("M" + "L".join(f"{x:.1f},{y:.1f}" for x, y in pts[:-1]) + "Z")
        cx = sum(x for x, _ in area_pts) / len(area_pts)
        cy = sum(y for _, y in area_pts) / len(area_pts)
        out_feats.append({"code": code, "name": p["DPTO_CNMBR"].title().replace(" De ", " de ").replace(" Del ", " del ").replace(" Y ", " y ").replace("D.C.", "D. C."),
                          "key": norm(p["DPTO_CNMBR"]), "d": "".join(parts), "cx": round(cx, 1), "cy": round(cy, 1)})
    doc = {"fuente": "DANE · Marco Geoestadístico Nacional 2018 (simplificado)",
           "w": W, "h": H, "inset": [bx0, by0, bw, bh, SAI], "dptos": sorted(out_feats, key=lambda x: x["code"])}
    json.dump(doc, open(out, "w", encoding="utf-8"), ensure_ascii=False, separators=(",", ":"))
    print(f"{len(out_feats)} departamentos · {W}x{H} · {len(json.dumps(doc))//1024} KB")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
