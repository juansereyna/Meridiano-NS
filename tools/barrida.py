#!/usr/bin/env python3
"""Meridiano · barrida automática (se ejecuta en GitHub Actions).

1. Abre data/alertas.enc.json con MERIDIANO_CLAVE.
2. Pide a Claude (API de Anthropic, con búsqueda web) las alertas de seguridad
   de Colombia publicadas desde la última barrida.
3. Valida el resultado, lo fusiona sin tocar estado/notas y vuelve a sellar.

Variables de entorno:
  MERIDIANO_CLAVE     clave de Meridiano (secreto de GitHub)
  ANTHROPIC_API_KEY   clave de la API de Anthropic (secreto de GitHub)
  MERIDIANO_MODELO    opcional, por defecto claude-sonnet-5-5
  MERIDIANO_BUSQUEDAS opcional, máximo de búsquedas web por barrida (por defecto 25)
"""
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(__file__))
import sellar  # noqa: E402

ARCHIVO = "data/alertas.enc.json"
BOGOTA = timezone(timedelta(hours=-5))
TIPOS = ["Atentado con explosivos", "Ataque con drones", "Ataque armado / hostigamiento", "Secuestro",
         "Extorsión", "Ataque a infraestructura", "Paro armado / restricción", "Amenaza / alerta temprana",
         "Ciberataque", "Orden público", "Contexto / informe"]
NIVELES = ["Crítico", "Alto", "Medio", "Bajo"]
SERVICIOS = ("A1 Análisis de Contexto Regional, A2 Due Diligence de Contraparte, A3 Monitoreo y Boletines de Riesgo, "
             "B1 Evaluación de Vulnerabilidades, B2 Planes Estratégicos de Riesgo, C1 HEAT / Formación en Entornos "
             "Hostiles, C2 Briefings de Seguridad para Viajes")


def log(*a):
    print(*a, flush=True)


def instrucciones(ahora, desde, turno, existentes):
    lista = "\n".join(f"- {a['id']} | {a.get('fecha','')} | {a.get('departamento','')} | {a.get('tipo','')} | {a.get('titulo','')}"
                      for a in existentes[:80]) or "(ninguna)"
    return f"""Eres el analista senior de North Stonebridge Intelligence & Risk Management, firma colombiana de inteligencia y gestión de riesgos. Vende análisis, informes, planes y formación; NO presta vigilancia, escolta ni protección física.

Fecha y hora actual en Bogotá: {ahora:%Y-%m-%d %H:%M}. Turno: {turno}.
Busca alertas de seguridad en COLOMBIA publicadas entre {desde:%Y-%m-%d %H:%M} y ahora (hora de Bogotá).

QUÉ BUSCAR (búsquedas separadas, con la fecha de hoy{' y la de ayer' if turno == 'mañana' else ''}):
atentados con explosivos · ataques con drones · hostigamientos y ataques armados · secuestros (incluye trabajadores y contratistas) · extorsión (comercio, transporte, contratistas, quema de maquinaria) · ataques a infraestructura (oleoductos, poliductos, torres de energía, vías férreas, maquinaria vial) · paros armados y restricciones de movilidad · alertas tempranas de la Defensoría del Pueblo · ciberataques a empresas o entidades · alteraciones graves de orden público.
Prioriza fuentes oficiales (Defensoría, MinDefensa, Ejército, Armada, Policía/GAULA, Fiscalía, ColCERT, gobernaciones, alcaldías) y prensa reconocida (El Tiempo, El Colombiano, El País, Vanguardia, La Opinión, El Heraldo, El Universal, Infobae, Caracol, RCN, Blu, La FM, RTVC, Semana, Cambio). Prioriza hechos donde una EMPRESA concreta (o su contratista) resulte afectada.
{'En este turno da prioridad a lo ocurrido en la noche y la madrugada.' if turno == 'mañana' else 'En este turno da prioridad a lo publicado en la mañana y a novedades de hechos ya registrados (víctimas, atribución, liberaciones, comunicados oficiales).'}

ALERTAS YA REGISTRADAS (no las dupliques; si hay novedades de una de ellas, usa su MISMO id e incluye solo los campos que cambian y la fuente nueva):
{lista}

REGLAS
- Nunca inventes datos. Fecha, lugar y hechos deben salir de la fuente; lo que no esté confirmado va como "por confirmar". En el resumen marca [Hecho] e [Inferencia]. Parafrasea, no copies párrafos.
- Solo hechos ocurridos en Colombia y publicados en la ventana indicada. Si no encuentras nada nuevo, devuelve una lista vacía.
- tipo: exactamente uno de {json.dumps(TIPOS, ensure_ascii=False)}.
- nivel: "Crítico" (muertos, secuestro masivo, paralización de operación crítica), "Alto", "Medio" o "Bajo".
- relevancia: "Prospecto" solo si la fuente nombra una empresa afectada; si no, "Contexto".
- servicios: elige entre {SERVICIOS}.
- departamento: nombre oficial del departamento (por ejemplo "Norte de Santander", "Bogotá, D.C."); usa "Nacional" si no aplica uno.
- id: "AAAA-MM-DD-municipio-tema-corto", minúsculas, sin tildes, con guiones.
- Contacto (solo Prospecto): únicamente canales corporativos públicos (página oficial de contacto, correo institucional general, conmutador, página corporativa de LinkedIn), con origen y fecha de consulta. PROHIBIDO: datos personales de empleados, víctimas o familiares; correos personales; canales de denuncias, control interno, notificaciones judiciales o quejas. Si no hay canal claro, explícalo en contacto.nota.
- Borrador (solo Prospecto): sobrio y respetuoso, sin alarmismo ni oportunismo: (1) reconocimiento breve y solidaridad; (2) presentación de la firma en una frase; (3) ofrecimiento sin costo de una lectura breve de contexto del territorio; (4) servicio relacionado en una frase, sin precios; (5) pedir que lo dirijan al área de seguridad o riesgos; (6) firma "[Nombre] · North Stonebridge · +57 323 612 7516 · info@northstonebridge.com · northstonebridge.com". Si hubo muertos o hay secuestrados en cautiverio, añade en contacto.nota: "Esperar al menos 7 días o a la resolución del caso antes de enviar."

FORMATO DE RESPUESTA
Al terminar de investigar, responde SOLO con un bloque <json>...</json> que contenga:
{{"alertas": [ {{"id", "fecha":"AAAA-MM-DD", "fecha_exacta":true, "tipo", "nivel", "titulo", "departamento", "municipio", "actor", "afectado", "empresa", "sector", "relevancia", "verificacion", "resumen", "servicios", "fuentes":[{{"nombre":"Medio · fecha", "url", "oficial":false}}], "contacto":{{"correo","telefono","web","linkedin","cargo_objetivo","fuente","nota"}}, "borrador":{{"asunto","cuerpo"}} }} ],
 "fuentes_revisadas": ["..."], "notas": "fallos o limitaciones de esta barrida, si los hubo"}}
Omite los campos vacíos. No incluyas "estado" ni "notas" dentro de las alertas."""


def llamar_claude(prompt, modelo, max_busquedas):
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        sys.exit("Falta el secreto ANTHROPIC_API_KEY.")
    mensajes = [{"role": "user", "content": prompt}]
    tools = [{"type": "web_search_20250305", "name": "web_search", "max_uses": max_busquedas,
              "user_location": {"type": "approximate", "country": "CO", "timezone": "America/Bogota"}}]
    texto = ""
    for vuelta in range(6):
        cuerpo = json.dumps({"model": modelo, "max_tokens": 16000, "messages": mensajes, "tools": tools}).encode()
        req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=cuerpo, method="POST", headers={
            "x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
        for intento in range(3):
            try:
                with urllib.request.urlopen(req, timeout=600) as r:
                    resp = json.load(r)
                break
            except urllib.error.HTTPError as e:
                detalle = e.read().decode(errors="replace")[:500]
                if e.code in (429, 500, 502, 503, 529) and intento < 2:
                    log(f"API {e.code}, reintento en {20 * (intento + 1)} s…"); time.sleep(20 * (intento + 1)); continue
                sys.exit(f"Error de la API de Anthropic ({e.code}): {detalle}")
        uso = resp.get("usage", {})
        log(f"Vuelta {vuelta + 1}: stop={resp.get('stop_reason')} · tokens in={uso.get('input_tokens')} out={uso.get('output_tokens')} · "
            f"búsquedas={uso.get('server_tool_use', {}).get('web_search_requests')}")
        texto += "".join(b.get("text", "") for b in resp.get("content", []) if b.get("type") == "text")
        if resp.get("stop_reason") == "pause_turn":
            mensajes.append({"role": "assistant", "content": resp["content"]})
            continue
        break
    return texto


def extraer(texto):
    m = re.search(r"<json>\s*(.*?)\s*</json>", texto, re.S) or re.search(r"(\{\s*\"alertas\".*\})", texto, re.S)
    if not m:
        sys.exit("La respuesta no trajo el bloque JSON esperado:\n" + texto[-1500:])
    try:
        return json.loads(m.group(1))
    except json.JSONDecodeError as e:
        sys.exit(f"JSON inválido en la respuesta: {e}\n{m.group(1)[:1500]}")


def validar(alertas, ids_existentes):
    buenas, descartadas = [], []
    for a in alertas:
        nueva = a.get("id") not in ids_existentes
        problemas = []
        if not re.fullmatch(r"[a-z0-9-]{8,120}", a.get("id", "")):
            problemas.append("id")
        if nueva:
            if a.get("tipo") not in TIPOS: problemas.append("tipo")
            if a.get("nivel") not in NIVELES: problemas.append("nivel")
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", a.get("fecha", "")): problemas.append("fecha")
            if not a.get("titulo"): problemas.append("titulo")
            if not any(str(f.get("url", "")).startswith("http") for f in a.get("fuentes", [])): problemas.append("fuente")
        if problemas:
            descartadas.append((a.get("id", "?"), problemas)); continue
        a.pop("estado", None); a.pop("notas", None)
        if a.get("relevancia") != "Prospecto":
            a.pop("borrador", None)
        buenas.append(a)
    return buenas, descartadas


def main():
    clave = sellar._clave()
    modelo = os.environ.get("MERIDIANO_MODELO") or "claude-sonnet-5-5"
    max_busquedas = int(os.environ.get("MERIDIANO_BUSQUEDAS") or 25)
    base = sellar.abrir_obj(sellar._leer(ARCHIVO), clave)
    existentes = base.get("alertas", [])
    ahora = datetime.now(BOGOTA)
    turno = "mañana" if ahora.hour < 10 else "mediodía"
    try:
        ultima = datetime.fromisoformat(base.get("barrida", {}).get("ultima"))
        desde = ultima - timedelta(hours=6)
        if ahora - desde > timedelta(hours=36):
            desde = ahora - timedelta(hours=36)
    except Exception:
        desde = ahora - timedelta(hours=36)
    log(f"Barrida {turno} · desde {desde:%Y-%m-%d %H:%M} · {len(existentes)} alertas registradas · modelo {modelo}")

    texto = llamar_claude(instrucciones(ahora, desde, turno, existentes), modelo, max_busquedas)
    salida = extraer(texto)
    ids = {a["id"] for a in existentes}
    alertas, descartadas = validar(salida.get("alertas", []), ids)
    for i, p in descartadas:
        log(f"Descartada por datos incompletos: {i} ({', '.join(p)})")
    hoy = ahora.isoformat(timespec="seconds")
    for a in alertas:
        a.setdefault("detectada", hoy); a.setdefault("turno", turno)
    n_nuevas = sum(1 for a in alertas if a["id"] not in ids)
    n_act = len(alertas) - n_nuevas
    n_pros = sum(1 for a in alertas if a.get("relevancia") == "Prospecto" and a["id"] not in ids)
    meta = {"ultima": hoy, "turno": turno, "modelo": modelo,
            "resumen": f"Turno {turno}: {n_nuevas} nuevas, {n_act} actualizadas, {n_pros} con empresa identificada",
            "fuentes_revisadas": salida.get("fuentes_revisadas", [])[:30]}
    if salida.get("notas"):
        meta["notas"] = str(salida["notas"])[:500]
    n, u = sellar.agregar(base, alertas, meta)
    sellar._escribir(ARCHIVO, sellar.sellar_obj(base, clave))
    sellar.abrir_obj(sellar._leer(ARCHIVO), clave)  # verificación
    resumen = f"{meta['resumen']} · total {len(base['alertas'])}"
    log(resumen)
    altas = [a for a in alertas if a.get("nivel") in ("Crítico", "Alto") and a["id"] not in ids]
    for a in altas:
        log(f"  · [{a['nivel']}] {a.get('departamento','')}: {a['titulo']}")
    gh = os.environ.get("GITHUB_OUTPUT")
    if gh:
        with open(gh, "a") as f:
            f.write(f"resumen={resumen}\nnuevas={n}\n")
    paso = os.environ.get("GITHUB_STEP_SUMMARY")
    if paso:
        with open(paso, "a", encoding="utf-8") as f:
            f.write(f"### Meridiano · {resumen}\n\n" + "".join(f"- **{a['nivel']}** · {a.get('departamento','')} · {a['titulo']}\n" for a in altas)
                    + (f"\n> {meta['notas']}\n" if meta.get("notas") else ""))


if __name__ == "__main__":
    main()
