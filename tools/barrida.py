#!/usr/bin/env python3
"""Meridiano · barrida automática en GitHub Actions (esquema de lotes con llave pública).

No usa la clave de Meridiano. Pide a Claude (API de Anthropic, con búsqueda web) las alertas
nuevas, las señales de redes y, cuando toca, el análisis del período; las valida y las sella
como un lote nuevo con tools/lote.py (llave pública). Solo el navegador, con la clave, abre los lotes.

Para no duplicar, guarda una MEMORIA de las alertas de los últimos 45 días en
data/memoria.enc.json, cifrada con una llave derivada del secreto ANTHROPIC_API_KEY
(sin ese secreto no se puede leer). Si la memoria no se puede abrir, sigue con las huellas.

Variables de entorno:
  ANTHROPIC_API_KEY   clave de la API de Anthropic (secreto de GitHub)        [obligatoria]
  MERIDIANO_MODELO    opcional, por defecto claude-sonnet-5-5
  MERIDIANO_BUSQUEDAS opcional, máximo de búsquedas web por barrida (por defecto 30)
"""
import base64, hashlib, json, os, re, subprocess, sys, time, urllib.error, urllib.request
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DATA = "data"
BOGOTA = timezone(timedelta(hours=-5))
TIPOS = ["Atentado con explosivos", "Ataque con drones", "Ataque armado / hostigamiento", "Secuestro",
         "Extorsión", "Ataque a infraestructura", "Paro armado / restricción", "Amenaza / alerta temprana",
         "Ciberataque", "Orden público", "Contexto / informe"]
NIVELES = ["Crítico", "Alto", "Medio", "Bajo"]
REDES = ["X", "Facebook", "Instagram", "TikTok", "YouTube", "Telegram", "WhatsApp (citado por prensa)", "Prensa"]
SERVICIOS = ("A1 Análisis de Contexto Regional, A2 Due Diligence de Contraparte, A3 Monitoreo y Boletines de Riesgo, "
             "B1 Evaluación de Vulnerabilidades, B2 Planes Estratégicos de Riesgo, C1 HEAT / Formación en Entornos "
             "Hostiles, C2 Briefings de Seguridad para Viajes")
OBJETIVOS = ["Estación, base o batallón", "Tropas o patrullas", "Peaje", "Red eléctrica", "Generación de energía",
             "Oleoducto o poliducto", "Petróleo y gas", "Minería o vía férrea", "Vía o puente",
             "Vehículo de transporte o carga", "Comercio", "Salud (hospital o misión médica)",
             "Vivienda o población civil", "Gobierno y funcionarios", "Medios de comunicación",
             "Sistemas informáticos", "Agroindustria"]
MEDIOS = ["Dron con explosivos", "Carro o moto bomba", "Artefacto explosivo", "Cilindros o tatucos",
          "Mina o área preparada", "Arma de fuego", "Incendio o quema", "Toma o retención", "Secuestro",
          "Extorsión", "Ciberataque", "Hurto de combustible"]


def log(*a):
    print(*a, flush=True)


def huella(i):
    # Debe coincidir con tools/lote.py
    return hashlib.sha256(("meridiano:" + str(i)).encode()).hexdigest()[:24]


# ---------- memoria cifrada (solo para evitar duplicados) ----------
def _llave_memoria():
    k = os.environ.get("ANTHROPIC_API_KEY", "")
    return hashlib.sha256(b"meridiano-memoria-v1|" + k.encode()).digest()


def leer_memoria():
    p = f"{DATA}/memoria.enc.json"
    if not os.path.exists(p):
        return []
    try:
        e = json.load(open(p))
        raw = AESGCM(_llave_memoria()).decrypt(base64.b64decode(e["iv"]), base64.b64decode(e["ct"]), None)
        return json.loads(raw)
    except Exception as ex:
        log(f"Aviso: no se pudo abrir la memoria ({ex}); se usan solo las huellas.")
        return []


def guardar_memoria(items, ahora):
    corte = (ahora - timedelta(days=45)).date().isoformat()
    vistos, out = set(), []
    for it in sorted(items, key=lambda x: x.get("fecha", ""), reverse=True):
        if it.get("fecha", "9999") < corte or it["id"] in vistos:
            continue
        vistos.add(it["id"]); out.append(it)
    iv = os.urandom(12)
    ct = AESGCM(_llave_memoria()).encrypt(iv, json.dumps(out[:400], ensure_ascii=False).encode(), None)
    json.dump({"v": 1, "iv": base64.b64encode(iv).decode(), "ct": base64.b64encode(ct).decode()},
              open(f"{DATA}/memoria.enc.json", "w"))


# ---------- análisis del período ----------
def periodos_a_escribir(ahora):
    """Devuelve las claves de período que esta corrida debe escribir (solo en el turno de la mañana)."""
    if ahora.hour >= 10:
        return []
    claves = []
    if ahora.day <= 3:
        prev = (ahora.replace(day=1) - timedelta(days=1))
        claves.append(f"{prev:%Y-%m}")
        if prev.month in (6, 12):
            claves.append(f"{prev.year}-S{1 if prev.month == 6 else 2}")
        if prev.month == 12:
            claves.append(f"{prev.year}")
    if ahora.weekday() == 0:  # lunes: períodos en curso
        claves += [f"{ahora:%Y-%m}", f"{ahora.year}-S{1 if ahora.month <= 6 else 2}", f"{ahora.year}"]
    return list(dict.fromkeys(claves))


def cifras_oficiales(claves):
    try:
        r = json.load(open(f"{DATA}/historico.resumen.json"))
    except Exception:
        return "No disponibles."
    M, T = r.get("mensual", {}), r.get("totales", {})
    nombres = {f["id"]: f"{f['nombre']} ({f['unidad']}, corte {f['corte']})" for f in r.get("fuentes", [])}

    def meses(k):
        if re.fullmatch(r"\d{4}-\d{2}", k):
            return [k]
        y = int(k[:4])
        rng = range(1, 7) if k.endswith("S1") else range(7, 13) if k.endswith("S2") else range(1, 13)
        return [f"{y}-{m:02d}" for m in rng]

    def previo(k):
        if re.fullmatch(r"\d{4}-\d{2}", k):
            y, m = int(k[:4]), int(k[5:])
            return f"{y - 1}-{m:02d}"
        return f"{int(k[:4]) - 1}{k[4:]}"

    lineas = []
    for k in claves:
        lineas.append(f"Período {k} (comparado con {previo(k)}):")
        for i, serie in M.items():
            con = [m for m in meses(k) if m in serie]
            if not con:
                lineas.append(f"  - {nombres.get(i, i)}: sin cifras oficiales todavía para este período")
                continue
            a = sum(serie[m] for m in con)
            b = sum(serie.get(m, 0) for m in meses(previo(k)))
            parcial = len(con) < len(meses(k))
            var = f"{round((a - b) / b * 100)} %" if b and not parcial else "no comparable (período incompleto)" if parcial else "s. d."
            lineas.append(f"  - {nombres.get(i, i)}: {a} frente a {b} ({var}){' · meses con datos: ' + ', '.join(con) if parcial else ''}")
    lineas.append("Totales anuales: " + json.dumps(T, ensure_ascii=False))
    lineas.append("Departamentos con más casos por año: " + json.dumps(r.get("top_deptos", {}), ensure_ascii=False)[:3000])
    return "\n".join(lineas)


# ---------- prompt ----------
def instrucciones(ahora, desde, turno, memoria, periodos):
    lista = "\n".join(f"- {a['id']} | {a.get('fecha','')} | {a.get('departamento','')} | {a.get('tipo','')} | {a.get('titulo','')}"
                      for a in memoria[:150]) or "(sin memoria disponible: revisa con cuidado que no sea un hecho ya publicado)"
    bloque_periodos = ""
    if periodos:
        bloque_periodos = f"""
ANÁLISIS NORTH STONEBRIDGE DEL PERÍODO (OBLIGATORIO en esta corrida): escribe uno por cada clave {json.dumps(periodos)}.
Cifras oficiales del Ministerio de Defensa ya calculadas (úsalas tal cual; el último mes es preliminar por rezago de registro):
{cifras_oficiales(periodos)}
Complementa con hechos del período verificados en prensa y fuentes oficiales. Formato de cada informe:
{{"generado":"<ISO -05:00>", "lectura":"párrafos separados por línea en blanco, cada uno iniciando con [Hecho], [Inferencia] o [Recomendación]", "postura":"una o dos frases institucionales", "matriz":[{{"dimension","implicacion","nivel":"Alto|Medio|Bajo","expuestos"}}], "senales":["3 a 4"], "recomendaciones":["3 a 4, cada una iniciando con [Recomendación] y citando servicios A1–C2 cuando aplique"], "fuentes":[{{"nombre","url"}}]}}
Sé neutral frente a partidos y gobiernos: describe políticas y hechos, sin opinar.
"""
    return f"""Eres el analista senior de North Stonebridge Intelligence & Risk Management, firma colombiana de inteligencia y gestión de riesgos. Vende análisis, informes, planes y formación; NO presta vigilancia, escolta ni protección física.

Fecha y hora actual en Bogotá: {ahora:%Y-%m-%d %H:%M}. Turno: {turno}.
Busca hechos de seguridad en COLOMBIA publicados entre {desde:%Y-%m-%d %H:%M} y ahora (hora de Bogotá).

1) ALERTAS. Búsquedas separadas, con la fecha de hoy{' y la de ayer' if turno == 'mañana' else ''}: atentados con explosivos · ataques con drones · hostigamientos y ataques armados · secuestros (incluye contratistas) · extorsión · ataques a infraestructura (oleoductos, torres de energía, peajes, maquinaria) · paros armados y restricciones de movilidad · alertas tempranas de la Defensoría · ciberataques a empresas o entidades · alteraciones graves de orden público.
Fuentes: Defensoría (SAT), MinDefensa, Ejército, Armada, Policía/GAULA, Fiscalía, Presidencia, ColCERT, gobernaciones, alcaldías; El Tiempo, El Colombiano, El País, Vanguardia, La Opinión, El Heraldo, El Universal, Infobae, Caracol, RCN, Blu, La FM, RTVC, Semana, Cambio; FIP, Indepaz, InSight Crime. Prioriza hechos con una EMPRESA concreta afectada.

2) ESCUCHA SOCIAL (todas las redes abiertas). Haz al menos una búsqueda propia por red: site:x.com, site:facebook.com, site:instagram.com, site:tiktok.com, site:youtube.com, site:t.me, combinadas con "paro armado", "bloqueo", "cierre de vía", "amenaza", "atentado", "toque de queda", "panfleto" y lugares o fechas; y en prensa "denuncian en redes", "video que circula en redes", "audio de WhatsApp". Telegram: solo canales públicos de medios o instituciones; nunca canales de grupos armados. Solo señales con evidencia enlazable; si una red no arroja nada verificable, no inventes y dilo en "notas". Nunca registres datos de particulares (Ley 1581): el emisor es "cuenta institucional X", "medio X" o "usuario particular".
{bloque_periodos}
YA REGISTRADO (no dupliques; si hay novedades de uno, usa su MISMO id e incluye solo los campos que cambian y la fuente nueva):
{lista}

REGLAS
- Nunca inventes datos. Fecha, lugar y hechos deben salir de la fuente; lo no confirmado va como "por confirmar". En los resúmenes marca [Hecho] e [Inferencia]. Parafrasea.
- Solo Colombia y dentro de la ventana. Si no hay nada nuevo, listas vacías.
- tipo: uno de {json.dumps(TIPOS, ensure_ascii=False)}. nivel: uno de {json.dumps(NIVELES, ensure_ascii=False)}.
- relevancia: "Prospecto" solo si la fuente nombra una empresa afectada; si no, "Contexto". servicios: elige entre {SERVICIOS}.
- impacto (solo si la fuente da cifras): {{"mil_m","mil_h","pol_m","pol_h","civ_m","civ_h","sec","fsec","parcial"}} con la cifra mínima confirmada; no cuentes integrantes de grupos armados abatidos.
- objetivo (uno si aplica): {json.dumps(OBJETIVOS, ensure_ascii=False)}. medio (uno si aplica): {json.dumps(MEDIOS, ensure_ascii=False)}.
- id: "AAAA-MM-DD-municipio-tema-corto", minúsculas, sin tildes, con guiones.
- Contacto (solo Prospecto): solo canales corporativos públicos verificados en la fuente o en el sitio oficial; nunca inventes URL. PROHIBIDO: datos personales, correos personales, canales de denuncias, control interno, notificaciones judiciales o PQRS. Sin canal claro, explícalo en contacto.nota.
- Borrador (solo Prospecto): sobrio, sin alarmismo: solidaridad; la firma en una frase; lectura breve de contexto sin costo; servicio relacionado sin precios; pedir que lo dirijan a seguridad o riesgos; firma "[Nombre] · North Stonebridge · +57 323 612 7516 · info@northstonebridge.com · northstonebridge.com". Si hubo muertos o hay secuestrados, en contacto.nota: "Esperar al menos 7 días o a la resolución del caso antes de enviar."

FORMATO DE RESPUESTA: al terminar, responde SOLO con un bloque <json>...</json>:
{{"alertas":[{{"id","fecha":"AAAA-MM-DD","fecha_exacta":true,"tipo","nivel","titulo","departamento","municipio","actor","afectado","empresa","sector","relevancia","verificacion","resumen","servicios","fuentes":[{{"nombre":"Medio · fecha","url","oficial":false}}],"contacto":{{}},"impacto":{{}},"objetivo","medio","borrador":{{"asunto","cuerpo"}}}}],
 "senales":[{{"id","fecha","tema","titulo","departamento","municipio","redes":{json.dumps(REDES, ensure_ascii=False)},"emisor","estado":"Rumor|En verificación|Confirmado|Desmentido","intensidad":"Baja|Media|Alta","resumen","verificacion","evidencias":[{{"nombre","url","tipo"}}]}}],
 "informes":{{}},
 "fuentes_revisadas":["..."], "notas":"limitaciones de esta barrida, incluidas las redes sin resultados"}}
Omite campos vacíos. No incluyas "estado" ni "notas" dentro de las alertas."""


# ---------- API ----------
def llamar_claude(prompt, modelo, max_busquedas):
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        sys.exit("Falta el secreto ANTHROPIC_API_KEY.")
    mensajes = [{"role": "user", "content": prompt}]
    tools = [{"type": "web_search_20250305", "name": "web_search", "max_uses": max_busquedas,
              "user_location": {"type": "approximate", "country": "CO", "timezone": "America/Bogota"}}]
    texto = ""
    for vuelta in range(8):
        cuerpo = json.dumps({"model": modelo, "max_tokens": 24000, "messages": mensajes, "tools": tools}).encode()
        req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=cuerpo, method="POST", headers={
            "x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
        for intento in range(3):
            try:
                with urllib.request.urlopen(req, timeout=900) as r:
                    resp = json.load(r)
                break
            except urllib.error.HTTPError as e:
                detalle = e.read().decode(errors="replace")[:500]
                if e.code in (429, 500, 502, 503, 529) and intento < 2:
                    log(f"API {e.code}, reintento en {30 * (intento + 1)} s…"); time.sleep(30 * (intento + 1)); continue
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


# ---------- validación ----------
def validar(alertas, senales, informes, existe):
    ok_a, ok_s, ok_i, malas = [], [], {}, []
    for a in alertas:
        p = []
        if not re.fullmatch(r"[a-z0-9-]{8,120}", a.get("id", "")): p.append("id")
        if not existe(a.get("id", "")):
            if a.get("tipo") not in TIPOS: p.append("tipo")
            if a.get("nivel") not in NIVELES: p.append("nivel")
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", a.get("fecha", "")): p.append("fecha")
            if not a.get("titulo"): p.append("titulo")
        if not any(str(f.get("url", "")).startswith("https://") for f in a.get("fuentes", [])): p.append("fuente")
        if p: malas.append((a.get("id", "?"), p)); continue
        a.pop("estado", None); a.pop("notas", None)
        if a.get("relevancia") != "Prospecto": a.pop("borrador", None)
        ok_a.append(a)
    for s in senales:
        if not re.fullmatch(r"[a-z0-9-]{8,120}", s.get("id", "")) or not any(
                str(e.get("url", "")).startswith("https://") for e in s.get("evidencias", [])):
            malas.append((s.get("id", "?"), ["señal sin id o evidencia"])); continue
        s["redes"] = [r for r in s.get("redes", []) if r in REDES] or ["Prensa"]
        ok_s.append(s)
    for k, an in (informes or {}).items():
        if re.fullmatch(r"\d{4}(-\d{2}|-S[12])?", k) and an.get("lectura"):
            an.setdefault("generado", datetime.now(BOGOTA).isoformat(timespec="seconds")); ok_i[k] = an
        else:
            malas.append((k, ["informe incompleto"]))
    return ok_a, ok_s, ok_i, malas


def main():
    modelo = os.environ.get("MERIDIANO_MODELO") or "claude-sonnet-5-5"
    max_busquedas = int(os.environ.get("MERIDIANO_BUSQUEDAS") or 30)
    idx = json.load(open(f"{DATA}/lotes.json"))
    huellas = set(idx.get("huellas", []))
    existe = lambda i: huella(i) in huellas
    memoria = leer_memoria()
    ahora = datetime.now(BOGOTA)
    turno = "mañana" if ahora.hour < 10 else "mediodía"
    try:
        desde = datetime.fromisoformat(idx.get("ultima")) - timedelta(hours=6)
        if ahora - desde > timedelta(hours=36):
            desde = max(datetime.fromisoformat(idx.get("ultima")), ahora - timedelta(days=7))
    except Exception:
        desde = ahora - timedelta(hours=36)
    periodos = periodos_a_escribir(ahora)
    log(f"Barrida {turno} · desde {desde:%Y-%m-%d %H:%M} · memoria {len(memoria)} · huellas {len(huellas)} · "
        f"informes {periodos or 'ninguno'} · modelo {modelo}")

    salida = extraer(llamar_claude(instrucciones(ahora, desde, turno, memoria, periodos), modelo, max_busquedas))
    alertas, senales, informes, malas = validar(salida.get("alertas", []), salida.get("senales", []),
                                                salida.get("informes", {}), existe)
    for i, p in malas:
        log(f"Descartado: {i} ({', '.join(p)})")
    hoy = ahora.isoformat(timespec="seconds")
    for x in alertas + senales:
        x.setdefault("detectada", hoy)
    for a in alertas:
        a.setdefault("turno", turno)
    nuevas = [a for a in alertas if not existe(a["id"])]
    pros = [a for a in nuevas if a.get("relevancia") == "Prospecto"]
    redes = sorted({r for s in senales for r in s.get("redes", [])})
    meta = {"ultima": hoy, "turno": turno, "modelo": modelo,
            "resumen": f"Turno {turno}: {len(nuevas)} alertas nuevas, {len(alertas) - len(nuevas)} actualizadas, "
                       f"{len(pros)} con empresa identificada · Escucha social: {len(senales)} señales"
                       + (f" (redes: {', '.join(redes)})" if redes else "")
                       + (f" · Análisis: {', '.join(informes)}" if informes else ""),
            "fuentes_revisadas": salida.get("fuentes_revisadas", [])[:40]}
    if salida.get("notas"):
        meta["notas"] = str(salida["notas"])[:800]
    json.dump({"alertas": alertas, "senales": senales, "informes": informes}, open("/tmp/nuevas.json", "w"), ensure_ascii=False)
    json.dump(meta, open("/tmp/meta.json", "w"), ensure_ascii=False)
    r = subprocess.run([sys.executable, "tools/lote.py", "agregar", DATA, "/tmp/nuevas.json", "/tmp/meta.json"],
                       capture_output=True, text=True)
    log(r.stdout.strip(), r.stderr.strip())
    if r.returncode:
        sys.exit("No se pudo sellar el lote.")
    memoria += [{k: a.get(k, "") for k in ("id", "fecha", "departamento", "tipo", "titulo")} for a in nuevas]
    guardar_memoria(memoria, ahora)
    os.remove("/tmp/nuevas.json")
    log(meta["resumen"])
    altas = [a for a in nuevas if a.get("nivel") in ("Crítico", "Alto")]
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"resumen={meta['resumen']}\n")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(f"### Meridiano · {meta['resumen']}\n\n"
                    + "".join(f"- **{a['nivel']}** · {a.get('departamento','')} · {a['titulo']}\n" for a in altas)
                    + (f"\n> {meta['notas']}\n" if meta.get("notas") else ""))


if __name__ == "__main__":
    main()
