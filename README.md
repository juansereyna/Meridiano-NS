# Meridiano

**Inteligencia de riesgo · North Stonebridge Intelligence & Risk Management S.A.S.**
*Cada alerta, en su lugar.*

Meridiano es la plataforma interna de North Stonebridge para el seguimiento de alertas de seguridad en Colombia: atentados, ataques con drones, secuestros, extorsión, ataques a infraestructura, paros armados, alertas tempranas y ciberataques. Cada alerta enlaza su fuente, se clasifica por tipo y nivel, y cuando hay una empresa afectada incluye un contacto corporativo público y un borrador de correo para aprobación.

> Uso interno · Documento Confidencial

---

## Cómo funciona

| Pieza | Qué hace |
|---|---|
| `index.html` | La plataforma. Pide la clave al abrir, descifra las alertas en el navegador y cierra la sesión tras 15 minutos sin actividad. |
| `data/alertas.enc.json` | Las alertas, **cifradas** (AES-256-GCM, clave derivada con PBKDF2-SHA256, 600.000 iteraciones). Sin la clave es texto ilegible. |
| `tools/sellar.py` | Script para cifrar, descifrar, agregar alertas y rotar la clave. |
| `data/colombia.json` | Fronteras de los 33 departamentos (DANE · MGN 2018, simplificado) para el mapa de presión. Lo genera `tools/mapa.py`. |
| Tarea programada | Dos barridas diarias (6:45 a. m. y 12:45 p. m., Bogotá) que agregan alertas nuevas al archivo cifrado y lo publican aquí. |

**La clave nunca se guarda en este repositorio.** Solo la conocen los socios y la tarea programada.

### Mapa de presión

Colorea cada departamento según las alertas de los últimos 14, 30 o 60 días. Cada alerta suma según su nivel (Crítico 4, Alto 3, Medio 2, Bajo 1) y pesa la mitad cada 14 días de antigüedad; las descartadas no cuentan. Escala: Sin reportes, Bajo, Moderado, Alto y Muy alto. Al pasar el cursor se ve el resumen de la región (tipos de hecho, actores señalados, última alerta); con un clic se filtra la lista por ese departamento. Las alertas nacionales o sin departamento no aparecen en el mapa.

### Comportamiento de la sesión

- La clave se pide **cada vez** que se abre o recarga el enlace. No se recuerda.
- Tras **15 minutos sin actividad** la sesión se cierra y la pantalla se limpia. Un minuto antes aparece un aviso.
- Si se vuelve a una pestaña que estuvo oculta más de 15 minutos, la sesión se cierra.
- La información se refresca sola cada 10 minutos mientras la sesión está abierta.
- **Estado y notas** de cada alerta se guardan cifrados **solo en el equipo** de cada persona. No se comparten entre usuarios.

---

## Activar la publicación (una sola vez)

GitHub Pages en un repositorio **privado** requiere un plan pago de GitHub (Pro, Team o Enterprise). Con una cuenta gratuita, el repositorio debe ser **público**. Esto es seguro para Meridiano porque las alertas están cifradas, pero el código de la página y este README serán visibles.

1. *Settings → General → Danger Zone → Change visibility* (solo si la cuenta es gratuita).
2. *Settings → Pages → Build and deployment → Source: Deploy from a branch → Branch: `main` / `(root)` → Save*.
3. En uno o dos minutos la plataforma queda en `https://juansereyna.github.io/Meridiano-NS/`.

---

## Rotar la clave

Recomendado cada 90 días, y de inmediato si alguien con acceso sale de la empresa.

```bash
pip install cryptography
export MERIDIANO_CLAVE='clave-actual'
export MERIDIANO_CLAVE_NUEVA='clave-nueva-de-al-menos-16-caracteres'
python3 tools/sellar.py rotar data/alertas.enc.json
git add data/alertas.enc.json && git commit -m "Rotación de clave" && git push
```

Después:

1. Actualice la clave en las instrucciones de la tarea programada de Meridiano (si no, la siguiente barrida fallará).
2. Comunique la clave nueva al equipo por un canal seguro, nunca por correo masivo ni en este repositorio.
3. Las sesiones abiertas se cierran solas en el siguiente refresco y piden la clave nueva.
4. El estado y las notas locales guardados con la clave anterior no se recuperan con la nueva.

También puede pedírselo a Claude: *"Rota la clave de Meridiano"*.

## Otros comandos

```bash
export MERIDIANO_CLAVE='...'
python3 tools/sellar.py verificar data/alertas.enc.json          # comprueba la clave y cuenta alertas
python3 tools/sellar.py abrir     data/alertas.enc.json abierto.json   # descifra (no subir abierto.json)
python3 tools/sellar.py agregar   data/alertas.enc.json nuevas.json [meta.json]
```

`agregar` fusiona por `id`: crea las alertas nuevas y actualiza las existentes sin tocar `estado` ni `notas`.

---

## Reglas

- Solo Colombia. Cada alerta enlaza su fuente; lo no confirmado se marca "por confirmar".
- Contactos: únicamente canales corporativos públicos. Nunca datos personales, de víctimas ni de familiares.
- Ningún correo sale sin aprobación de un socio.
- North Stonebridge vende análisis, informes, planes y formación. No presta vigilancia, escolta ni protección física.

North Stonebridge · info@northstonebridge.com · +57 323 612 7516 · northstonebridge.com
