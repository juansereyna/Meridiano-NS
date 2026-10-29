# Meridiano

Herramienta interna de North Stonebridge. Uso restringido.

Los datos de este repositorio están cifrados (AES-256-GCM, clave derivada con PBKDF2-SHA256, 600.000 iteraciones). Sin la clave no se pueden leer. La clave **nunca** se guarda en este repositorio, en la documentación ni en las instrucciones de las tareas automáticas: solo vive en variables de entorno o secretos.

La documentación de operación está en el repositorio documental privado de la empresa, no aquí.

## Reglas de seguridad

- No suba archivos descifrados (`.json` distintos de `data/alertas.enc.json` y `data/colombia.json`, `.txt`, `.env`). El `.gitignore` los bloquea; no lo modifique.
- No escriba la clave en commits, issues, mensajes, documentos ni instrucciones de tareas.
- Rote la clave cada 90 días y de inmediato si se sospecha exposición o si alguien con acceso sale de la empresa. La clave nueva debe tener 24 caracteres o más (`python3 tools/sellar.py generar` propone una).
- Los informes descargados desde la plataforma contienen información descifrada: son confidenciales y no se comparten por canales abiertos.
- Reporte cualquier incidente a los socios de inmediato.
