# Portal cautivo RADIUS por rol

Laboratorio de Comunicaciones II que combina `hostapd`, `dnsmasq`, FreeRADIUS,
`iptables` y un portal HTTP en Python. El servidor RADIUS no solo acepta o
rechaza credenciales: también devuelve atributos que personalizan la landing
del usuario.

## Perfiles de demostración

| Perfil | Usuario | Contraseña | `Reply-Message` | `Session-Timeout` |
| --- | --- | --- | --- | ---: |
| Invitado | `invitado1` | `Invitado123` | `Rol: invitado` | 300 s |
| Estudiante | `estudiante1` | `Estudiante123` | `Rol: estudiante` | 900 s |
| Estudiante | `estudiante2` | `Estudiante456` | `Rol: estudiante` | 900 s |
| Docente | `docente1` | `Docente123` | `Rol: docente` | 1800 s |
| Docente | `docente2` | `Docente456` | `Rol: docente` | 1800 s |

Los usuarios se encuentran en [`authorize`](authorize). La landing de invitado
muestra recomendaciones de seguridad, la de estudiante incluye un micro-quiz y
la de docente enlaza a tres recursos internos simulados. Un `Access-Accept` sin
un rol reconocido recibe una landing general.

## Configuración

1. Instala Python 3.10 o posterior, `pyrad`, FreeRADIUS, `hostapd`, `dnsmasq` e
   `iptables` en el equipo que funcionará como punto de acceso.
2. Copia o integra [`authorize`](authorize) en el archivo `mods-config/files/authorize`
   de FreeRADIUS y reinicia el servicio.
3. Ajusta interfaz, SSID y direccionamiento en [`hostapd.conf`](hostapd.conf) y
   [`portal.conf`](portal.conf).
4. Confirma que exista la cadena `PORTAL_AUTH` y la redirección HTTP del portal
   antes de iniciar la aplicación.
5. Revisa `RADIUS_SERVER`, `RADIUS_SECRET` y `RADIUS_PORT` en
   [`portal-cautivo/portal.py`](portal-cautivo/portal.py). Si cambia la puerta de
   enlace, actualiza también `PORTAL_URL` para que apunte a la IP del portal.
   `RADIUS_TIMEOUT` limita cuánto espera el formulario cuando el servicio no
   responde.

Instala la dependencia de Python y ejecuta el portal desde cualquier directorio:

```bash
python3 -m pip install pyrad
sudo python3 /ruta/al/proyecto/portal-cautivo/portal.py
```

El proceso necesita privilegios para escuchar en el puerto 80 y modificar
`iptables`. La ruta de las plantillas se resuelve con respecto a `portal.py`, no
al directorio actual del proceso.

El servidor reconoce las sondas de portal cautivo habituales de Android, Apple
y Windows, como `/generate_204`, `/hotspot-detect.html` y `/connecttest.txt`.
Antes de autenticar, responde directamente con el formulario y utiliza enlaces
absolutos hacia `http://10.10.0.1/`, de modo que el sistema pueda abrir el portal
y seguir cargando sus recursos locales después de autorizar la IP.

## Atributos RADIUS

El diccionario local declara los atributos estándar utilizados por `pyrad`:

- `Reply-Message` (18, string): contiene `Rol: invitado`, `Rol: estudiante` o
  `Rol: docente`.
- `Session-Timeout` (27, integer): duración comunicada por RADIUS en segundos.

El contador mostrado en la landing es deliberadamente visual. Cuando llega a
cero, la página avisa que la sesión expiró, pero no elimina las reglas de
`iptables` ni interrumpe la conectividad. Esta limitación aparece también en la
propia interfaz para evitar confundir la demostración con una revocación real.

## Contenido editable

Los consejos, la pregunta del quiz y los recursos docentes están agrupados al
inicio de `portal-cautivo/portal.py` en `GUEST_TIPS`, `STUDENT_QUIZ` y
`STAFF_RESOURCES`. Pueden reemplazarse sin modificar la interpretación de los
atributos RADIUS.
