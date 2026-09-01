from dataclasses import dataclass
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import subprocess
from urllib.parse import parse_qs, urlsplit

import pyrad.client
import pyrad.packet
from pyrad.dictionary import Dictionary


BASE_DIR = Path(__file__).resolve().parent
RADIUS_DICTIONARY = Dictionary(str(BASE_DIR / "dictionary"))

HOST = "0.0.0.0"
PORT = 80
PORTAL_URL = "http://10.10.0.1/"
PORTAL_ORIGIN = PORTAL_URL.rstrip("/")

RADIUS_SERVER = "127.0.0.1"
RADIUS_SECRET = b"testing123"
RADIUS_PORT = 1812
RADIUS_TIMEOUT = 2
RADIUS_RETRIES = 1

CAPTIVE_PROBE_PATHS = {
    "/generate_204",
    "/gen_204",
    "/online",
    "/online/",
    "/hotspot-detect.html",
    "/library/test/success.html",
    "/connecttest.txt",
    "/ncsi.txt",
    "/redirect",
    "/canonical.html",
    "/success.txt",
}

KNOWN_ROLES = {"invitado", "estudiante", "docente"}
ROLE_LABELS = {
    "invitado": "Invitado",
    "estudiante": "Estudiante",
    "docente": "Docente / staff",
    "generico": "Usuario autenticado",
}

# Contenido demostrativo local. Puede editarse sin cambiar la logica RADIUS.
GUEST_TIPS = (
    ("Protege tus credenciales", "No compartas tu contraseña ni la guardes en equipos públicos."),
    ("Verifica los sitios", "Comprueba que las páginas sensibles utilicen HTTPS antes de enviar datos."),
    ("Cierra tu sesión", "Desconecta la red cuando termines de utilizar el acceso de invitado."),
)

STUDENT_QUIZ = {
    "question": "¿Qué protocolo centraliza autenticación, autorización y contabilidad de acceso?",
    "options": (
        ("radius", "RADIUS"),
        ("dns", "DNS"),
        ("dhcp", "DHCP"),
    ),
    "answer": "radius",
    "success": "Correcto. RADIUS permite aplicar políticas y devolver atributos junto con la autorización.",
    "error": "Aún no. La respuesta correcta es RADIUS; el quiz no afecta tu acceso.",
}

STAFF_RESOURCES = {
    "/recursos/aula-virtual": {
        "title": "Aula virtual",
        "summary": "Cursos, materiales y actividades de la semana.",
        "detail": "Este es un recurso interno simulado para demostrar una experiencia diferenciada por rol.",
    },
    "/recursos/repositorio": {
        "title": "Repositorio académico",
        "summary": "Guías, formatos y documentos institucionales.",
        "detail": "En un despliegue real, este enlace apuntaría al repositorio protegido de la institución.",
    },
    "/recursos/soporte": {
        "title": "Mesa de ayuda",
        "summary": "Canal interno para reportar incidentes de tecnología.",
        "detail": "La demostración mantiene todo el contenido dentro del portal y no envía solicitudes externas.",
    },
}


@dataclass(frozen=True)
class AuthResult:
    status: str
    role: str = "generico"
    reply_message: str = ""
    session_timeout: int | None = None

    @property
    def accepted(self):
        return self.status == "accepted"


def _first_attribute(packet, name):
    try:
        value = packet[name]
    except (KeyError, TypeError):
        return None

    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


def _attribute_text(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _attribute_integer(value):
    if value is None:
        return None
    if isinstance(value, bytes):
        if value.isdigit():
            value = value.decode("ascii")
        else:
            value = int.from_bytes(value, byteorder="big")
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def role_from_reply_message(message):
    prefix, separator, value = message.partition(":")
    if separator and prefix.strip().casefold() == "rol":
        role = value.strip().casefold()
        if role in KNOWN_ROLES:
            return role
    return "generico"


def parse_access_accept(response):
    reply_message = _attribute_text(_first_attribute(response, "Reply-Message"))
    session_timeout = _attribute_integer(_first_attribute(response, "Session-Timeout"))
    return AuthResult(
        status="accepted",
        role=role_from_reply_message(reply_message),
        reply_message=reply_message,
        session_timeout=session_timeout,
    )


def autenticar_radius(usuario, clave):
    try:
        cliente = pyrad.client.Client(
            server=RADIUS_SERVER,
            authport=RADIUS_PORT,
            secret=RADIUS_SECRET,
            dict=RADIUS_DICTIONARY,
            timeout=RADIUS_TIMEOUT,
            retries=RADIUS_RETRIES,
        )

        paquete = cliente.CreateAuthPacket(code=pyrad.packet.AccessRequest)
        paquete["User-Name"] = usuario
        paquete["User-Password"] = paquete.PwCrypt(clave)
        respuesta = cliente.SendPacket(paquete)

        print(f"RADIUS respondio con codigo: {respuesta.code}", flush=True)
        if respuesta.code == pyrad.packet.AccessAccept:
            return parse_access_accept(respuesta)
        return AuthResult(status="rejected")
    except Exception as error:
        print(f"Error comunicando con RADIUS: {error}", flush=True)
        return AuthResult(status="unavailable")


def cliente_autorizado(ip_cliente):
    """Verifica si la IP ya tiene reglas de autorizacion activas."""
    filter_ok = subprocess.run(
        ["iptables", "-C", "PORTAL_AUTH", "-s", ip_cliente, "-j", "ACCEPT"],
        capture_output=True,
    ).returncode == 0

    nat_ok = subprocess.run(
        [
            "iptables", "-t", "nat", "-C", "PREROUTING", "-s", ip_cliente,
            "-p", "tcp", "--dport", "80", "-j", "ACCEPT",
        ],
        capture_output=True,
    ).returncode == 0
    return filter_ok and nat_ok


def autorizar_cliente(ip_cliente):
    """Inserta las reglas necesarias para que la IP salga del portal cautivo."""
    if cliente_autorizado(ip_cliente):
        print(f"IP {ip_cliente} ya estaba autorizada, no se duplica regla.")
        return

    subprocess.run(
        ["iptables", "-I", "PORTAL_AUTH", "1", "-s", ip_cliente, "-j", "ACCEPT"],
        check=True,
    )
    subprocess.run(
        [
            "iptables", "-t", "nat", "-I", "PREROUTING", "1", "-s", ip_cliente,
            "-p", "tcp", "--dport", "80", "-j", "ACCEPT",
        ],
        check=True,
    )
    print(f"Reglas de autorizacion insertadas para {ip_cliente}")


def load_template(name):
    return (BASE_DIR / name).read_text(encoding="utf-8")


def render_template(name, **context):
    content = load_template(name)
    placeholder = re.compile(r"\{\{([A-Z_]+)\}\}")
    return placeholder.sub(lambda match: str(context.get(match.group(1), match.group(0))), content)


def render_login(error_message="", username=""):
    error_panel = ""
    if error_message:
        error_panel = (
            '<div class="alert alert-error" role="alert">'
            f"{escape(error_message)}"
            "</div>"
        )
    return render_template(
        "index.html",
        ERROR_PANEL=error_panel,
        PORTAL_URL=escape(PORTAL_URL, quote=True),
        USERNAME=escape(username, quote=True),
    )


def _render_guest_content():
    cards = "".join(
        (
            '<article class="info-card">'
            f"<h3>{escape(title)}</h3><p>{escape(description)}</p>"
            "</article>"
        )
        for title, description in GUEST_TIPS
    )
    return (
        '<section class="content-section" aria-labelledby="security-title">'
        '<div class="section-heading"><p class="eyebrow">Conexión responsable</p>'
        '<h2 id="security-title">Buenas prácticas de seguridad</h2></div>'
        f'<div class="card-grid">{cards}</div></section>'
    )


def _render_student_content():
    answer = escape(STUDENT_QUIZ["answer"], quote=True)
    question = escape(STUDENT_QUIZ["question"])
    success = escape(STUDENT_QUIZ["success"])
    error = escape(STUDENT_QUIZ["error"])
    options = "".join(
        (
            '<label class="quiz-option">'
            f'<input type="radio" name="quiz-answer" value="{escape(value, quote=True)}">'
            f"<span>{escape(label)}</span></label>"
        )
        for value, label in STUDENT_QUIZ["options"]
    )
    return (
        '<section class="content-section quiz-section" aria-labelledby="quiz-title">'
        '<div class="section-heading"><p class="eyebrow">Pregunta de la semana</p>'
        '<h2 id="quiz-title">Micro-quiz opcional</h2></div>'
        f'<form id="quiz-form" class="quiz" data-answer="{answer}">'
        f'<fieldset><legend>{question}</legend>{options}</fieldset>'
        '<button class="button button-secondary" type="submit">Comprobar respuesta</button>'
        '<p id="quiz-empty" class="quiz-feedback" hidden>Selecciona una opción para continuar.</p>'
        f'<p id="quiz-success" class="quiz-feedback success" hidden>{success}</p>'
        f'<p id="quiz-error" class="quiz-feedback error" hidden>{error}</p>'
        '</form></section>'
    )


def _render_staff_content():
    cards = []
    for path, resource in STAFF_RESOURCES.items():
        title = escape(resource["title"])
        summary = escape(resource["summary"])
        cards.append(
            f'<a class="resource-card" href="{escape(path, quote=True)}">'
            '<span class="resource-mark" aria-hidden="true"></span>'
            f'<span><strong>{title}</strong>'
            f'<small>{summary}</small></span>'
            '<span class="resource-arrow" aria-hidden="true">&rarr;</span></a>'
        )
    return (
        '<section class="content-section" aria-labelledby="resources-title">'
        '<div class="section-heading"><p class="eyebrow">Acceso institucional</p>'
        '<h2 id="resources-title">Recursos internos simulados</h2></div>'
        f'<div class="resource-list">{"".join(cards)}</div></section>'
    )


def render_role_content(role):
    if role == "invitado":
        return _render_guest_content()
    if role == "estudiante":
        return _render_student_content()
    if role == "docente":
        return _render_staff_content()
    return (
        '<section class="content-section generic-message">'
        '<p>RADIUS concedió el acceso, pero no envió un rol reconocido. '
        'Se muestra la experiencia general sin recursos privilegiados.</p></section>'
    )


def render_landing(usuario, result):
    timeout = result.session_timeout
    timer_value = str(timeout) if timeout else ""
    timer_text = "Calculando..." if timeout else "Sin límite comunicado"
    reply_message = result.reply_message or "RADIUS no envió un mensaje adicional."
    return render_template(
        "landing.html",
        PORTAL_URL=escape(PORTAL_URL, quote=True),
        USERNAME=escape(usuario),
        ROLE=escape(result.role, quote=True),
        ROLE_LABEL=escape(ROLE_LABELS[result.role]),
        REPLY_MESSAGE=escape(reply_message),
        SESSION_TIMEOUT=timer_value,
        TIMER_TEXT=timer_text,
        ROLE_CONTENT=render_role_content(result.role),
    )


def render_resource(resource):
    return render_template(
        "resource.html",
        PORTAL_URL=escape(PORTAL_URL, quote=True),
        RESOURCE_TITLE=escape(resource["title"]),
        RESOURCE_SUMMARY=escape(resource["summary"]),
        RESOURCE_DETAIL=escape(resource["detail"]),
    )


class PortalHandler(BaseHTTPRequestHandler):
    def _send_bytes(self, status, content, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "Content-Security-Policy",
            f"default-src 'self' {PORTAL_ORIGIN}; "
            f"style-src 'self' {PORTAL_ORIGIN}; "
            f"script-src 'self' {PORTAL_ORIGIN}; "
            f"img-src 'self' {PORTAL_ORIGIN} data:; "
            f"form-action 'self' {PORTAL_ORIGIN}; base-uri 'none'",
        )
        self.end_headers()
        self.wfile.write(content)

    def _send_html(self, status, content):
        self._send_bytes(status, content.encode("utf-8"), "text/html; charset=utf-8")

    def do_GET(self):
        path = urlsplit(self.path).path
        if path in CAPTIVE_PROBE_PATHS:
            self._send_html(200, render_login())
            return
        if path == "/":
            self._send_html(200, render_login())
            return
        if path == "/styles.css":
            self._send_bytes(200, (BASE_DIR / "styles.css").read_bytes(), "text/css; charset=utf-8")
            return
        if path == "/portal.js":
            self._send_bytes(200, (BASE_DIR / "portal.js").read_bytes(), "text/javascript; charset=utf-8")
            return
        if path in STAFF_RESOURCES:
            self._send_html(200, render_resource(STAFF_RESOURCES[path]))
            return
        self.send_error(404, "Recurso no encontrado")

    def do_HEAD(self):
        path = urlsplit(self.path).path
        if path in CAPTIVE_PROBE_PATHS:
            content_length = len(render_login().encode("utf-8"))
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(content_length))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return
        self.send_error(404, "Recurso no encontrado")

    def do_POST(self):
        if urlsplit(self.path).path != "/login":
            self.send_error(404, "Recurso no encontrado")
            return

        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            self._send_html(400, render_login("La solicitud no es válida."))
            return

        body = self.rfile.read(length).decode("utf-8", errors="replace")
        data = parse_qs(body)
        usuario = data.get("usuario", [""])[0].strip()
        clave = data.get("clave", [""])[0]

        print(f"POST recibido: usuario={usuario}", flush=True)
        result = autenticar_radius(usuario, clave)
        if result.status == "rejected":
            print(f"ACCESO RECHAZADO: {usuario}", flush=True)
            self._send_html(401, render_login("Usuario o clave incorrectos.", usuario))
            return
        if result.status == "unavailable":
            self._send_html(
                503,
                render_login("El servicio de autenticación no está disponible. Intenta de nuevo.", usuario),
            )
            return

        ip_cliente = self.client_address[0]
        try:
            autorizar_cliente(ip_cliente)
        except (OSError, subprocess.CalledProcessError) as error:
            print(f"Error aplicando reglas iptables: {error}", flush=True)
            self._send_html(500, render_login("No fue posible habilitar el acceso de red.", usuario))
            return

        print(f"ACCESO ACEPTADO: {usuario} ({ip_cliente}), rol={result.role}", flush=True)
        self._send_html(200, render_landing(usuario, result))


def main():
    server = ThreadingHTTPServer((HOST, PORT), PortalHandler)
    print(f"Portal cautivo escuchando en http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
