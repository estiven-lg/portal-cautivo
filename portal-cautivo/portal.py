from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

from pyrad.client import Client
from pyrad.dictionary import Dictionary
from pathlib import Path
import pyrad.packet

from pyrad.dictionary import Dictionary
from pathlib import Path
from pyrad.dictionary import Dictionary

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
import subprocess
import pyrad.client
import pyrad.dictionary

BASE_DIR = Path(__file__).resolve().parent
RADIUS_DICTIONARY = Dictionary(str(BASE_DIR / "dictionary"))

HOST = "0.0.0.0"
PORT = 80

RADIUS_SERVER = "127.0.0.1"
RADIUS_SECRET = b"testing123"
RADIUS_PORT = 1812


def cliente_autorizado(ip_cliente):
    """Verifica si la IP ya tiene reglas de autorización activas."""
    filter_ok = subprocess.run(
        ["iptables", "-C", "PORTAL_AUTH", "-s", ip_cliente, "-j", "ACCEPT"],
        capture_output=True
    ).returncode == 0

    nat_ok = subprocess.run(
        ["iptables", "-t", "nat", "-C", "PREROUTING",
         "-s", ip_cliente, "-p", "tcp", "--dport", "80", "-j", "ACCEPT"],
        capture_output=True
    ).returncode == 0

    return filter_ok and nat_ok


def autorizar_cliente(ip_cliente):
    """Inserta las reglas necesarias para que la IP salga del portal cautivo."""
    if cliente_autorizado(ip_cliente):
        print(f"IP {ip_cliente} ya estaba autorizada, no se duplica regla.")
        return

    # 1. Permite el forward general (ya lo tenías, pero con -I en vez de -A
    #    para que quede al inicio de la cadena, por consistencia)
    subprocess.run([
        "iptables", "-I", "PORTAL_AUTH", "1",
        "-s", ip_cliente,
        "-j", "ACCEPT"
    ], check=True)

    # 2. Evita que el tráfico HTTP de esta IP sea redirigido al portal
    #    Debe ir ANTES del REDIRECT en PREROUTING
    subprocess.run([
        "iptables", "-t", "nat", "-I", "PREROUTING", "1",
        "-s", ip_cliente,
        "-p", "tcp", "--dport", "80",
        "-j", "ACCEPT"
    ], check=True)

    print(f"Reglas de autorización insertadas para {ip_cliente}")

def autenticar_radius(usuario, clave):
    try:
        cliente = pyrad.client.Client(
            server=RADIUS_SERVER,
            secret=RADIUS_SECRET,
            dict=RADIUS_DICTIONARY
        )

        cliente.authport = RADIUS_PORT

        paquete = cliente.CreateAuthPacket(
            code=pyrad.packet.AccessRequest
        )

        paquete["User-Name"] = usuario
        paquete["User-Password"] = paquete.PwCrypt(clave)

        respuesta = cliente.SendPacket(paquete)

        print(f"RADIUS respondió con código: {respuesta.code}")

        return respuesta.code == pyrad.packet.AccessAccept

    except Exception as e:
        print(f"Error comunicando con RADIUS: {e}")
        return False

class PortalHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        try:
            with open("index.html", "rb") as f:
                content = f.read()

            self.send_response(200)
            self.send_header(
                "Content-Type",
                "text/html; charset=utf-8"
            )
            self.send_header(
                "Content-Length",
                str(len(content))
            )
            self.end_headers()

            self.wfile.write(content)

        except Exception as e:
            self.send_error(500, str(e))

    def do_POST(self):
        if self.path != "/login":
            self.send_error(404)
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8")
        data = parse_qs(body)

        usuario = data.get("usuario", [""])[0]
        clave = data.get("clave", [""])[0]

        print(f"POST recibido: usuario={usuario}")

        if autenticar_radius(usuario, clave):
            ip_cliente = self.client_address[0]

            try:
                autorizar_cliente(ip_cliente)
                print(f"ACCESO ACEPTADO: {usuario} ({ip_cliente})")

                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(
                    b"<html><body>Login exitoso. "
                    b"<a href='http://example.com'>Continuar</a></body></html>"
                )
            except subprocess.CalledProcessError as e:
                print(f"Error aplicando reglas iptables: {e}")
                self.send_response(500)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"<html><body>Error interno al autorizar</body></html>")
        else:
            print(f"ACCESO RECHAZADO: {usuario}")
            self.send_response(401)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body>Usuario o clave incorrectos</body></html>")
server = HTTPServer(
    (HOST, PORT),
    PortalHandler
)

print(
    f"Portal cautivo escuchando en "
    f"http://{HOST}:{PORT}"
)

server.serve_forever()

