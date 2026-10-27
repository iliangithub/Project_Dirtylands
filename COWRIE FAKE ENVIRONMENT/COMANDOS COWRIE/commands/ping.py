# SPDX-License-Identifier: BSD-3-Clause
"""
ping emulado.

EL DE COWRIE ESTABA MAL DE CUATRO FORMAS DISTINTAS, y todas se ven en una
sesion de treinta segundos:

  1. LAS ESTADISTICAS ESTABAN ESCRITAS A FUEGO. Cualquier ping terminaba en
     "rtt min/avg/max/mdev = 48.264/50.352/52.441/2.100 ms", el mismo numero
     siempre, y ni siquiera cuadraba con los tiempos de arriba: los paquetes
     iban de 40.4 a 45.2 y el resumen decia un minimo de 48.264. El "time
     907ms" tambien era fijo, con seis paquetes o con uno ---y seis paquetes
     no caben en 907 ms, porque van de segundo en segundo---.

  2. localhost TARDABA 50 ms Y CON ttl=50. La vuelta por loopback son
     centesimas de milisegundo y el TTL es 64, porque el paquete no sale de
     la maquina. Es de las cosas mas faciles de comprobar que hay.

  3. CUALQUIER NOMBRE RESOLVIA. "ping help" contestaba desde
     101.127.139.141, y "ping a" desde 12.193.117.185 ---inventadas, y
     distintas en cada intento---. Un ping de verdad dice "Name or service
     not known".

  4. A UNA IP LITERAL LE PONIA EL PARENTESIS. Escribia "64 bytes from
     8.8.8.8 (8.8.8.8)", que es el formato de cuando se le da un NOMBRE. Con
     una IP va sola.

Y ademas "ping --help", "ping -help" y "ping" a secas contestaban cosas que
no dice ninguna version de iputils.

TODO LO DE AQUI ESTA MEDIDO contra iputils 20240117 con LC_ALL=C, no
recordado: los mensajes, los codigos de salida, el flujo por el que sale cada
cosa y el formato de los tiempos.

    $ ping                    -> ping: usage error: Destination address required   (1)
    $ ping nombremalo         -> ping: nombremalo: Name or service not known       (2)
    $ ping -h                 -> el uso, POR STDERR                                (2)
    $ ping --help             -> ping: invalid option -- '-' y luego el uso        (2)

EL FORMATO DEL TIEMPO no es "%.1f" ni "%.3f": iputils cambia de precision
segun la magnitud, y por eso en la misma pantalla conviven "time=0.084 ms" y
"time=118 ms". Con microsegundos: >=100000 entero, >=10000 un decimal,
>=1000 dos, y por debajo tres. El resumen, en cambio, SIEMPRE lleva tres.

LOS NOMBRES SE RESUELVEN CONTRA EL /etc/hosts DEL SENUELO, no contra una
tabla escrita aqui: asi "ping localhost" y "cat /etc/hosts" no pueden
contradecirse. Lo que no este ahi y tenga un punto se resuelve a una IP
publica inventada pero ESTABLE ---la misma para el mismo nombre siempre,
porque una IP distinta en cada intento es justo lo que delataba al anterior---
y lo que no tenga punto no resuelve, como en cualquier maquina.
"""

from __future__ import annotations

import hashlib
import random
import time

from twisted.internet import reactor

from cowrie.shell.command import HoneyPotCommand

commands = {}

USO = """
Usage
  ping [options] <destination>

Options:
  <destination>      DNS name or IP address
  -3                 RTT precision (do not round up the result time)
  -a                 use audible ping
  -A                 use adaptive ping
  -B                 sticky source address
  -c <count>         stop after <count> replies
  -C                 call connect() syscall on socket creation
  -D                 print timestamps
  -d                 use SO_DEBUG socket option
  -e <identifier>    define identifier for ping session, default is random for
                     SOCK_RAW and kernel defined for SOCK_DGRAM
                     Imply using SOCK_RAW (for IPv4 only for identifier 0)
  -f                 flood ping
  -h                 print help and exit
  -H                 force reverse DNS name resolution (useful for numeric
                     destinations or for -f), override -n
  -I <interface>     either interface name or address
  -i <interval>      seconds between sending each packet
  -L                 suppress loopback of multicast packets
  -l <preload>       send <preload> number of packages while waiting replies
  -m <mark>          tag the packets going out
  -M <pmtud opt>     define path MTU discovery, can be one of <do|dont|want|probe>
  -n                 no reverse DNS name resolution, override -H
  -O                 report outstanding replies
  -p <pattern>       contents of padding byte
  -q                 quiet output
  -Q <tclass>        use quality of service <tclass> bits
  -s <size>          use <size> as number of data bytes to be sent
  -S <size>          use <size> as SO_SNDBUF socket option value
  -t <ttl>           define time to live
  -U                 print user-to-user latency
  -v                 verbose output
  -V                 print version and exit
  -w <deadline>      reply wait <deadline> in seconds
  -W <timeout>       time to wait for response

IPv4 options:
  -4                 use IPv4
  -b                 allow pinging broadcast
  -R                 record route
  -T <timestamp>     define timestamp, can be one of <tsonly|tsandaddr|tsprespec>

IPv6 options:
  -6                 use IPv6
  -F <flowlabel>     define flow label, default is random
  -N <nodeinfo opt>  use IPv6 node info query, try <help> as argument

For more details see ping(8).
"""

# Opciones de una letra que se llevan un valor detras. Sin esta lista el valor
# se tomaria por el destino.
CON_VALOR = set("cieIlmMpQsStwWTNF")
# Las que existen y no llevan valor. Cualquier otra letra es invalida, y hay
# que decirlo como lo dice iputils.
# El "3" es de trixie (iputils 20240905): "-3  RTT precision". No estaba
# en el iputils anterior.
SIN_VALOR = set("aABCDdfHLnOqUv46bR3")


def _semilla(texto: str) -> random.Random:
    """Un generador ESTABLE para un destino dado.

    La misma IP da siempre el mismo TTL y la misma latencia base. El anterior
    sorteaba en cada intento, asi que "ping a" contestaba desde una IP
    distinta cada vez ---y eso no lo hace ninguna red---.
    """
    h = hashlib.md5(texto.encode("utf-8", "replace")).hexdigest()
    return random.Random(int(h[:16], 16))


def formatea_tiempo(ms: float) -> str:
    """La precision que usa iputils, que cambia con la magnitud.

    Por eso en una misma pantalla salen "time=0.084 ms" y "time=118 ms".
    """
    us = ms * 1000.0
    if us >= 100000:
        return "%d" % round(ms)
    if us >= 10000:
        return "%.1f" % ms
    if us >= 1000:
        return "%.2f" % ms
    return "%.3f" % ms


def resuelve_nombre(nombre: str, fs) -> str | None:
    """El nombre, a IP. None si no resuelve.

    ESTA FUNCION LA COMPARTEN VARIOS COMANDOS ---ping y psql a dia de hoy--- y
    por eso esta aqui suelta y no dentro de la clase. Si cada uno resolviera a
    su manera, un `ping db-internal.ignislabs.dev` contestaria desde una IP y un
    `psql -h db-internal.ignislabs.dev` diria que ese nombre no existe. Dos
    respuestas distintas a la misma pregunta es lo que delata a un senuelo, y
    ademas es justo lo que prueba un atacante que ya sospecha.

    El /etc/hosts que se lee es el del PROPIO senuelo, por lo mismo: si alguien
    hace un `cat /etc/hosts` y luego un ping, las dos cosas tienen que cuadrar.
    """
    if es_ip(nombre):
        return nombre
    # EL /etc/hosts DEL PROPIO SENUELO, para que no puedan contradecirse.
    try:
        crudo = fs.file_contents("/etc/hosts")
        texto = crudo.decode("utf-8", "replace")
    except Exception:                                      # noqa: BLE001
        texto = "127.0.0.1\tlocalhost\n"
    for linea in texto.splitlines():
        linea = linea.split("#", 1)[0].strip()
        if not linea:
            continue
        campos = linea.split()
        if len(campos) >= 2 and nombre in campos[1:] and es_ip(campos[0]):
            return campos[0]
    # Un nombre sin punto no es un dominio: en una maquina de verdad no
    # resuelve, y ahi es donde el anterior se inventaba una IP para
    # cosas como "ping help".
    if "." not in nombre.strip("."):
        return None
    r = _semilla(nombre)
    while True:
        ip = "%d.%d.%d.%d" % (r.randint(1, 223), r.randint(0, 255),
                              r.randint(0, 255), r.randint(1, 254))
        if not ip.startswith(("10.", "127.", "169.254.", "172.", "192.168.")):
            return ip


def es_ip(texto: str) -> bool:
    partes = texto.split(".")
    if len(partes) != 4:
        return False
    for p in partes:
        if not p.isdigit() or not 0 <= int(p) <= 255:
            return False
    return True


class Command_ping(HoneyPotCommand):
    def start(self) -> None:
        self.enviados = 0
        self.tiempos: list[float] = []
        self.limite: int | None = None
        self.programado = None
        self.inicio = time.time()

        destino = None
        args = list(self.args)
        i = 0
        while i < len(args):
            a = args[i]
            if a.startswith("--"):
                # Medido: "ping --help" da esto, no un mensaje sobre --help.
                self.errorWrite("ping: invalid option -- '-'\n")
                self.uso()
                return
            if a.startswith("-") and len(a) > 1:
                for pos, letra in enumerate(a[1:]):
                    if letra == "h":
                        self.uso()
                        return
                    if letra == "V":
                        self.version()
                        return
                    if letra in CON_VALOR:
                        resto = a[2 + pos:]
                        if resto:
                            valor = resto
                        else:
                            i += 1
                            valor = args[i] if i < len(args) else ""
                        if letra == "c":
                            try:
                                self.limite = max(0, int(valor))
                            except ValueError:
                                self.errorWrite(
                                    "ping: bad number of packets to transmit.\n")
                                self.exit_code = 2
                                self.exit()
                                return
                        break
                    if letra not in SIN_VALOR:
                        self.errorWrite("ping: invalid option -- '%s'\n" % letra)
                        self.uso()
                        return
                i += 1
                continue
            if destino is None:
                destino = a
            i += 1

        if destino is None:
            # DOS, no uno. Medido contra el iputils 20240905 de trixie; el
            # 20240117 de la maquina de desarrollo daba 1 y lo cambiaron entre
            # medias. Es el ejemplo de por que estos numeros hay que sacarlos
            # del sistema que se emula y no del que se tiene a mano.
            self.errorWrite("ping: usage error: Destination address required\n")
            self.exit_code = 2
            self.exit()
            return

        ip = self.resuelve(destino)
        if ip is None:
            self.errorWrite("ping: %s: Name or service not known\n" % destino)
            self.exit_code = 2
            self.exit()
            return

        self.destino = destino
        self.ip = ip
        # Con una IP literal NO se repite entre parentesis; con un nombre, si.
        self.origen = ip if es_ip(destino) else "%s (%s)" % (destino, ip)
        self.ttl, self.base = self.perfil(ip)

        self.write("PING %s (%s) 56(84) bytes of data.\n" % (destino, ip))
        if self.limite == 0:
            self.resumen()
            self.exit()
            return
        self.responde()

    # ------------------------------------------------------------- resolucion
    def resuelve(self, nombre: str) -> str | None:
        return resuelve_nombre(nombre, self.fs)

    def perfil(self, ip: str) -> tuple[int, float]:
        """(ttl, latencia base) coherentes con DONDE esta esa IP."""
        if ip.startswith("127."):
            # No sale de la maquina: ni salta routers ni cruza cable.
            return 64, 0.045
        if ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.",
                          "172.19.", "172.20.", "172.21.")):
            return 64, 0.35
        r = _semilla(ip)
        saltos = r.randint(4, 14)
        return 64 - saltos, r.uniform(8.0, 62.0)

    # ---------------------------------------------------------------- envio
    def responde(self) -> None:
        self.enviados += 1
        jitter = random.uniform(-0.07, 0.09)
        t = max(0.008, self.base * (1.0 + jitter))
        self.tiempos.append(t)
        self.write("64 bytes from %s: icmp_seq=%d ttl=%d time=%s ms\n"
                   % (self.origen, self.enviados, self.ttl, formatea_tiempo(t)))
        if self.limite is not None and self.enviados >= self.limite:
            self.resumen()
            self.exit()
            return
        self.programado = reactor.callLater(1, self.responde)

    def resumen(self) -> None:
        n = len(self.tiempos)
        etiqueta = getattr(self, "destino", "")
        transcurrido = int((time.time() - self.inicio) * 1000)
        self.write("\n--- %s ping statistics ---\n" % etiqueta)
        self.write("%d packets transmitted, %d received, 0%% packet loss, "
                   "time %dms\n" % (n, n, transcurrido))
        if not n:
            return
        media = sum(self.tiempos) / n
        # mdev de iputils es la desviacion tipica, no la desviacion media.
        var = sum((x - media) ** 2 for x in self.tiempos) / n
        self.write("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n"
                   % (min(self.tiempos), media, max(self.tiempos), var ** 0.5))

    def handle_CTRL_C(self) -> None:
        if self.programado is not None and self.programado.active():
            self.programado.cancel()
        # El "^C" NO lleva salto: lo pone el "\n" con el que empieza el
        # resumen. Asi sale igual que en un ping de verdad, donde el corte y
        # la linea de estadisticas quedan pegadas.
        self.write("^C")
        self.resumen()
        self.exit()

    # ----------------------------------------------------------------- ayuda
    def uso(self) -> None:
        # POR STDERR y saliendo con 2, aunque sea la ayuda. Medido.
        self.errorWrite(USO)
        self.exit_code = 2
        self.exit()

    def version(self) -> None:
        """La version sale del listado de dpkg, no escrita aqui.

        Asi "ping -V" y "dpkg -l iputils-ping" no pueden decir cosas
        distintas. El paquete es "3:20240117-1"; iputils se nombra solo por
        la parte de en medio.
        """
        try:
            from cowrie.commands.dpkg import datos_de, leer_paquetes
            version, _arch = datos_de(leer_paquetes(), "iputils-ping",
                                      por_defecto=("3:20240117-1", "amd64"))
        except Exception:                                      # noqa: BLE001
            version = "3:20240117-1"
        upstream = version.split(":")[-1].split("-")[0]
        self.write("ping from iputils %s\n" % upstream)
        self.write("libcap: yes, IDN: yes, NLS: no, error.h: yes, "
                   "getrandom(): yes, __fpending(): yes\n")
        self.exit()


commands["/usr/bin/ping"] = Command_ping
commands["/bin/ping"] = Command_ping
commands["ping"] = Command_ping
