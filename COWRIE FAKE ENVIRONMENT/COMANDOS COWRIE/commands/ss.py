# SPDX-License-Identifier: BSD-3-Clause
"""
ss emulado.

EL FORMATO ERA DE OTRA EPOCA. La cabecera estaba escrita a fuego con anchos
fijos ---"State       Recv-Q   Send-Q     Local Address:Port"--- y le faltaba
la columna Netid. El ss de iproute2 6.x calcula los anchos del CONTENIDO, y
Netid aparece en cuanto se pide mas de un protocolo, que es justo lo que hace
el "ss -tuln" de cualquier reconocimiento.

Medido en un Debian 13.6, con las posiciones de cada campo:

    Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port
    udp   UNCONN 0      0          127.0.0.1:5353      0.0.0.0:*
    tcp   LISTEN 0      1          127.0.0.1:8080      0.0.0.0:*

Y AQUI ESTA EL DETALLE QUE NO SE ADIVINA: las dos columnas de direccion no se
alinean como un todo. ss parte cada una por el ULTIMO ":", alinea la
direccion a la DERECHA y el puerto a la IZQUIERDA, y el ancho de cada mitad
sale de su propia cabecera:

    "Local Address:Port"  ->  "Local Address"(13) + ":" + "Port"(4)
    "Peer Address:Port"   ->  "Peer Address"(12)  + ":" + "Port"(4)

Por eso "0.0.0.0:*" no queda pegado a la derecha sino a cinco espacios, y
deja tres detras. Con una alineacion normal no cuadra ninguna de las dos.

Las cuatro primeras columnas si son normales: ancho = el mayor entre su
cabecera y sus valores, a la izquierda, separadas por un espacio.

LOS SOCKETS SON LOS MISMOS QUE LOS DE netstat, y hay una prueba que lo cruza:
dos comandos que listan lo que escucha una maquina no pueden decir cosas
distintas. Las colas si difieren a proposito ---ss ensena el backlog en
Send-Q y netstat un 0--- porque eso es lo que hacen de verdad.
"""

from __future__ import annotations

from cowrie.shell.command import HoneyPotCommand

commands = {}

# LO QUE ESCUCHA LA MAQUINA, EN UN SOLO SITIO. Lo leen ss y netstat, que lo
# pintan de formas distintas ---y eso NO es una incoherencia, es lo que hacen
# de verdad: netstat escribe "127.0.0.53:53" y ss "127.0.0.53%lo:53" con el
# sufijo de interfaz; netstat separa "tcp" de "tcp6" y ss usa "[::]"; netstat
# pone 0 en las dos colas y ss ensena el backlog en Send-Q---. Lo que no puede
# pasar es que discrepen en QUE hay escuchando, y por eso los hechos son uno.
#
# LOS SOCKETS DE systemd-resolved NO ESTABAN, y la maquina lleva el servicio
# declarado activo en systemctl y su proceso en el ps (PID 620). Un resolvedor
# corriendo sin un solo socket es la contradiccion; anadirlos la quita.
#
# Medido en un debian:trixie con systemd-resolved arrancado. Tres detalles que
# no se adivinan: el stub va con "%lo", hay un SEGUNDO escuchador en
# 127.0.0.54, y el LLMNR del 5355 sale por v4 y por v6.
#
# Y LA COLUMNA DEL PROGRAMA TAMPOCO ES LA MISMA: ss ensena el nombre CORTO
# del proceso ---el "comm" del nucleo, que se corta a 15 caracteres, de ahi
# "systemd-resolve" sin la "d"--- y netstat la linea de ordenes. Por eso hay
# dos campos y no uno.
#
# Los PID son los del ps_command_output.json, no otros: 682 sshd, 745 node y
# 620 systemd-resolved. Hay una prueba que los cruza.
#
# (familia, proto, direccion, interfaz, puerto, backlog, pid, comm, ordenes)
SOCKETS = [
    ("4", "tcp", "0.0.0.0", "", 22, 128, 682, "sshd", "sshd: /usr/sbin/sshd"),
    ("4", "tcp", "127.0.0.1", "", 3000, 511, 745, "node", "node"),
    ("6", "tcp", "::", "", 22, 128, 682, "sshd", "sshd: /usr/sbin/sshd"),
    ("4", "udp", "0.0.0.0", "", 5355, 0, 620, "systemd-resolve", "systemd-resolve"),
    ("4", "udp", "127.0.0.54", "", 53, 0, 620, "systemd-resolve", "systemd-resolve"),
    ("4", "udp", "127.0.0.53", "lo", 53, 0, 620, "systemd-resolve", "systemd-resolve"),
    ("6", "udp", "::", "", 5355, 0, 620, "systemd-resolve", "systemd-resolve"),
    ("4", "tcp", "127.0.0.53", "lo", 53, 4096, 620, "systemd-resolve", "systemd-resolve"),
    ("4", "tcp", "127.0.0.54", "", 53, 4096, 620, "systemd-resolve", "systemd-resolve"),
    ("4", "tcp", "0.0.0.0", "", 5355, 4096, 620, "systemd-resolve", "systemd-resolve"),
    ("6", "tcp", "::", "", 5355, 4096, 620, "systemd-resolve", "systemd-resolve"),
]


def para_ss(familia, direccion, interfaz):
    """La direccion como la escribe ss: con "%lo" y con "[::]"."""
    base = "[%s]" % direccion if familia == "6" else direccion
    return base + ("%" + interfaz if interfaz else "")


def _parte(direccion: str) -> tuple[str, str]:
    """Separa "addr:port" por el ULTIMO ":", que es como lo hace ss.

    Hace falta el ultimo y no el primero: una direccion IPv6 lleva colons
    dentro ("[::]:22"), y partir por el primero daria "[" y ":]:22".
    """
    if ":" not in direccion:
        return direccion, ""
    izq, _, der = direccion.rpartition(":")
    return izq, der


def formatea(filas: list[tuple], columnas: list[str], con_proceso: bool) -> str:
    """La tabla, con los anchos que saldrian del contenido."""
    # Las columnas simples: ancho = el mayor entre cabecera y valores.
    anchos = [max(len(c), *(len(f[i]) for f in filas)) if filas else len(c)
              for i, c in enumerate(columnas[:-2])]

    # Y las dos de direccion, cada mitad por su lado.
    mitades = []
    for i, cab in enumerate(columnas[-2:], start=len(columnas) - 2):
        c_dir, c_pto = _parte(cab)
        anchos_dir = [len(_parte(f[i])[0]) for f in filas] or [0]
        anchos_pto = [len(_parte(f[i])[1]) for f in filas] or [0]
        mitades.append((max(len(c_dir), *anchos_dir),
                        max(len(c_pto), *anchos_pto)))

    def pinta(campos, es_cabecera):
        trozos = [campos[i].ljust(anchos[i]) for i in range(len(anchos))]
        for j, i in enumerate(range(len(columnas) - 2, len(columnas))):
            ancho_dir, ancho_pto = mitades[j]
            d, p = _parte(campos[i])
            trozos.append(d.rjust(ancho_dir) + ":" + p.ljust(ancho_pto))
        linea = " ".join(trozos)
        if con_proceso:
            # La cabecera pega "Process" SIN separador; las filas si lo
            # llevan. Es una rareza de ss, y esta medida.
            linea += ("Process" if es_cabecera else " " + campos[-1])
        return linea

    salida = [pinta(columnas + [""], True)]
    salida += [pinta(list(f), False) for f in filas]
    return "\n".join(salida) + "\n"


class Command_ss(HoneyPotCommand):
    def call(self) -> None:
        args = "".join(a for a in self.args if a.startswith("-")).replace("-", "")
        quiere_escucha = "l" in args
        quiere_todo = "a" in args
        quiere_tcp = "t" in args
        quiere_udp = "u" in args
        quiere_proc = "p" in args
        es_root = self.protocol.user.username == "root"
        if not quiere_tcp and not quiere_udp:
            quiere_tcp = True

        # NETID SALE CUANDO SE PIDE MAS DE UN PROTOCOLO, y no siempre: con un
        # "ss -tln" a secas no aparece, porque no hay nada que distinguir.
        con_netid = quiere_tcp and quiere_udp

        filas = []
        if quiere_escucha or quiere_todo:
            # ss ordena los udp antes que los tcp. Medido.
            for orden in ("udp", "tcp"):
                for (fam, proto, dirc, iface, puerto, backlog, pid, nombre,
                     _ordenes) in SOCKETS:
                    if proto != orden:
                        continue
                    if proto == "tcp" and not quiere_tcp:
                        continue
                    if proto == "udp" and not quiere_udp:
                        continue
                    filas.append((
                        proto,
                        "LISTEN" if proto == "tcp" else "UNCONN",
                        "0", str(backlog),
                        "%s:%d" % (para_ss(fam, dirc, iface), puerto),
                        "[::]:*" if fam == "6" else "0.0.0.0:*",
                        self._proceso(pid, nombre, quiere_proc, es_root)))
        if quiere_tcp and (not quiere_escucha or quiere_todo):
            filas.append((
                "tcp", "ESTAB", "0", "0",
                f"{self.protocol.kippoIP}:22",
                f"{self.protocol.clientIP}:54122",
                self._proceso(682, "sshd", quiere_proc, es_root)))

        columnas = ["State", "Recv-Q", "Send-Q"]
        if con_netid:
            columnas.insert(0, "Netid")
        else:
            filas = [f[1:] for f in filas]
        columnas += ["Local Address:Port", "Peer Address:Port"]
        self.write(formatea(filas, columnas, quiere_proc and es_root))

    @staticmethod
    def _proceso(pid, nombre, quiere, es_root) -> str:
        if not (quiere and es_root):
            return ""
        return f'users:(("{nombre}",pid={pid},fd=3))'


commands["ss"] = Command_ss
commands["/usr/bin/ss"] = Command_ss
commands["/sbin/ss"] = Command_ss
