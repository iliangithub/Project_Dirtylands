# SPDX-License-Identifier: BSD-3-Clause
#
# journalctl emulado.
#
# LO QUE HABIA ERA PEOR QUE UN COMANDO SIN IMPLEMENTAR. Devolvia once lineas
# fijas, escritas a mano, con tres problemas cada una:
#
#   1. FECHAS DE JULIO. Decia "Jul 23 06:14:02" pasara lo que pasara. La
#      maquina arranco el 2026-03-10 y "date" dice el dia de hoy, asi que
#      bastaba mirar las dos cosas seguidas. Es el mismo fallo que ya se
#      corrigio en /proc/uptime: un dato que nace correcto y a los cinco
#      minutos miente.
#   2. DECIA "sshd[48213]". En trixie el que atiende la sesion es
#      "sshd-session" desde OpenSSH 9.8 ---el auth.log ya lo dice bien--- asi
#      que los dos registros de la MISMA maquina daban nombres distintos al
#      mismo proceso.
#   3. IGNORABA TODOS SUS ARGUMENTOS. "journalctl -u ssh", "journalctl -n 5",
#      "journalctl --since today" y "journalctl -f" contestaban las mismas
#      once lineas. Cualquiera que pida el registro de UNA unidad y reciba
#      tambien el de cron sabe que no esta hablando con un journalctl.
#
# Ahora se genera, y de la MISMA fuente que /var/log/auth.log: authlog.eventos
# devuelve lo que ha pasado sin formato, el auth.log le da el formato de
# rsyslog y esto le da el de journald. Asi los dos ficheros no pueden contar
# historias distintas de la misma maquina.
#
# El journal cubre los mismos siete dias que el auth.log. Un journald de
# verdad tampoco guarda desde el principio de los tiempos: recorta por tamano
# con SystemMaxUse, y una ventana de dias es lo normal.
from __future__ import annotations

import time

from cowrie.shell.command import HoneyPotCommand

commands = {}

H = "pc-dev-003-ignis"
SIN_ENTRADAS = "-- No entries --\n"

# Lo que teclea la gente para nombrar una unidad -> como se llama el proceso
# que escribe en el registro. "cron" y "cron.service" valen los dos, medido.
UNIDADES = {
    "cron": ("CRON",),
    "ssh": ("sshd", "sshd-session"),
    "sshd": ("sshd", "sshd-session"),
    "systemd-logind": ("systemd-logind",),
    "init": ("systemd",),
}

# Las unidades que dispara un temporizador en una Debian recien puesta. No
# salen en "systemctl list-units" y no es una contradiccion: un servicio
# oneshot que ya termino se queda inactivo y solo aparece con --all.
DIARIAS = [
    ("logrotate", "Rotate log files", 3, 25),
    ("man-db", "Daily man-db regeneration", 7, 9),
    ("systemd-tmpfiles-clean", "Cleanup of Temporary Directories", 9, 41),
    ("apt-daily-upgrade", "Daily apt upgrade and clean activities", 6, 52),
]


def corta(momento: float) -> str:
    """La marca de journald.

    OJO AL DIA: journald lo escribe con cero delante ---"Sep 03"--- y "date"
    lo escribe con espacio ---"Sep  3"---. Son formatos distintos del mismo
    dia y copiar el del comando equivocado se ve a simple vista.
    """
    return time.strftime("%b %d %H:%M:%S", time.localtime(momento))


def linea(ev) -> str:
    momento, quien, pid, texto = ev[0], ev[1], ev[2], ev[3]
    return "%s %s %s[%d]: %s" % (corta(momento), H, quien, pid, texto)


def _unidades(ahora: float, dias: int) -> list:
    """Los temporizadores diarios, que son de systemd y no de cron."""
    salida = []
    desde = ahora - dias * 86400
    dia = desde - (desde % 86400)
    while dia < ahora:
        for nombre, descripcion, hora, minuto in DIARIAS:
            t = dia + hora * 3600 + minuto * 60 + (int(dia) % 7)
            if not desde <= t < ahora:
                continue
            unidad = nombre + ".service"
            salida.append((t, "systemd", 1,
                           "Starting %s - %s..." % (unidad, descripcion)))
            salida.append((t + 1.2, "systemd", 1,
                           "%s: Deactivated successfully." % unidad))
            salida.append((t + 1.3, "systemd", 1,
                           "Finished %s - %s." % (unidad, descripcion)))
        dia += 86400
    return salida


class Command_journalctl(HoneyPotCommand):
    """journalctl. En Debian un usuario normal puede leer el journal."""

    # En la clase, no solo en start(), para que llamar a call() por su cuenta
    # ---como hacen las pruebas--- no se encuentre el atributo sin definir.
    paginar = True
    paginando = False

    def start(self) -> None:
        """El paginador se queda con el terminal, asi que aqui NO se puede
        salir sin mas: si el comando termina, la shell vuelve a pintar su
        prompt por debajo del paginador y las teclas dejan de ser suyas."""
        self.paginar = True
        self.paginando = False
        self.call()
        if not self.paginando:
            self.exit()

    def _muestra(self, texto: str) -> None:
        if not self.paginar:
            self.write(texto)
            return
        try:
            from cowrie.commands import paginador
        except ImportError:                                    # noqa: BLE001
            # Que falte el paginador no puede dejar al comando sin contestar:
            # se vuelca, que es lo que hacia antes de que existiera.
            self.write(texto)
            return
        self.paginando = paginador.vuelca(self, texto)
        if not self.paginando:
            self.write(texto)

    def _falla(self, texto: str) -> None:
        self.errorWrite(texto)
        self.exit_code = 1

    def _momento(self, texto: str):
        """--since/--until. Devuelve None si no lo entiende."""
        t = texto.strip().lower()
        ahora = time.time()
        if t in ("now",):
            return ahora
        if t == "today":
            h = time.localtime(ahora)
            return time.mktime((h.tm_year, h.tm_mon, h.tm_mday,
                                0, 0, 0, 0, 0, -1))
        if t == "yesterday":
            return self._momento("today") - 86400
        for formato in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d",
                        "%H:%M:%S", "%H:%M"):
            try:
                partes = time.strptime(t, formato)
            except ValueError:
                continue
            if formato.startswith("%H"):
                h = time.localtime(ahora)
                return time.mktime((h.tm_year, h.tm_mon, h.tm_mday,
                                    partes.tm_hour, partes.tm_min,
                                    partes.tm_sec, 0, 0, -1))
            return time.mktime(partes)
        return None

    def call(self) -> None:
        cuantas = None
        unidad = None
        al_reves = False
        solo_kernel = False
        prioridad = None
        desde = hasta = None
        listar_arranques = False

        args = list(self.args)
        i = 0
        while i < len(args):
            a = args[i]
            siguiente = args[i + 1] if i + 1 < len(args) else None
            if a in ("-n", "--lines"):
                # "-n" a secas son diez, medido. Y un "-n abc" no protesta por
                # el numero: journalctl toma "abc" como una expresion de
                # busqueda y se queja de eso.
                if siguiente is not None and siguiente.isdigit():
                    cuantas = int(siguiente); i += 2; continue
                cuantas = 10
            elif a.startswith("--lines="):
                valor = a.split("=", 1)[1]
                if not valor.isdigit():
                    self._falla("Failed to add match '%s': Invalid argument\n"
                                % valor)
                    return
                cuantas = int(valor)
            elif a in ("-u", "--unit") and siguiente is not None:
                unidad = siguiente; i += 2; continue
            elif a.startswith("--unit="):
                unidad = a.split("=", 1)[1]
            elif a in ("-p", "--priority") and siguiente is not None:
                prioridad = siguiente; i += 2; continue
            elif a.startswith("--priority="):
                prioridad = a.split("=", 1)[1]
            elif a in ("--since", "-S") and siguiente is not None:
                desde = siguiente; i += 2; continue
            elif a.startswith("--since="):
                desde = a.split("=", 1)[1]
            elif a in ("--until", "-U") and siguiente is not None:
                hasta = siguiente; i += 2; continue
            elif a.startswith("--until="):
                hasta = a.split("=", 1)[1]
            elif a in ("-r", "--reverse"):
                al_reves = True
            elif a in ("-k", "--dmesg"):
                solo_kernel = True
            elif a == "--list-boots":
                listar_arranques = True
            elif a == "--no-pager":
                self.paginar = False
            elif a in ("-b", "--boot", "-x", "--catalog",
                       "-q", "--quiet", "-a", "--all", "--full", "-l",
                       "--no-hostname", "-e", "--pager-end", "--no-tail",
                       "-m", "--merge", "--system", "--user"):
                pass
            elif a in ("-o", "--output") and siguiente is not None:
                i += 2; continue
            elif a.startswith("--output=") or a.startswith("--boot="):
                pass
            elif a in ("-f", "--follow"):
                # Un journalctl -f de verdad NO termina: saca la cola y se
                # queda esperando. Aqui se saca la cola y se sale, porque
                # dejar la sesion colgada para siempre ata una conexion sin
                # que el atacante saque nada. Es la misma decision que se
                # tomo con el candado de apt, y esta escrita en el README.
                cuantas = 10 if cuantas is None else cuantas
            elif a.startswith("--"):
                self._falla("journalctl: unrecognized option '%s'\n"
                            % a.split("=")[0])
                return
            elif a.startswith("-") and len(a) > 1:
                self._falla("journalctl: invalid option -- '%s'\n" % a[1])
                return
            else:
                # Un argumento suelto es una expresion de busqueda CAMPO=valor.
                if "=" not in a:
                    self._falla("Failed to add match '%s': Invalid argument\n"
                                % a)
                    return
            i += 1

        ahora = time.time()
        if listar_arranques:
            self._arranques(ahora)
            return

        limite_desde = limite_hasta = None
        for texto, destino in ((desde, "desde"), (hasta, "hasta")):
            if texto is None:
                continue
            valor = self._momento(texto)
            if valor is None:
                self._falla("Failed to parse timestamp: %s\n" % texto)
                return
            if destino == "desde":
                limite_desde = valor
            else:
                limite_hasta = valor

        filas = self._entradas(ahora)

        if solo_kernel:
            # El kernel no escribe aqui: sus lineas vienen del anillo del
            # nucleo y este senuelo no lo emula.
            filas = []
        if unidad is not None:
            nombre = unidad.split(".")[0]
            quienes = UNIDADES.get(nombre)
            filas = [f for f in filas if quienes and f[1] in quienes]
        if prioridad is not None and prioridad not in ("info", "6", "debug",
                                                       "7", "notice", "5"):
            # Lo unico que sale con prioridad de error es el aviso de pam_env.
            # Medido: "journalctl -p err" devuelve justo esas lineas.
            filas = [f for f in filas if "pam_env(" in f[3]]
        if limite_desde is not None:
            filas = [f for f in filas if f[0] >= limite_desde]
        if limite_hasta is not None:
            filas = [f for f in filas if f[0] <= limite_hasta]

        if cuantas is not None:
            filas = filas[-cuantas:] if cuantas else []
        if al_reves:
            filas = list(reversed(filas))

        if not filas:
            self.write(SIN_ENTRADAS)
            return
        self._muestra("".join(linea(f) + "\n" for f in filas))

    def _entradas(self, ahora: float) -> list:
        """Todo el registro, ordenado. Sale de la misma fuente que el
        auth.log: si algun dia divergieran, seria porque alguien duplico el
        generador en vez de usarlo."""
        try:
            from cowrie.commands.authlog import (DIAS, datos_sesion,
                                                  eventos)
            usuario, uid, ip, puerto, sesion = datos_sesion(self.protocol)
            sin_locale = not self.fs.exists("/etc/default/locale")
            filas = eventos(usuario, uid, ip, puerto, ahora, sin_locale,
                            sesion)
            filas = filas + _unidades(ahora, DIAS)
        except Exception:                                      # noqa: BLE001
            return []
        filas.sort(key=lambda x: x[0])
        return filas

    def _arranques(self, ahora: float) -> None:
        """--list-boots. Un solo arranque, el de la leyenda."""
        from cowrie.commands.base import IGNIS_BOOT_EPOCH
        formato = "%a %Y-%m-%d %H:%M:%S %Z"
        self.write("IDX BOOT ID                          "
                   "FIRST ENTRY                 LAST ENTRY\n")
        self.write("  0 %s %s %s\n"
                   % (BOOT_ID,
                      time.strftime(formato, time.localtime(IGNIS_BOOT_EPOCH)),
                      time.strftime(formato, time.localtime(ahora))))


# El identificador del arranque es fijo porque la maquina arranco una sola
# vez: cambiarlo entre dos llamadas diria que se reinicio en medio.
BOOT_ID = "4f8b2c1e9a6d47b3ae05c7412f9db836"


commands["journalctl"] = Command_journalctl
commands["/usr/bin/journalctl"] = Command_journalctl
commands["/bin/journalctl"] = Command_journalctl
