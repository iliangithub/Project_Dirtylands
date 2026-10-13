# SPDX-License-Identifier: BSD-3-Clause
"""
apt y apt-get emulados.

EXISTE POR UNA SESION REAL, la del 2026-08-30 20:51. Un bot entro como root y
tecleo cuatro ordenes; el apt que Cowrie trae de serie le contesto SEIS
imposibles seguidos:

  1. "apt-get update" siendo root ->
     "E: Could not open lock file /var/lib/apt/lists/lock - open (13:
     Permission denied)". Root no recibe permiso denegado sobre un fichero
     suyo. El de serie da por hecho que quien entra no es root, y nosotros
     aceptamos root/root como credencial: en la practica lo es casi siempre.
  2. El "-y" se instalo COMO SI FUERA UN PAQUETE: "masscan y" en la lista de
     nuevos, con su "Get:2 ... y 0.11-7" y su "Setting up y (0.11-7)".
  3. El fichero era "masscan_0.33-6_i386.deb" en una maquina que declara
     x86_64 en uname, en lscpu y en todo el dpkg -l.
  4. Venia de "ftp.debian.org stable/main"; la leyenda es Debian 13 trixie.
  5. Y despues "masscan" contestaba "masscan: Segmentation fault", que es lo
     que hace Cowrie con TODO paquete que finge instalar.
  6. La peor, porque no hace falta saber Linux para verla: "apt-get update"
     dijo permiso denegado y treinta segundos despues "apt-get install"
     descargo 328 kB tan tranquilo. La misma herramienta, el mismo usuario.

LA REGLA, y es una sola: ESTO NO INSTALA NADA. Se puede consultar lo que YA
esta instalado ---y eso sale del mismo fichero que lee dpkg, asi que
"apt-get install nano" y "dpkg -l | grep nano" no pueden contradecirse--- y lo
que no esta, no se encuentra.

Esa regla se lleva por delante la clase entera de fallos de arriba, porque
ninguno de ellos existe si no hay nada que fingir: no aparece un binario de la
nada que luego no sepa ejecutarse.

QUE SE PIERDE, y conviene saberlo: quien pida un paquete que SI existe en
Debian ---masscan mismo--- recibe "Unable to locate package". Es una respuesta
mundana, de servidor con los repositorios recortados, y no dice nada del
senuelo. La alternativa era seguir fingiendo la instalacion, y entonces hay
que fingir tambien el binario: eso es justo lo que hacia Cowrie y por eso
acababa en "Segmentation fault".

PENDIENTE DE VERIFICAR CONTRA UN TRIXIE REAL: Debian 13 trae apt 3.0, que
cambio la presentacion de "apt" (no la de "apt-get", que sigue siendo la
clasica). Aqui las dos dan la salida clasica. Es una imprecision de formato,
no una contradiccion, y esta muy por debajo de lo que habia; pero si alguien
tiene un trixie a mano, esto es lo que hay que medir.
"""

from __future__ import annotations

from twisted.internet import reactor

from cowrie.commands.dpkg import datos_de, leer_paquetes
from cowrie.shell.command import HoneyPotCommand

commands = {}

SUITE = "trixie"

# Lo que saca un "update" que no tiene nada nuevo que traer. Van con "Hit"
# porque el senuelo lleva dias levantado: un "Get" obligaria a inventar
# tamanos y velocidades que nadie puede comprobar.
FUENTES = (
    f"Hit:1 http://deb.debian.org/debian {SUITE} InRelease",
    f"Hit:2 http://deb.debian.org/debian {SUITE}-updates InRelease",
    f"Hit:3 http://security.debian.org/debian-security {SUITE}-security InRelease",
)

# LAS OPCIONES QUE SE LLEVAN UN VALOR DETRAS. Sin esta lista el valor se cuela
# como si fuera un paquete, que es la version general del fallo del "-y".
CON_VALOR = {"-o", "-c", "-t", "-a", "--option", "--config-file",
             "--target-release", "--default-release"}

# Acciones que solo LEEN. Las demas cambiarian el sistema, y eso no pasa.
SOLO_LEEN = {"update", "list", "show", "search", "policy", "showpkg"}

RESUMEN_CERO = ("0 upgraded, 0 newly installed, 0 to remove and "
                "0 not upgraded.\n")

# EL TIEMPO NO ES UN ADORNO. Un "apt update" de verdad tarda cerca de un
# segundo y va soltando las lineas segun contacta cada repositorio; el nuestro
# las vomitaba de golpe y "parecia que no hacia nada". Los retrasos de abajo
# estan MEDIDOS en un debian:trixie con un pseudo-terminal, apuntando el
# instante de cada escritura.
#
# Y con terminal apt no escribe lo mismo que en una tuberia:
#
#   apt-get update, terminal:  progreso SIN color, y DEJA "Reading package
#                              lists... Done" en pantalla
#   apt update, terminal:      progreso EN AMARILLO, y BORRA las tres lineas
#                              de "...  Done" antes de decir "All packages are
#                              up to date."
#   en tuberia:                ni progreso ni "Done"; y "apt" ademas avisa de
#                              que su interfaz no es estable
#
# De ahi que "apt" y "apt-get" tengan guiones distintos aunque hagan lo mismo.
AMARILLO, FIN_COLOR = "\x1b[33m", "\x1b[0m"

# EL CANDADO DE dpkg, y por que esta es la respuesta buena.
#
# Antes, "apt install nmap" contestaba "Unable to locate package nmap". Pero
# nmap ESTA en Debian, y el de verdad ensena su resumen y pregunta. O sea que
# la regla de "lo que no esta, no se encuentra" era mentira comprobable para
# cualquier paquete real --- y son justo los que se piden: nmap, masscan,
# tcpdump...
#
# La salida es esta: el candado de dpkg lo tiene otro proceso, asi que apt no
# llega ni a mirar si el paquete existe. Medido: con el candado ocupado, lo
# PRIMERO que sale es la espera, antes de leer las listas. Y "apt update"
# sigue funcionando, porque usa otro candado --- comprobado tambien.
#
# El que lo sostiene es unattended-upgrades, que en el ps de la maquina es el
# PID de abajo. Su "comm" es python3 porque es un guion de Python, igual que
# se midio.
PID_CANDADO, COMM_CANDADO = 691, "python3"

# CUANTO ESPERA, y aqui NOS APARTAMOS DEL REAL A PROPOSITO. El apt de trixie
# espera PARA SIEMPRE: se midieron cien segundos y seguia escribiendo una
# linea por segundo. Un senuelo que se cuelga asi se lleva por delante el
# resto del guion del atacante, que es justo lo que queremos ver. Se espera
# unos segundos y se falla con el error que da apt cuando no espera
# ---DPkg::Lock::Timeout=0---, que tambien es una salida suya de verdad.
ESPERA_CANDADO = 3


def _borra(ancho: int) -> str:
    """Lo que apt manda para tapar su propia linea de progreso."""
    return "\r" + " " * ancho + "\r"


def separa_paquetes(args):
    """Deja fuera las opciones Y sus valores; devuelve accion y paquetes.

    Aqui es donde se corrige el "-y": una opcion nunca puede terminar en la
    lista de paquetes, ni ella ni lo que la acompana.
    """
    sueltos = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            sueltos.extend(args[i + 1:])
            break
        if a.startswith("-"):
            if a in CON_VALOR:
                i += 1                      # y su valor, tambien fuera
            i += 1
            continue
        sueltos.append(a)
        i += 1
    return sueltos


class Command_aptget(HoneyPotCommand):
    """apt-get: la salida clasica."""

    NOMBRE = "apt-get"
    RESUMEN_UPDATE = False       # "apt" ademas dice si todo esta al dia
    # apt-get DEJA en pantalla su "... Done"; apt lo borra. Medido.
    DEJA_DONE = True
    COLOR = ""                   # apt pinta su progreso en amarillo
    # Y NO SE QUEJAN IGUAL: apt-get dice "E:" y el apt 3.0 dice "Error:".
    # Medido los dos.
    PREFIJO = "E: "

    def es_root(self) -> bool:
        return getattr(getattr(self.protocol, "user", None),
                       "username", "") == "root"

    # ------------------------------------------------------------------ util
    # ------------------------------------------------------- salida con tiempo
    def _paso(self, retraso: float, texto: str, error: bool = False) -> None:
        """Apunta una escritura para dentro de `retraso` segundos."""
        self.pasos.append((retraso, texto, error))

    def _reproducir(self) -> None:
        if not self.pasos:
            self.exit()
            return
        retraso, texto, error = self.pasos.pop(0)
        if retraso <= 0:
            (self.errorWrite if error else self.write)(texto)
            self._reproducir()
            return
        self.programado = reactor.callLater(retraso, self._emitir, texto, error)

    def _emitir(self, texto: str, error: bool) -> None:
        (self.errorWrite if error else self.write)(texto)
        self._reproducir()

    def handle_CTRL_C(self) -> None:
        if self.programado is not None and self.programado.active():
            self.programado.cancel()
        self.pasos = []
        self.write("^C\n")
        self.exit()

    def _hay_terminal(self) -> bool:
        """False si la salida va a una tuberia o a un fichero.

        Importa porque apt escribe cosas distintas: con terminal dibuja su
        progreso y lo borra; sin el, ni progreso ni "Done". Un "apt update |
        grep Hit" que recibiera los borrados se llevaria basura.
        """
        pp = getattr(self.protocol, "pp", None)
        if pp is None:
            return True
        return (getattr(pp, "next_command", None) is None
                and not getattr(pp, "redirect", False))

    def _fase(self, etiqueta: str, tramos, deja_done: bool) -> None:
        """Una fase de progreso: los porcentajes, y borrarla o dejarla.

        Los porcentajes y sus tiempos estan medidos: apt no cuenta de diez en
        diez, salta del 0% al 96% y al 99%.
        """
        if not self._hay_terminal():
            # En tuberia solo la etiqueta, sin "Done" y sin porcentajes.
            self._paso(tramos[0][0], "%s...\n" % etiqueta)
            return
        for retraso, tanto in tramos:
            self._paso(retraso, "\r%s... %d%%\r" % (etiqueta, tanto))
        if deja_done:
            self._paso(0.01, "\r%s... Done\n" % etiqueta)
        else:
            self._paso(0.01, _borra(len(etiqueta) + 9))

    def leyendo_listas(self) -> None:
        # 0% -> 96% -> 99%, con medio segundo de parada en el 0%: es lo que
        # tarda de verdad en leer las listas.
        self._fase("Reading package lists", ((0.01, 0), (0.52, 96), (0.01, 99)),
                   self.DEJA_DONE)

    def arbol(self) -> None:
        self._fase("Building dependency tree", ((0.01, 0), (0.03, 50)),
                   self.DEJA_DONE)
        self._fase("Reading state information", ((0.02, 0),), self.DEJA_DONE)

    def sin_permiso_listas(self) -> None:
        self._paso(0.01, 
            "%sCould not open lock file /var/lib/apt/lists/lock - open " % self.PREFIJO +
            "(13: Permission denied)\n", error=True)
        self._paso(0, "%sUnable to lock directory /var/lib/apt/lists/\n" % self.PREFIJO,
                   error=True)
        self.exit_code = 100

    def sin_permiso_dpkg(self) -> None:
        self._paso(
            0.01,
            "%sCould not open lock file /var/lib/dpkg/lock-frontend - open " % self.PREFIJO +
            "(13: Permission denied)\n", error=True)
        self._paso(
            0,
            "%sUnable to acquire the dpkg frontend lock " % self.PREFIJO +
            "(/var/lib/dpkg/lock-frontend), are you root?\n", error=True)
        self.exit_code = 100

    # --------------------------------------------------------------- acciones
    def start(self) -> None:
        self.pasos: list = []
        self.programado = None
        # "apt" en tuberia avisa de que su interfaz no es estable; "apt-get"
        # no, porque la suya si lo es. Medido.
        if self.NOMBRE == "apt" and not self._hay_terminal():
            self._paso(0.06, "\nWARNING: apt does not have a stable CLI "
                             "interface. Use with caution in scripts.\n\n")
        sueltos = separa_paquetes(self.args)
        if any(a in ("-v", "--version") for a in self.args):
            self.version()
            self._reproducir()
            return
        if not sueltos:
            self.uso()
            self._reproducir()
            return

        accion, paquetes = sueltos[0], sueltos[1:]

        if accion == "update":
            self.update()
        elif accion in ("install", "reinstall"):
            self.install(paquetes)
        elif accion in ("upgrade", "dist-upgrade", "full-upgrade"):
            self.upgrade()
        elif accion in ("remove", "purge", "autoremove"):
            self.remove(paquetes)
        elif accion in ("clean", "autoclean"):
            pass                     # no escriben nada y salen con 0
        else:
            self._paso(0, "%sInvalid operation %s\n" % (self.PREFIJO, accion), error=True)
            self.exit_code = 100
        self._reproducir()

    def update(self) -> None:
        if not self.es_root():
            # ESTO SI ERA CORRECTO en el de serie, solo que lo decia SIEMPRE.
            self.leyendo_listas()
            self.sin_permiso_listas()
            return
        if self._hay_terminal():
            # El indicador de progreso se pinta, se tapa con espacios para
            # escribir la linea del repositorio, y se vuelve a pintar. Los
            # tiempos son los medidos: 0.15 s hasta el primero ---la ida y
            # vuelta a la red--- y centesimas entre los siguientes.
            def prog(texto):
                return "%s\r%s%s" % (self.COLOR, texto, FIN_COLOR
                                     if self.COLOR else "")
            self._paso(0.06, prog("0% [Working]"))
            for i, linea in enumerate(FUENTES):
                espera = 0.15 if i == 0 else 0.02
                if i == 2:
                    self._paso(0.02, prog("0% [Waiting for headers]"))
                    espera = 0.02
                self._paso(espera, _borra(12) + linea + "\n" +
                           (prog("0% [Working]") if i < 2 else ""))
            self._paso(0.02, prog("20% [Working]") + _borra(13))
        else:
            for linea in FUENTES:
                self._paso(0.3 if linea is FUENTES[0] else 0.02,
                           linea + "\n")
        self.leyendo_listas()
        if self.RESUMEN_UPDATE:
            self.arbol()
            self._paso(0.01, "All packages are up to date.\n")

    def candado_dpkg(self) -> None:
        """Lo que ve quien intenta cambiar el sistema: el candado ocupado.

        Sin ser root ni se llega ahi: apt no puede ni abrir el fichero, y lo
        que sale es el "are you root?". Siendo root, el candado lo tiene otro
        proceso y apt NOMBRA cual --- por eso el PID de arriba tiene que estar
        en el ps, y hay una prueba que lo cruza.
        """
        if not self.es_root():
            self.leyendo_listas()
            self.arbol()
            self.sin_permiso_dpkg()
            return

        linea = ("Waiting for cache lock: Could not get lock "
                 "/var/lib/dpkg/lock-frontend. It is held by process %d (%s)"
                 % (PID_CANDADO, COMM_CANDADO))
        if self._hay_terminal():
            # Una linea por segundo, con el contador subiendo, como el real.
            for s in range(ESPERA_CANDADO):
                self._paso(1.05 if s == 0 else 1.0,
                           "\r%s... %ds\r" % (linea, s))
            self._paso(1.0, _borra(len(linea) + 6))
        else:
            self._paso(1.05 + ESPERA_CANDADO, "")
        self._paso(0, "%sCould not get lock /var/lib/dpkg/lock-frontend. It "
                      "is held by process %d (%s)\n"
                   % (self.PREFIJO, PID_CANDADO, COMM_CANDADO), error=True)
        self._paso(0, "%sUnable to acquire the dpkg frontend lock "
                      "(/var/lib/dpkg/lock-frontend), is another process "
                      "using it?\n" % self.PREFIJO, error=True)
        self.exit_code = 100

    # install, upgrade y remove hacen los tres lo mismo: tocar dpkg. Y por eso
    # los tres se topan con lo mismo.
    def install(self, paquetes) -> None:
        self.candado_dpkg()

    def upgrade(self) -> None:
        self.candado_dpkg()

    def remove(self, paquetes) -> None:
        self.candado_dpkg()

    def version(self) -> None:
        version, arch = datos_de(leer_paquetes(), "apt",
                                 por_defecto=("3.0.3", "amd64"))
        self._paso(0, "%s %s (%s)\n" % (self.NOMBRE, version, arch))

    def uso(self) -> None:
        self._paso(0, "%s: missing operation\n" % self.NOMBRE, error=True)
        self._paso(0, "Usage: %s [options] command\n" % self.NOMBRE,
                   error=True)
        self.exit_code = 100


class Command_apt(Command_aptget):
    """apt: lo mismo, pero dice si todo esta al dia despues del update."""

    NOMBRE = "apt"
    RESUMEN_UPDATE = True
    DEJA_DONE = False
    COLOR = AMARILLO
    PREFIJO = "Error: "


commands["/usr/bin/apt-get"] = Command_aptget
commands["apt-get"] = Command_aptget
commands["/usr/bin/apt"] = Command_apt
commands["apt"] = Command_apt
