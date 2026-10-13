# SPDX-License-Identifier: BSD-3-Clause
#
# setarch y sus cuatro alias: x86_64, i386, linux32 y linux64.
#
# "x86_64" ES EL CUARTO DE LA LISTA de lo que la maquina dice tener y no sabia
# ejecutar, con DIEZ usos en noventa dias de log ---detras de tr, sed y
# openssl, que ya estan---. Y no es un binario cualquiera con un nombre raro:
# en Debian /usr/bin/x86_64 es un ENLACE A setarch, del paquete util-linux, y
# lo que hace es EJECUTAR LO QUE SE LE PONGA DETRAS cambiando la personalidad
# del proceso.
#
# O sea que no era un comando que fallara y ya: era un ENVOLTORIO. Lo mas
# probable en esos diez usos es
#
#     x86_64 -R ./payload
#
# que desactiva la aleatorizacion del espacio de direcciones ---una tecnica de
# verdad para que un exploit salga fiable---. Sin emularlo, la orden de dentro
# no llegaba a ejecutarse nunca y la cadena del atacante se cortaba ahi, con un
# "Exec format error" que ademas delata que el binario esta en el disco y no
# se puede ejecutar.
#
# Las banderas de personalidad no hacen nada aqui, y no pueden: cambian el
# comportamiento del NUCLEO para el proceso, y estas ordenes no tienen
# proceso. Se aceptan y se ejecuta lo de detras, que es lo unico observable.
#
# Todo medido contra el setarch de un util-linux, incluida la ayuda en C: en
# otra configuracion regional sale traducida y no es la que veria una sesion
# del senuelo.
from __future__ import annotations

from cowrie.commands.base import FallaAlAvisar
from cowrie.shell.command import HoneyPotCommand

commands = {}

# Los cuatro nombres que enlazan a setarch en un Debian de amd64, mirados uno
# a uno en /usr/bin. Cada uno se identifica POR SU PROPIO NOMBRE en la ayuda,
# en la version y en los errores: "x86_64 from util-linux", no "setarch from".
ALIAS = ("setarch", "x86_64", "i386", "linux32", "linux64")

# Las que llevan argumento no hay ninguna; todas son banderas sueltas.
BANDERAS = {
    "-B", "--32bit", "-F", "--fdpic-funcptrs", "-I", "--short-inode",
    "-L", "--addr-compat-layout", "-R", "--addr-no-randomize",
    "-S", "--whole-seconds", "-T", "--sticky-timeouts",
    "-X", "--read-implies-exec", "-Z", "--mmap-page-zero",
    "-3", "--3gb", "--4gb", "--uname-2.6", "-v", "--verbose",
}

# Lo que dice "-v" al encender cada una. Solo se nombran las que tienen
# nombre de personalidad; "-v" a secas no enciende ninguna.
NOMBRE_PERSONALIDAD = {
    "-B": "ADDR_LIMIT_32BIT", "--32bit": "ADDR_LIMIT_32BIT",
    "-F": "FDPIC_FUNCPTRS", "--fdpic-funcptrs": "FDPIC_FUNCPTRS",
    "-I": "SHORT_INODE", "--short-inode": "SHORT_INODE",
    "-L": "ADDR_COMPAT_LAYOUT", "--addr-compat-layout": "ADDR_COMPAT_LAYOUT",
    "-R": "ADDR_NO_RANDOMIZE", "--addr-no-randomize": "ADDR_NO_RANDOMIZE",
    "-S": "WHOLE_SECONDS", "--whole-seconds": "WHOLE_SECONDS",
    "-T": "STICKY_TIMEOUTS", "--sticky-timeouts": "STICKY_TIMEOUTS",
    "-X": "READ_IMPLIES_EXEC", "--read-implies-exec": "READ_IMPLIES_EXEC",
    "-Z": "MMAP_PAGE_ZERO", "--mmap-page-zero": "MMAP_PAGE_ZERO",
    "-3": "ADDR_LIMIT_3GB", "--3gb": "ADDR_LIMIT_3GB",
    "--uname-2.6": "UNAME26",
}

AYUDA = """
Usage:
 {nombre} [options] [<program> [<argument>...]]

Change the reported architecture and set personality flags.

Options:
 -B, --32bit              turns on ADDR_LIMIT_32BIT
 -F, --fdpic-funcptrs     makes function pointers point to descriptors
 -I, --short-inode        turns on SHORT_INODE
 -L, --addr-compat-layout changes the way virtual memory is allocated
 -R, --addr-no-randomize  disables randomization of the virtual address space
 -S, --whole-seconds      turns on WHOLE_SECONDS
 -T, --sticky-timeouts    turns on STICKY_TIMEOUTS
 -X, --read-implies-exec  turns on READ_IMPLIES_EXEC
 -Z, --mmap-page-zero     turns on MMAP_PAGE_ZERO
 -3, --3gb                limits the used address space to a maximum of 3 GB
     --4gb                ignored (for backward compatibility only)
     --uname-2.6          turns on UNAME26
 -v, --verbose            say what options are being switched on

 -h, --help               display this help
 -V, --version            display version

For more details see setarch(8).
"""


def version_util_linux() -> str:
    """La version del paquete, del listado de dpkg como todas las demas."""
    crudo = "2.41-5"
    try:
        from cowrie.commands.dpkg import datos_de, leer_paquetes

        crudo, _arch = datos_de(leer_paquetes(), "util-linux",
                                por_defecto=("2.41-5", "amd64"))
    except Exception:                                          # noqa: BLE001
        pass
    return crudo.split("-")[0].split("+")[0]


class Command_setarch(FallaAlAvisar, HoneyPotCommand):
    def _quien_soy(self) -> str:
        """El nombre con el que lo han llamado, que es el que sale en todo.

        setarch mira su argv[0]: llamado como "x86_64" dice "x86_64 from
        util-linux", no "setarch from util-linux".
        """
        # Cowrie no le pasa el nombre al comando, asi que lo deja el shell en
        # el protocolo justo antes de ejecutarlo ---es el mismo sitio del que
        # tira dash para nombrarse en sus errores---. Con la ruta entera
        # ("/usr/bin/x86_64") setarch usa igualmente el ultimo trozo.
        nombre = getattr(self.protocol, "_nombre_invocado", "") or "setarch"
        return nombre.rsplit("/", 1)[-1]

    def call(self) -> None:
        yo = self._quien_soy()
        verboso = False
        encendidas: list = []
        orden: list = []
        for i, arg in enumerate(self.args):
            if orden:
                orden.append(arg)
                continue
            if arg in ("-h", "--help"):
                self.write(AYUDA.format(nombre=yo))
                return
            if arg in ("-V", "--version"):
                self.write("%s from util-linux %s\n"
                           % (yo, version_util_linux()))
                return
            if arg in ("-v", "--verbose"):
                verboso = True
                continue
            if arg in BANDERAS:
                if arg in NOMBRE_PERSONALIDAD:
                    encendidas.append(NOMBRE_PERSONALIDAD[arg])
                continue
            if arg.startswith("--"):
                self.errorWrite("%s: unrecognized option '%s'\n" % (yo, arg))
                self.errorWrite("Try '%s --help' for more information.\n" % yo)
                return
            if arg.startswith("-") and len(arg) > 1:
                self.errorWrite("%s: invalid option -- '%s'\n" % (yo, arg[1]))
                self.errorWrite("Try '%s --help' for more information.\n" % yo)
                return
            orden.append(arg)

        if verboso:
            for nombre in encendidas:
                self.write("Switching on %s.\n" % nombre)

        if not orden:
            # SIN ORDEN, setarch ARRANCA $SHELL. Aqui no se apila otra shell:
            # lo que el atacante ve es lo mismo ---le vuelve el prompt y sigue
            # igual--- y montar una anidada solo cambiaria a donde le lleva su
            # "exit". Queda dicho por si algun dia importa.
            if verboso:
                self.write("Execute command `%s'.\n"
                           % self.environ.get("SHELL", "/bin/sh"))
            return

        # Se importa AQUI y no arriba: "--version" y "--help" no relanzan nada
        # y asi el comando se puede cargar y probar sin el resto de Cowrie.
        from cowrie.commands.bashbuiltins import _path_lookup, _relanzar

        # SI NO EXISTE, EL ERROR ES EL DE setarch, no el del shell. setarch
        # hace execvp y se queja EL: "x86_64: failed to execute X" con codigo
        # 127. Relanzando a secas saldria "-bash: X: command not found", que
        # es de otro programa y descoloca a quien esta mirando.
        if "/" not in orden[0] and not _path_lookup(orden[0], self.environ,
                                                    self.fs):
            self.errorWrite("%s: failed to execute %s: "
                            "No such file or directory\n" % (yo, orden[0]))
            self.exit_code = 127
            return

        if verboso:
            self.write("Execute command `%s'.\n" % orden[0])
        _relanzar(self, " ".join(orden))


for _n in ALIAS:
    commands[_n] = Command_setarch
    commands["/usr/bin/" + _n] = Command_setarch
    commands["/bin/" + _n] = Command_setarch
