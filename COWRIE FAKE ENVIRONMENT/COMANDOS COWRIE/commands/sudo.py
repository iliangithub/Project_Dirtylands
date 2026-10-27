# SPDX-License-Identifier: BSD-3-Clause
"""
sudo parcheado.

DOS COMPORTAMIENTOS, segun quien lo llame, y esa es toda la correccion:

  - Un usuario normal recibe el prompt de contrasena (oculta) y una negativa:
    no esta en el fichero de sudoers. Eso ya estaba y es correcto.

  - ROOT NO. En un Linux de verdad, sudo llamado por root no pregunta nada:
    ejecuta la orden y ya. Aqui se le pedia la contrasena y despues se le
    contestaba "root is not in the sudoers file. This incident will be
    reported.", que es un imposible ---root no necesita estar en sudoers---
    y lo dijo de verdad en la sesion del 2026-08-30 20:52, porque aceptamos
    root/root como credencial y entonces casi todo el que entra es root.

La orden se ejecuta como la ejecuta bash.py: en una shell no interactiva que
se apila y se saca POR IDENTIDAD. Un pop() a ciegas se llevaria lo que hubiera
encima ---este mismo sudo, o una descarga aun en vuelo--- y eso es lo que deja
una sesion sin prompt. Ver la nota de execute_commands() en bash.py.
"""
from __future__ import annotations

import shlex

from twisted.python import log

from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.honeypot import HoneyPotShell

commands = {}

# TODO ESTO ESTA MEDIDO contra sudo 1.9.15 con LC_ALL=C, no recordado. El
# texto que habia era de la rama 1.8 ---se reconoce por el "[-D level]", el
# "-l[l]" y los "groupname|#gid"--- mientras que nuestro propio "sudo -V"
# declaraba 1.9.16p2: se contradecian entre si. El de la 1.9 ademas PARTE las
# lineas largas con sangria, y el nuestro las escupia planas.
USO = """usage: sudo -h | -K | -k | -V
usage: sudo -v [-ABkNnS] [-g group] [-h host] [-p prompt] [-u user]
usage: sudo -l [-ABkNnS] [-g group] [-h host] [-p prompt] [-U user]
            [-u user] [command [arg ...]]
usage: sudo [-ABbEHkNnPS] [-r role] [-t type] [-C num] [-D directory]
            [-g group] [-h host] [-p prompt] [-R directory] [-T timeout]
            [-u user] [VAR=value] [-i | -s] [command [arg ...]]
usage: sudo -e [-ABkNnS] [-r role] [-t type] [-C num] [-D directory]
            [-g group] [-h host] [-p prompt] [-R directory] [-T timeout]
            [-u user] file ...
"""

OPCIONES = """Options:
  -A, --askpass                 use a helper program for password prompting
  -b, --background              run command in the background
  -B, --bell                    ring bell when prompting
  -C, --close-from=num          close all file descriptors >= num
  -D, --chdir=directory         change the working directory before running
                                command
  -E, --preserve-env            preserve user environment when running command
      --preserve-env=list       preserve specific environment variables
  -e, --edit                    edit files instead of running a command
  -g, --group=group             run command as the specified group name or ID
  -H, --set-home                set HOME variable to target user's home dir
  -h, --help                    display help message and exit
  -h, --host=host               run command on host (if supported by plugin)
  -i, --login                   run login shell as the target user; a command
                                may also be specified
  -K, --remove-timestamp        remove timestamp file completely
  -k, --reset-timestamp         invalidate timestamp file
  -l, --list                    list user's privileges or check a specific
                                command; use twice for longer format
  -n, --non-interactive         non-interactive mode, no prompts are used
  -P, --preserve-groups         preserve group vector instead of setting to
                                target's
  -p, --prompt=prompt           use the specified password prompt
  -R, --chroot=directory        change the root directory before running command
  -r, --role=role               create SELinux security context with specified
                                role
  -S, --stdin                   read password from standard input
  -s, --shell                   run shell as the target user; a command may
                                also be specified
  -t, --type=type               create SELinux security context with specified
                                type
  -T, --command-timeout=timeout terminate command after the specified time limit
  -U, --other-user=user         in list mode, display privileges for user
  -u, --user=user               run command (or edit file) as specified user
                                name or ID
  -V, --version                 display version information and exit
  -v, --validate                update user's timestamp without running a
                                command
  --                            stop processing command line arguments
"""



# Opciones de sudo que se llevan un valor detras: sin esta lista, ese valor se
# tomaria por el principio de la orden a ejecutar.
CON_VALOR = {"-u", "-g", "-p", "-r", "-t", "-U", "-C", "-D", "-a"}


def separa(args):
    """(opciones de sudo, orden a ejecutar)."""
    opciones = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            i += 1
            break
        if not a.startswith("-"):
            break
        opciones.append(a)
        if a in CON_VALOR and i + 1 < len(args):
            i += 1
            opciones.append(args[i])
        i += 1
    return opciones, args[i:]


class Command_sudo(HoneyPotCommand):
    def short_help(self) -> None:
        """El uso a secas: POR STDERR y saliendo con 1.

        Y SIN la linea "sudo: Only one of the -e, -h, -i, -K, -l, -s, -v or -V
        options may be specified", que es lo que llevaba delante. Ese error
        solo sale cuando se le pasan opciones INCOMPATIBLES; un "sudo" pelado
        no lo dice nunca. Medido.
        """
        self.errorWrite(USO)
        self.exit_code = 1
        self.exit()

    def long_help(self) -> None:
        """La ayuda de "-h": por STDOUT y con 0, al reves que el uso."""
        self.write("sudo - execute a command as another user\n\n")
        self.write(USO)
        self.write("\n")
        self.write(OPCIONES)
        self.exit()

    def version(self) -> None:
        """Cinco lineas para un usuario normal; CIENTO CUARENTA Y DOS si es root.

        Esa es la diferencia que faltaba. Un "sudo -V" ejecutado por root no
        saca la version y ya: vuelca las opciones de compilacion, las rutas,
        los defaults de sudoers y la lista entera de variables de entorno que
        conserva. Y como aceptamos root/root, root es el caso HABITUAL: la
        version corta era la que casi nadie iba a ver.

        El volcado no vive aqui sino en ayudas-comandos.json, que es donde ya
        viven los demas textos medidos: son datos de un binario, no codigo, y
        142 lineas dentro del modulo lo hacen ilegible. Se le sustituye la
        version al vuelo por la del listado de dpkg, para que ni el volcado
        largo ni las cinco lineas puedan contradecir a "dpkg -l sudo".

        Si el fichero de datos faltara, sale la version corta: mas vale
        quedarse escueto que no contestar.
        """
        if self.protocol.user.username == "root":
            largo = self._volcado_largo()
            if largo:
                self.write(largo)
                self.exit()
                return
        return self._version_corta()

    def _volcado_largo(self) -> str:
        try:
            from cowrie.commands.ayuda import ayudas

            entrada = ayudas().get("_sudo_version_root") or {}
            texto = entrada.get("texto")
            if not texto:
                return ""
            viejo = entrada.get("version_a_sustituir")
            nuevo = self._numero_de_version()
            return texto.replace(viejo, nuevo) if viejo else texto
        except Exception:                                  # noqa: BLE001
            return ""

    def _numero_de_version(self) -> str:
        try:
            from cowrie.commands.dpkg import datos_de, leer_paquetes

            paquete, _arch = datos_de(leer_paquetes(), "sudo",
                                      por_defecto=("1.9.16p2-1", "amd64"))
        except Exception:                                  # noqa: BLE001
            paquete = "1.9.16p2-1"
        return paquete.split(":")[-1].split("-")[0]

    def _version_corta(self) -> None:
        """Cinco lineas, no cuatro: faltaba la del plugin de auditoria.

        Y la version sale del listado de dpkg, no escrita aqui, para que
        "sudo -V" y "dpkg -l sudo" no puedan decir cosas distintas --- que es
        exactamente lo que pasaba con el texto del uso. El paquete es
        "1.9.16p2-1"; sudo se nombra solo por la parte de delante del guion.
        """
        v = self._numero_de_version()
        self.write(
            f"Sudo version {v}\n"
            f"Sudoers policy plugin version {v}\n"
            "Sudoers file grammar version 50\n"
            f"Sudoers I/O plugin version {v}\n"
            f"Sudoers audit plugin version {v}\n"
        )
        self.exit()

    def start(self) -> None:
        opciones, orden = separa(self.args)
        if "-V" in opciones:
            self.version()
            return
        # "sudo --help" y "sudo -help" sacan el mismo uso largo que "-h";
        # medido contra sudo 1.9. Antes "--help" no lo reconocia nadie y se
        # caia al camino normal: le PEDIA LA CONTRASENA a quien pedia ayuda.
        if opciones and ({"-h", "-help", "--help"} & set(opciones)):
            self.long_help()
            return

        # SIN NADA QUE HACER, sudo IMPRIME EL USO Y SALE. No pregunta.
        #
        # Analiza los argumentos ANTES de autenticar, asi que un "sudo" pelado
        # no llega nunca al prompt de la contrasena --- y aqui si llegaba,
        # cuando quien lo tecleaba no era root. Las opciones de abajo son las
        # que si tienen sentido sin orden detras.
        SIN_ORDEN = {"-i", "--login", "-s", "--shell", "-v", "--validate",
                     "-l", "-ll", "--list", "-K", "--remove-timestamp",
                     "-k", "--reset-timestamp", "-e", "--edit"}
        if not orden and not (set(opciones) & SIN_ORDEN):
            self.short_help()
            return

        if self.protocol.user.username == "root":
            self.como_root(opciones, orden)
            return

        # Usuario normal: pedir contrasena (oculta) y denegar.
        user = self.protocol.user.username
        self.write(f"[sudo] password for {user}: ")
        self.protocol.password_input = True
        self.callbacks = [self.finish]

    def como_root(self, opciones, orden) -> None:
        """Root ya lo es todo: sudo no pregunta, hace."""
        if orden:
            self.ejecuta(orden)
            return
        # "-i" abre una shell de login, que siendo root solo cambia el
        # directorio; "-s" ni eso. No se apila otra shell porque no hay
        # ninguna identidad que cambiar --- es la misma razon por la que "su"
        # tampoco la apila, solo cambia el usuario en el sitio.
        if "-i" in opciones or "--login" in opciones:
            if self.fs.exists("/root"):
                self.protocol.cwd = "/root"
            self.exit()
            return
        # "-l" SI ESCRIBE. Es de lo primero que se teclea al entrar ---dice
        # que puede hacer uno con sudo--- y salia en blanco, que en un sudo de
        # verdad no pasa nunca: o lista o dice que no puedes. Medido en un
        # Debian 13; la ruta segura es la misma que declara el sudoers de la
        # leyenda y el nombre de la maquina sale del protocolo, no escrito
        # aqui, para que no pueda discrepar del prompt.
        if "-l" in opciones or "-ll" in opciones or "--list" in opciones:
            maquina = self.protocol.hostname
            self.write(
                "Matching Defaults entries for root on %s:\n"
                "    env_reset, mail_badpass,"
                " secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:"
                "/usr/bin\\:/sbin\\:/bin, use_pty\n"
                "\n"
                "User root may run the following commands on %s:\n"
                "    (ALL : ALL) ALL\n" % (maquina, maquina))
            self.exit()
            return
        # Las demas de las que valen sin orden ---"-v", "-k"...--- no tienen
        # nada que hacer siendo root ya: se sale en silencio, que es lo que
        # hace el de verdad cuando no hay nada que validar.
        self.exit()

    def ejecuta(self, orden) -> None:
        linea = " ".join(shlex.quote(a) for a in orden)
        shell = HoneyPotShell(self.protocol, interactive=False)
        self.protocol.cmdstack.append(shell)
        shell.lineReceived(linea)
        # POR IDENTIDAD Y SOLO SI SIGUE AHI. Ver la cabecera.
        if shell in self.protocol.cmdstack:
            self.protocol.cmdstack.remove(shell)
        self.exit()

    def finish(self, line: str) -> None:
        self.protocol.password_input = False
        user = self.protocol.user.username
        self.write(
            f"{user} is not in the sudoers file. This incident will be reported.\n"
        )
        self.exit()

    def lineReceived(self, line: str) -> None:
        log.msg(
            eventid="cowrie.command.input",
            realm="sudo",
            input=line,
            format="INPUT (%(realm)s): %(input)s",
        )
        if getattr(self, "callbacks", None):
            self.callbacks.pop(0)(line)


commands["/usr/bin/sudo"] = Command_sudo
commands["sudo"] = Command_sudo
