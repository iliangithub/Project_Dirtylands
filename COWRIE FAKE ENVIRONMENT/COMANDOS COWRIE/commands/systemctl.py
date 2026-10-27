# SPDX-License-Identifier: BSD-3-Clause
from __future__ import annotations

from cowrie.shell.command import HoneyPotCommand

# LOS GLIFOS VAN EN ASCII: "*" en vez de "●", "|-" en vez de "├─" y "`-" en
# vez de "└─". Es lo que hace el special_glyph() de systemd cuando el locale no
# es UTF-8, y la sesion del senuelo corre en POSIX. Aqui NO se pudo medir
# ---el contenedor de pruebas no arranca systemd como PID 1--- pero pstree y
# lsblk si, y tienen que coincidir: en un mismo terminal no puede un comando
# dibujar en ASCII y otro en Unicode. Ver la nota de pstree.py.
commands = {}

OVERALL = """* pc-dev-003-ignis
    State: running
    Units: 312 loaded (incl. loaded aliases)
     Jobs: 0 queued
   Failed: 0 units
    Since: Tue 2026-03-10 08:23:04 EET; 4 months 13 days ago
  systemd: 257.8-1
   CGroup: /
           |-init.scope
           | `-1 /sbin/init
           `-system.slice
             |-NetworkManager.service
             | `-639 /usr/sbin/NetworkManager --no-daemon
             |-cron.service
             | `-667 /usr/sbin/cron -f
             |-ssh.service
             | `-682 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
             `-system-getty.slice
               `-getty@tty1.service
                 `-701 /sbin/agetty -o -p -- \\u --noclear tty1 linux
"""

UNITS = """  UNIT                          LOAD   ACTIVE SUB     DESCRIPTION
  cron.service                  loaded active running Regular background program processing daemon
  dbus.service                  loaded active running D-Bus System Message Bus
  getty@tty1.service            loaded active running Getty on tty1
  NetworkManager.service        loaded active running Network Manager
  rsyslog.service               loaded active running System Logging Service
  ssh.service                   loaded active running OpenBSD Secure Shell server
  systemd-journald.service      loaded active running Journal Service
  systemd-logind.service        loaded active running User Login Management
  systemd-resolved.service      loaded active running Network Name Resolution
  unattended-upgrades.service   loaded active running Unattended Upgrades Shutdown
  systemd-timesyncd.service     loaded active running Network Time Synchronization
  systemd-udevd.service         loaded active running Rule-based Manager for Device Events and Files
  -.mount                       loaded active mounted Root Mount
  boot-efi.mount                loaded active mounted /boot/efi

Legend: LOAD   -> Reflects whether the unit definition was properly loaded.
        ACTIVE -> The high-level unit activation state, i.e. generalization of SUB.
        SUB    -> The low-level unit activation state, values depend on unit type.

14 loaded units listed. Pass --all to see loaded but inactive units, too.
To show all installed unit files use 'systemctl list-unit-files'.
"""

# EL PIE ERA EL DE UN systemd ANTERIOR. Se reconoce por el "LOAD   =" sin
# "Legend:" y sin sangrar las dos lineas siguientes; el 245 lo escribia asi.
# Nuestra maquina declara systemd 257 ---lo dice systemctl --version y lo dice
# el dpkg--- y el 257 pone "Legend: LOAD   ->", indenta las otras dos a ocho
# espacios y anade DOS lineas que no teniamos:
#
#   66 loaded units listed. Pass --all to see loaded but inactive units, too.
#   To show all installed unit files use 'systemctl list-unit-files'.
#
# Medido en un contenedor debian:trixie con systemd arrancado como PID 1.

# La version de respaldo, por si no hubiera listado de dpkg. Es la de
# Debian 13.6.
VERSION_RESPALDO = "257.13-1~deb13u1"

# La linea de caracteristicas de compilacion, copiada del systemd 257 de
# Debian 13. No se inventa ni se recorta: un "+FIDO2" de menos es tan
# comprobable como una version equivocada.
CARACTERISTICAS = (
    "+PAM +AUDIT +SELINUX +APPARMOR +IMA +IPE +SMACK +SECCOMP +GCRYPT -GNUTLS +OPENSSL +ACL +BLKID +CURL +ELFUTILS +FIDO2 +IDN2 -IDN +IPTC +KMOD +LIBCRYPTSETUP +LIBCRYPTSETUP_PLUGINS +LIBFDISK +PCRE2 +PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD +BPF_FRAMEWORK +BTF -XKBCOMMON -UTMP +SYSVINIT +LIBARCHIVE"
)

UNIT_STATUS = {
    "ssh": """* ssh.service - OpenBSD Secure Shell server
     Loaded: loaded (/usr/lib/systemd/system/ssh.service; enabled; preset: enabled)
     Active: active (running) since Tue 2026-03-10 08:23:11 EET; 4 months 13 days ago
       Docs: man:sshd(8)
             man:sshd_config(5)
   Main PID: 682 (sshd)
      Tasks: 1 (limit: 18960)
     Memory: 9.3M
        CPU: 4.120s
     CGroup: /system.slice/ssh.service
             `-682 "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"
""",
    "cron": """* cron.service - Regular background program processing daemon
     Loaded: loaded (/usr/lib/systemd/system/cron.service; enabled; preset: enabled)
     Active: active (running) since Tue 2026-03-10 08:23:10 EET; 4 months 13 days ago
       Docs: man:cron(8)
   Main PID: 667 (cron)
      Tasks: 1 (limit: 18960)
     Memory: 2.0M
     CGroup: /system.slice/cron.service
             `-667 /usr/sbin/cron -f
""",
}


class Command_systemctl(HoneyPotCommand):
    # En la clase, no solo en start(), para que llamar a call() por su cuenta
    # ---como hacen las pruebas--- no se encuentre el atributo sin definir.
    paginar = True
    paginando = False

    def start(self) -> None:
        """Igual que journalctl: si pagina, el comando no puede terminar."""
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

    def call(self) -> None:
        self.paginar = not any(a == "--no-pager" for a in self.args)
        # "systemctl --version" NO ESTABA: le pasabas eso y contestaba con la
        # lista de unidades, que es lo que hacia con cualquier opcion que no
        # conociera. Y es de las primeras cosas que se teclean para saber que
        # sistema hay debajo.
        if any(a in ("--version", "-V") for a in self.args):
            self.version()
            return
        args = [a for a in self.args if not a.startswith("-")]
        if not args or args[0] in ("list-units", "list-unit-files"):
            self._muestra(UNITS)
            return
        sub = args[0]
        if sub == "is-system-running":
            self.write("running\n")
            return
        if sub == "status":
            if len(args) == 1:
                self.write(OVERALL)
                return
            name = args[1].replace(".service", "")
            if name in UNIT_STATUS:
                self.write(UNIT_STATUS[name])
            else:
                self.errorWrite(f"Unit {args[1]}.service could not be found.\n")
            return
        if sub in ("is-active",):
            self.write("active\n")
            return
        if sub in ("is-enabled",):
            self.write("enabled\n")
            return
        # start/stop/restart/enable/disable need privileges
        if sub in ("start", "stop", "restart", "reload", "enable", "disable"):
            if self.protocol.user.username != "root":
                self.errorWrite(
                    "Failed to reload daemon: Interactive authentication required.\n"
                )
            return


    def version(self) -> None:
        """La version sale del listado de dpkg, no escrita aqui.

        Es lo mismo que se hace en ping, sudo y apt: asi "systemctl --version"
        y "dpkg -l systemd" no pueden decir cosas distintas. El paquete es
        "257.13-1~deb13u1"; systemd se nombra por el numero de delante del
        primer punto, y entre parentesis va el del paquete entero.

        La segunda linea es la de caracteristicas de compilacion, copiada del
        systemd 257 de Debian 13.
        """
        try:
            from cowrie.commands.dpkg import datos_de, leer_paquetes

            paquete, _arch = datos_de(leer_paquetes(), "systemd",
                                      por_defecto=(VERSION_RESPALDO, "amd64"))
        except Exception:                                  # noqa: BLE001
            paquete = VERSION_RESPALDO
        limpio = paquete.split(":")[-1]
        self.write("systemd %s (%s)\n" % (limpio.split(".")[0], limpio))
        self.write(CARACTERISTICAS + "\n")


commands["systemctl"] = Command_systemctl
commands["/usr/bin/systemctl"] = Command_systemctl
commands["/bin/systemctl"] = Command_systemctl
