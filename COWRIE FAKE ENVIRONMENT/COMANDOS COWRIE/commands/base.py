# SPDX-FileCopyrightText: 2009-2014 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2014-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# coding=utf-8

from __future__ import annotations

import codecs
import datetime
import getopt
import random
import re
import time
from typing import TYPE_CHECKING, Any

from twisted.internet import error, reactor
from twisted.python import failure, log

from cowrie.core import utils
from cowrie.shell.command import HoneyPotCommand

if TYPE_CHECKING:
    from collections.abc import Callable

commands: dict[str, Callable] = {}


def escribe_fichero(cmd, ruta: str, datos: bytes, modo: int = 33188,
                    uid: int = 0, gid: int = 0) -> bool:
    """Deja un fichero en el sistema de ficheros CON su contenido.

    El nodo por si solo no basta: mkfile solo apunta el tamano, y un fichero
    que aparece en el listado con 200 bytes y sale vacio al leerlo es peor que
    no crearlo. El contenido va a un Artifact y el nodo apunta a el con
    update_realfile, que ademas lo deja capturado en disco como cualquier otra
    muestra.

    Estaba escrito por separado en nano, en "sed -i" y en tee, y cada copia
    aprendio el truco por su cuenta. Aqui esta una vez.
    """
    from cowrie.core.artifact import Artifact
    from cowrie.shell import fs as _fs

    try:
        cmd.fs.mkfile(ruta, uid, gid, len(datos), modo)
        artefacto = Artifact("fichero")
        with artefacto:
            artefacto.write(datos)
        cmd.fs.update_realfile(cmd.fs.getfile(ruta), artefacto.shasumFilename)
    except _fs.FileNotFound:
        return False
    except Exception:                                          # noqa: BLE001
        return False
    return True


class FallaAlAvisar:
    """Un comando que, si escribe en la salida de error, TERMINA MAL.

    Casi ninguno lo hacia. Escribian su queja ---"cat: /noexiste: No such file
    or directory"--- y devolvian CERO, asi que:

        cat fichero || wget URL -O fichero

    se tragaba el respaldo. Y ese patron ---intentar algo y tener un plan B---
    es la mitad de lo que hace un dropper: el atacante ve su guion seguir por
    la rama que no toca y sabe que el shell no le esta contando la verdad.

    Se hereda en vez de tocar el errorWrite de Cowrie a proposito: hay
    comandos que escriben en el error SIN fallar ---un aviso de apt, el
    progreso de wget, el "break" fuera de un bucle--- y esos no deben
    heredarlo. Asi la lista de los que si es explicita y se lee.

    El codigo no siempre es 1: grep y sort dan 2 cuando el fallo es de fichero
    o de uso. Medido en Debian 13.
    """

    CODIGO_DE_FALLO = 1

    def errorWrite(self, data: str) -> None:
        # Solo si no hay uno puesto ya: un comando puede tener su propio
        # codigo ---grep sin coincidencias devuelve 1 sin escribir nada--- y
        # este no debe pisarlo.
        if not getattr(self, "exit_code", 0):
            self.exit_code = self.CODIGO_DE_FALLO
        super().errorWrite(data)                    # type: ignore[misc]

# Fixed boot time (2026-03-10 08:23:00 Europe/Kyiv) so uptime/w stay stable and
# coherent with the ps START dates across container restarts.
IGNIS_BOOT_EPOCH = 1773123780


def formato_uptime(segundos: float) -> str:
    """La duracion tal y como la escribe procps, y en un SOLO sitio.

    Estaba escrita TRES VECES y las tres decian cosas distintas: uptime y w
    usaban el utils.uptime() de Cowrie, que rellena las horas con cero
    ---"02:39"---, y top llevaba su propia copia, que ya rellenaba con espacio
    pero decia "1 days". El de verdad hace esto:

        sprintf(buf, "%d day%s, ", updays, updays != 1 ? "s" : "");
        if (uphours) sprintf(buf, "%2d:%02d", uphours, upminutes);
        else         sprintf(buf, "%d min", upminutes);

    De ahi salen las tres diferencias: la hora va con ESPACIO delante y no con
    cero, el dia en singular no lleva la "s", y en la primera hora no se
    escriben horas sino "45 min" ---que ninguna de las tres copias sabia
    hacer---.

    Medido en un Debian 13.6: " 10:54:24 up  2:39,  0 users, ...".
    """
    total = int(segundos)
    dias, resto = total // 86400, total % 86400
    horas, minutos = resto // 3600, (resto % 3600) // 60
    texto = "%d day%s, " % (dias, "" if dias == 1 else "s") if dias else ""
    if horas:
        return texto + "%2d:%02d" % (horas, minutos)
    return texto + "%d min" % minutos

# El PID del bash de la sesion. Tiene que ser EL MISMO que el PID_LEYENDA de
# COWRIE FAKE ENVIRONMENT/sanitize-pickle.py, porque el /proc/self del pickle
# es un enlace fijo a /proc/<ese numero>. Si no coinciden, un "ls /proc"
# ensena un PID que "ps aux" no conoce. Lo comprueba test_comandos.py.
PID_SESION = 48230


# Los ficheros de /proc que llevan dentro QUIEN es el proceso. Se hornean al
# construir el pickle con los datos de root, y el pickle es el MISMO para
# todas las sesiones: entrando como un usuario normal, "id" y estos ficheros
# daban duenos distintos para el mismo proceso.
_PROC_DEL_PROCESO = ("status", "cgroup", "stat")


def rutas_del_proceso() -> tuple:
    """Las dos formas de nombrar los ficheros del proceso de la sesion.

    /proc/self es un enlace a /proc/<PID_SESION>, o sea el MISMO fichero por
    dos nombres: los dos tienen que contestar igual.
    """
    return tuple("/proc/%s/%s" % (donde, que)
                 for donde in ("self", str(PID_SESION))
                 for que in _PROC_DEL_PROCESO)


def con_dueno_de_sesion(cmd, ruta: str, datos):
    """Pone en esos ficheros el usuario de ESTA sesion, no el de root.

    Va aqui y no en el sistema de ficheros porque el objeto del sistema de
    ficheros lo COMPARTE CowrieServer entre conexiones de la misma IP: un
    envoltorio ahi se quedaria con el usuario de la primera sesion y se lo
    daria a las demas. Cada lector ---cat, grep, head, tail, less, more---
    llama aqui, que es lo unico que sabe quien pregunta.

    Solo toca las lineas que dependen de quien entro; todo lo demas viene del
    pickle tal cual, asi que la plantilla sigue siendo una sola.
    """
    if not datos or ruta not in rutas_del_proceso():
        return datos
    try:
        uid = int(cmd.current_user["uid"])
        gid = int(cmd.current_user["gid"])
    except Exception:                                          # noqa: BLE001
        return datos
    eran_bytes = isinstance(datos, bytes)
    texto = datos.decode("utf-8", "replace") if eran_bytes else datos
    texto = re.sub(r"^Uid:\t.*$", "Uid:\t%d\t%d\t%d\t%d" % ((uid,) * 4),
                   texto, flags=re.M)
    texto = re.sub(r"^Gid:\t.*$", "Gid:\t%d\t%d\t%d\t%d" % ((gid,) * 4),
                   texto, flags=re.M)
    texto = re.sub(r"^Groups:\t.*$", "Groups:\t%d " % gid, texto, flags=re.M)
    texto = texto.replace("/user-0.slice/", "/user-%d.slice/" % uid)
    return texto.encode() if eran_bytes else texto


def _ignis_uptime() -> float:
    return time.time() - IGNIS_BOOT_EPOCH


class Command_whoami(HoneyPotCommand):
    def call(self) -> None:
        self.write(f"{self.protocol.user.username}\n")


commands["/usr/bin/whoami"] = Command_whoami
commands["whoami"] = Command_whoami
commands["/usr/bin/users"] = Command_whoami
commands["users"] = Command_whoami


class Command_help(HoneyPotCommand):
    def call(self) -> None:
        self.write(
            """GNU bash, version 4.2.37(1)-release (x86_64-pc-linux-gnu)
These shell commands are defined internally.  Type `help' to see this list.
Type `help name' to find out more about the function `name'.
Use `info bash' to find out more about the shell in general.
Use `man -k' or `info' to find out more about commands not in this list.

A star (*) next to a name means that the command is disabled.

 job_spec [&]                                                                                   history [-c] [-d offset] [n] or history -anrw [filename] or history -ps arg [arg...]
 (( expression ))                                                                               if COMMANDS; then COMMANDS; [ elif COMMANDS; then COMMANDS; ]... [ else COMMANDS; ] fi
 . filename [arguments]                                                                         jobs [-lnprs] [jobspec ...] or jobs -x command [args]
 :                                                                                              kill [-s sigspec | -n signum | -sigspec] pid | jobspec ... or kill -l [sigspec]
 [ arg... ]                                                                                     let arg [arg ...]
 [[ expression ]]                                                                               local [option] name[=value] ...
 alias [-p] [name[=value] ... ]                                                                 logout [n]
 bg [job_spec ...]                                                                              mapfile [-n count] [-O origin] [-s count] [-t] [-u fd] [-C callback] [-c quantum] [array]
 bind [-lpvsPVS] [-m keymap] [-f filename] [-q name] [-u name] [-r keyseq] [-x keyseq:shell-c>  popd [-n] [+N | -N]
 break [n]                                                                                      printf [-v var] format [arguments]
 builtin [shell-builtin [arg ...]]                                                              pushd [-n] [+N | -N | dir]
 caller [expr]                                                                                  pwd [-LP]
 case WORD in [PATTERN [| PATTERN]...) COMMANDS ;;]... esac                                     read [-ers] [-a array] [-d delim] [-i text] [-n nchars] [-N nchars] [-p prompt] [-t timeout>
 cd [-L|[-P [-e]]] [dir]                                                                        readarray [-n count] [-O origin] [-s count] [-t] [-u fd] [-C callback] [-c quantum] [array]>
 command [-pVv] command [arg ...]                                                               readonly [-aAf] [name[=value] ...] or readonly -p
 compgen [-abcdefgjksuv] [-o option]  [-A action] [-G globpat] [-W wordlist]  [-F function] [>  return [n]
 complete [-abcdefgjksuv] [-pr] [-DE] [-o option] [-A action] [-G globpat] [-W wordlist]  [-F>  select NAME [in WORDS ... ;] do COMMANDS; done
 compopt [-o|+o option] [-DE] [name ...]                                                        set [-abefhkmnptuvxBCHP] [-o option-name] [--] [arg ...]
 continue [n]                                                                                   shift [n]
 coproc [NAME] command [redirections]                                                           shopt [-pqsu] [-o] [optname ...]
 declare [-aAfFgilrtux] [-p] [name[=value] ...]                                                 source filename [arguments]
 dirs [-clpv] [+N] [-N]                                                                         suspend [-f]
 disown [-h] [-ar] [jobspec ...]                                                                test [expr]
 echo [-neE] [arg ...]                                                                          time [-p] pipeline
 enable [-a] [-dnps] [-f filename] [name ...]                                                   times
 eval [arg ...]                                                                                 trap [-lp] [[arg] signal_spec ...]
 exec [-cl] [-a name] [command [arguments ...]] [redirection ...]                               true
 exit [n]                                                                                       type [-afptP] name [name ...]
 export [-fn] [name[=value] ...] or export -p                                                   typeset [-aAfFgilrtux] [-p] name[=value] ...
 false                                                                                          ulimit [-SHacdefilmnpqrstuvx] [limit]
 fc [-e ename] [-lnr] [first] [last] or fc -s [pat=rep] [command]                               umask [-p] [-S] [mode]
 fg [job_spec]                                                                                  unalias [-a] name [name ...]
 for NAME [in WORDS ... ] ; do COMMANDS; done                                                   unset [-f] [-v] [name ...]
 for (( exp1; exp2; exp3 )); do COMMANDS; done                                                  until COMMANDS; do COMMANDS; done
 function name { COMMANDS ; } or name () { COMMANDS ; }                                         variables - Names and meanings of some shell variables
 getopts optstring name [arg]                                                                   wait [id]
 hash [-lr] [-p pathname] [-dt] [name ...]                                                      while COMMANDS; do COMMANDS; done
 help [-dms] [pattern ...]                                                                      { COMMANDS ; }\n"""
        )


commands["help"] = Command_help


class Command_w(HoneyPotCommand):
    def call(self) -> None:
        self.write(
            f" {time.strftime('%H:%M:%S')} up {formato_uptime(_ignis_uptime())},"
            f"  1 user,  load average: 0.00, 0.01, 0.00\n"
        )
        self.write(
            "USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT\n"
        )
        self.write(
            f"{self.protocol.user.username:8s} pts/0    {self.protocol.clientIP[:17].ljust(17)} {time.strftime('%H:%M', time.localtime(self.protocol.logintime))}    0.00s  0.00s  0.00s w\n"
        )


commands["/usr/bin/w"] = Command_w
commands["w"] = Command_w


class Command_who(HoneyPotCommand):
    def call(self) -> None:
        self.write(
            f"{self.protocol.user.username:8s} pts/0        {time.strftime('%Y-%m-%d', time.localtime(self.protocol.logintime))} {time.strftime('%H:%M', time.localtime(self.protocol.logintime))} ({self.protocol.clientIP})\n"
        )


commands["/usr/bin/who"] = Command_who
commands["who"] = Command_who


class Command_echo(HoneyPotCommand):
    def call(self) -> None:
        newline = True
        escape_decode = False

        try:
            optlist, args = getopt.getopt(self.args, "eEn")
            for opt in optlist:
                if opt[0] == "-e":
                    escape_decode = True
                elif opt[0] == "-E":
                    escape_decode = False
                elif opt[0] == "-n":
                    newline = False
        except Exception:
            args = self.args

        try:
            # replace r'\\x' with r'\x'
            string = " ".join(args).replace(r"\\x", r"\x")

            # replace single character escape \x0 with \x00
            string = re.sub(
                r"(?<=\\)x([0-9a-fA-F])(?=\\|\"|\'|\s|$)", r"x0\g<1>", string
            )

            # if the string ends with \c escape, strip it and set newline flag to False
            if string.endswith("\\c"):
                string = string[:-2]
                newline = False

            if newline is True:
                string += "\n"

            if escape_decode:
                data: bytes = codecs.escape_decode(string)[0]
                self.writeBytes(data)
            else:
                self.write(string)

        except ValueError:
            log.msg("echo command received Python incorrect hex escape")


commands["/bin/echo"] = Command_echo
commands["echo"] = Command_echo


_PRINTF_SPEC = re.compile(r"%([-+ 0#]*)(\d+)?(?:\.(\d+))?([diouxXeEfFgGcsb%])")
_PRINTF_ESC = {
    "n": b"\n", "t": b"\t", "r": b"\r", "\\": b"\\", "a": b"\a",
    "b": b"\b", "f": b"\f", "v": b"\v", "0": b"\x00", '"': b'"', "'": b"'",
}


def _printf_render(fmt: str, values: list[str]) -> bytes:
    out = bytearray()
    vi = [0]

    def next_val() -> str:
        if vi[0] < len(values):
            v = values[vi[0]]
            vi[0] += 1
            return v
        vi[0] += 1
        return ""

    first = True
    while first or vi[0] < len(values):
        first = False
        i = 0
        n = len(fmt)
        while i < n:
            ch = fmt[i]
            if ch == "%":
                m = _PRINTF_SPEC.match(fmt, i)
                if not m:
                    out.append(ord("%"))
                    i += 1
                    continue
                flags, width, prec, conv = m.groups()
                i = m.end()
                if conv == "%":
                    out += b"%"
                    continue
                pyspec = "%" + (flags or "") + (width or "") + (("." + prec) if prec else "") + conv
                raw = next_val()
                try:
                    if conv in "diouxX":
                        s = pyspec % (int(raw, 0) if raw else 0)
                    elif conv in "eEfFgG":
                        s = pyspec % (float(raw) if raw else 0.0)
                    elif conv == "c":
                        s = raw[:1]
                    elif conv == "b":
                        s = codecs.escape_decode(raw.encode())[0].decode("latin-1")
                    else:  # s
                        s = pyspec % raw
                    out += s.encode("latin-1", "replace")
                except Exception:
                    out += raw.encode("latin-1", "replace")
            elif ch == "\\" and i + 1 < n:
                nxt = fmt[i + 1]
                if nxt in _PRINTF_ESC:
                    out += _PRINTF_ESC[nxt]
                    i += 2
                    continue
                out.append(ord(ch))
                i += 1
            else:
                out += ch.encode("latin-1", "replace")
                i += 1
        if not values:
            break
    return bytes(out)


class Command_printf(HoneyPotCommand):
    def call(self) -> None:
        args = list(self.args)
        to_var = False
        if len(args) >= 2 and args[0] == "-v":
            to_var = True
            args = args[2:]
        if not args:
            self.errorWrite("printf: usage: printf [-v var] format [arguments]\n")
            return
        rendered = _printf_render(args[0], args[1:])
        # `-v NAME` assigns to a shell variable rather than printing
        if not to_var:
            self.writeBytes(rendered)


commands["/usr/bin/printf"] = Command_printf
commands["printf"] = Command_printf


class Command_clear(HoneyPotCommand):
    def call(self) -> None:
        self.protocol.terminal.reset()


commands["/usr/bin/clear"] = Command_clear
commands["clear"] = Command_clear
commands["/usr/bin/reset"] = Command_clear
commands["reset"] = Command_clear


HOSTNAME_USO = """Usage: hostname [-b] {hostname|-F file}         set host name (from file)
       hostname [-a|-A|-d|-f|-i|-I|-s|-y]       display formatted name
       hostname                                 display host name

       {yp,nis,}domainname {nisdomain|-F file}  set NIS domain name (from file)
       {yp,nis,}domainname                      display NIS domain name

       dnsdomainname                            display dns domain name

       hostname -V|--version|-h|--help          print info and exit

Program name:
       {yp,nis,}domainname=hostname -y
       dnsdomainname=hostname -d

Program options:
    -a, --alias            alias names
    -A, --all-fqdns        all long host names (FQDNs)
    -b, --boot             set default hostname if none available
    -d, --domain           DNS domain name
    -f, --fqdn, --long     long host name (FQDN)
    -F, --file             read host name or NIS domain name from given file
    -i, --ip-address       addresses for the host name
    -I, --all-ip-addresses all addresses for the host
    -s, --short            short host name
    -y, --yp, --nis        NIS/YP domain name

Description:
   This command can get or set the host name or the NIS domain name. You can
   also get the DNS domain or the FQDN (fully qualified domain name).
   Unless you are using bind or NIS for host lookups you can change the
   FQDN (Fully Qualified Domain Name) and the DNS domain name (which is
   part of the FQDN) in the /etc/hosts file.
"""


class Command_hostname(HoneyPotCommand):
    """hostname y sus banderas.

    CUALQUIER ARGUMENTO SE TOMABA POR UN NOMBRE NUEVO. O sea que "hostname -I"
    ---de lo primero que se teclea al reconocer una maquina--- no daba la IP:
    LE PONIA A LA MAQUINA EL NOMBRE "-I", y a partir de ahi el prompt del
    atacante decia "root@-I:~#". No es que faltara una opcion, es que la
    sesion se quedaba con un nombre que ningun sistema tendria y a la vista en
    cada linea.

    La IP sale de ip.py, que es donde ya esta, para que "hostname -I",
    "ip a" e "ifconfig" no puedan decir tres cosas distintas.
    """

    def call(self) -> None:
        opciones = [a for a in self.args if a.startswith("-") and a != "-"]
        nombres = [a for a in self.args if not a.startswith("-")]

        for o in opciones:
            if o in ("-h", "--help"):
                self.write(HOSTNAME_USO)
                return
            if o in ("-V", "--version"):
                self.write("hostname 3.25\n")
                return

        corta = "".join(o[1:] for o in opciones if not o.startswith("--"))
        largas = [o for o in opciones if o.startswith("--")]
        conocidas = "aAbdfiIsy"
        LARGAS = {"--alias": "a", "--all-fqdns": "A", "--boot": "b",
                  "--domain": "d", "--fqdn": "f", "--long": "f",
                  "--ip-address": "i", "--all-ip-addresses": "I",
                  "--short": "s", "--yp": "y", "--nis": "y"}
        for larga in largas:
            if larga not in LARGAS:
                self.errorWrite("hostname: unrecognized option '%s'\n" % larga)
                self.errorWrite(HOSTNAME_USO)
                self.exit_code = 255
                return
            corta += LARGAS[larga]
        for letra in corta:
            if letra not in conocidas:
                self.errorWrite("hostname: invalid option -- '%s'\n" % letra)
                self.errorWrite(HOSTNAME_USO)
                self.exit_code = 255
                return

        if "I" in corta or "i" in corta:
            from cowrie.commands.ip import IP4

            # "-I" deja un espacio detras de cada direccion; "-i" no.
            self.write(IP4 + " \n" if "I" in corta else IP4 + "\n")
            return
        if "d" in corta or "y" in corta:
            # Sin dominio configurado los dos escriben una linea vacia.
            self.write("\n")
            return
        if corta:
            # -a, -A, -f, -s y -b: sin dominio, todas dan el nombre a secas.
            self.write(f"{self.protocol.hostname}\n")
            return

        if not nombres:
            self.write(f"{self.protocol.hostname}\n")
            return
        if self.protocol.user.username == "root":
            self.protocol.hostname = nombres[0]
        else:
            self.write("hostname: you must be root to change the host name\n")


commands["/bin/hostname"] = Command_hostname
commands["hostname"] = Command_hostname


class Command_ps(HoneyPotCommand):
    """ps.

    El formato NO esta inventado: las tres plantillas de abajo se dedujeron de
    un "ps" real de procps en Debian 13 y se comprobaron BYTE A BYTE contra su
    cabecera y contra sus lineas de datos.

    Lo que habia antes rellenaba la CADENA DE FORMATO en vez del valor:

        "%s".ljust(ANCHO - len(valor)) % valor

    El ancho efectivo salia al reves y con valores largos no quedaba ni un
    espacio de separacion. En el senuelo se veia asi:

        admin  745  0.2  1.66  1180000000285000000 ?  Sl  Jul08

    ---el VSZ y el RSS pegados--- y, lo que es peor, la linea se pasaba de 80
    columnas ANTES de llegar a TIME y COMMAND. Como "ps" recorta a la anchura
    del terminal (eso si lo hace el de verdad), el resultado era un "ps aux"
    SIN COLUMNA DE ORDENES. No hay ningun Linux donde eso pase, y es de los
    primeros comandos que ejecuta cualquiera.
    """

    # Verificadas contra procps 4.x en Debian 13.
    FMT_SIMPLE = "%7s %-8s %8s %s"
    FMT_LARGO = "%7s %-8s %-5s %5s %s"
    FMT_USUARIO = "%-10s%6s %4s %4s %6s %5s %-9s%-5s%5s %6s %s"

    CAB_SIMPLE = ("PID", "TTY", "TIME", "CMD")
    CAB_LARGO = ("PID", "TTY", "STAT", "TIME", "COMMAND")
    CAB_USUARIO = ("USER", "PID", "%CPU", "%MEM", "VSZ", "RSS", "TTY",
                   "STAT", "START", "TIME", "COMMAND")

    # Solo se usa si NO hay ps_command_output.json cargado, que en este
    # despliegue no deberia pasar nunca (apartado 3.4.2.10 del README).
    RESERVA = (
        ('root', '1', '0.0', '0.1', '2100', '688', '?', 'Ss', 'Nov06', '0:07', 'init [2]'),
        ('root', '2', '0.0', '0.0', '0', '0', '?', 'S<', 'Nov06', '0:00', '[kthreadd]'),
        ('root', '3', '0.0', '0.0', '0', '0', '?', 'S<', 'Nov06', '0:00', '[migration/0]'),
        ('root', '4', '0.0', '0.0', '0', '0', '?', 'S<', 'Nov06', '0:00', '[ksoftirqd/0]'),
        ('root', '5', '0.0', '0.0', '0', '0', '?', 'S<', 'Nov06', '0:00', '[watchdog/0]'),
        ('root', '6', '0.0', '0.0', '0', '0', '?', 'S<', 'Nov06', '0:17', '[events/0]'),
        ('root', '7', '0.0', '0.0', '0', '0', '?', 'S<', 'Nov06', '0:00', '[khelper]'),
        ('root', '39', '0.0', '0.0', '0', '0', '?', 'S<', 'Nov06', '0:00', '[kblockd/0]'),
        ('root', '41', '0.0', '0.0', '0', '0', '?', 'S<', 'Nov06', '0:00', '[kacpid]'),
        ('root', '42', '0.0', '0.0', '0', '0', '?', 'S<', 'Nov06', '0:00', '[kacpi_notify]'),
        ('root', '170', '0.0', '0.0', '0', '0', '?', 'S<', 'Nov06', '0:00', '[kseriod]'),
        ('root', '207', '0.0', '0.0', '0', '0', '?', 'S', 'Nov06', '0:01', '[pdflush]'),
        ('root', '208', '0.0', '0.0', '0', '0', '?', 'S', 'Nov06', '0:00', '[pdflush]'),
        ('root', '209', '0.0', '0.0', '0', '0', '?', 'S<', 'Nov06', '0:00', '[kswapd0]'),
        ('root', '210', '0.0', '0.0', '0', '0', '?', 'S<', 'Nov06', '0:00', '[aio/0]'),
        ('root', '748', '0.0', '0.0', '0', '0', '?', 'S<', 'Nov06', '0:00', '[ata/0]'),
        ('root', '749', '0.0', '0.0', '0', '0', '?', 'S<', 'Nov06', '0:00', '[ata_aux]'),
        ('root', '929', '0.0', '0.0', '0', '0', '?', 'S<', 'Nov06', '0:00', '[scsi_eh_0]'),
        ('root', '1014', '0.0', '0.0', '0', '0', '?', 'D<', 'Nov06', '0:03', '[kjournald]'),
        ('root', '1087', '0.0', '0.1', '2288', '772', '?', 'S<s', 'Nov06', '0:00', 'udevd --daemon'),
        ('root', '1553', '0.0', '0.0', '0', '0', '?', 'S<', 'Nov06', '0:00', '[kpsmoused]'),
        ('root', '2054', '0.0', '0.2', '28428', '1508', '?', 'Sl', 'Nov06', '0:01', '/usr/sbin/rsyslogd -c3'),
        ('root', '2103', '0.0', '0.2', '2628', '1196', 'tty1', 'Ss', 'Nov06', '0:00', '/bin/login --'),
        ('root', '2105', '0.0', '0.0', '1764', '504', 'tty2', 'Ss+', 'Nov06', '0:00', '/sbin/getty 38400 tty2'),
        ('root', '2107', '0.0', '0.0', '1764', '504', 'tty3', 'Ss+', 'Nov06', '0:00', '/sbin/getty 38400 tty3'),
        ('root', '2109', '0.0', '0.0', '1764', '504', 'tty4', 'Ss+', 'Nov06', '0:00', '/sbin/getty 38400 tty4'),
        ('root', '2110', '0.0', '0.0', '1764', '504', 'tty5', 'Ss+', 'Nov06', '0:00', '/sbin/getty 38400 tty5'),
        ('root', '2112', '0.0', '0.0', '1764', '508', 'tty6', 'Ss+', 'Nov06', '0:00', '/sbin/getty 38400 tty6'),
        ('root', '2133', '0.0', '0.1', '2180', '620', '?', 'S<s', 'Nov06', '0:00', 'dhclient3 -pf /var/run/dhclient.eth0.pid -lf /var/lib/dhcp3/dhclien'),
        ('root', '4969', '0.0', '0.1', '5416', '1024', '?', 'Ss', 'Nov08', '0:00', '@PS@'),
        ('@USER@', '5673', '0.0', '0.2', '2924', '1540', 'pts/0', 'Ss', '04:30', '0:00', '-bash'),
        ('@USER@', '5679', '0.0', '0.1', '2432', '928', 'pts/0', 'R+', '04:32', '0:00', '@PS@'),
    )

    @staticmethod
    def _tiempo(minutos, con_horas=False):
        """El TIME de ps: "M:SS" normalmente, "HH:MM:SS" en el ps a secas."""
        try:
            total = int(round(float(minutos) * 60))
        except (TypeError, ValueError):
            total = 0
        h, resto = divmod(total, 3600)
        m, s = divmod(resto, 60)
        if con_horas:
            return "%02d:%02d:%02d" % (h, m, s)
        return "%d:%02d" % (h * 60 + m, s)

    def _de_json(self, p):
        """Una fila a partir de una entrada de ps_command_output.json.

        VSZ y RSS vienen multiplicados por mil en ese fichero y se publicaban
        en crudo: 172000000 donde un ps escribe 172000.
        """
        return (
            str(p.get("USER", "root")),
            str(p.get("PID", 0)),
            "%.1f" % float(p.get("CPU", 0.0)),
            "%.1f" % float(p.get("MEM", 0.0)),
            str(int(p.get("VSZ", 0)) // 1000),
            str(int(p.get("RSS", 0)) // 1000),
            str(p.get("TTY", "?")),
            str(p.get("STAT", "S")),
            str(p.get("START", "?")),
            str(p.get("TIME", 0.0)),
            str(p.get("COMMAND", "")),
        )

    def _sesion(self, user, args):
        """Los procesos de ESTA sesion, para el usuario que esta dentro.

        El ps_command_output.json ya NO trae una sesion escrita a mano. La
        traia ---la de alyosha, con su sshd, su bash y hasta su "ps aux"--- y
        eso daba dos sesiones a la vez en el MISMO pts/0, que no puede ser, y
        un "-bash" de alyosha cuando quien estaba dentro era root. Ademas
        contradecia a "who", que solo ensena al que ha entrado.

        Los PID van en las decenas de miles porque la maquina lleva meses
        levantada: unos PID de tres cifras para algo que acaba de arrancar
        serian mas bajos que los de los servicios de marzo.

        La forma de la sesion depende de por donde se entro, y esta comprobada
        en un Debian 13 con openbsd-inetd e inetutils-telnetd:

          - Por SSH, OpenSSH 10 parte el proceso en dos: "sshd-session: user
            [priv]" como root y "sshd-session: user@pts/0" como el usuario.
          - Por telnet es "telnetd" a secas, como root y con TTY "?", colgando
            del inetd que lo genero.

        En las dos vias, pam_systemd arranca un "systemd --user" y su ayudante
        "(sd-pam)". Son los que explican las variables XDG_ del entorno.
        """
        # Los PID NO son al azar: el /proc/self del pickle es un enlace fijo a
        # /proc/48230, y ese numero tiene que ser el del bash de la sesion o
        # "ls /proc" ensena un PID que "ps aux" no conoce. El saneador lo llama
        # PID_LEYENDA y hay una prueba que comprueba que los dos coinciden.
        base = PID_SESION
        ahora = time.strftime("%H:%M")
        por_telnet = "Telnet" in type(self.protocol).__name__

        def fila(usuario, pid, vsz, rss, tty, stat, orden):
            return (usuario, str(pid), "0.0", "0.0", str(vsz), str(rss),
                    tty, stat, ahora, "0.0", orden)

        filas = []
        if por_telnet:
            filas.append(fila("root", base - 17, 11776, 2852, "?", "Ss",
                              "telnetd"))
        else:
            filas.append(fila("root", base - 17, 17200, 12400, "?", "Ss",
                              "sshd-session: %s [priv]" % user))
            filas.append(fila(user, base - 11, 17400, 8200, "?", "S",
                              "sshd-session: %s@pts/0" % user))
        filas.append(fila(user, base - 10, 21000, 10200, "?", "Ss",
                          "/lib/systemd/systemd --user"))
        filas.append(fila(user, base - 9, 170000, 4100, "?", "S", "(sd-pam)"))
        filas.append(fila(user, base, 9400, 5200, "pts/0", "Ss", "-bash"))
        filas.append(fila(user, base + 61, 21500, 3600, "pts/0", "R+",
                          ("ps %s" % args).strip()))
        return filas

    # El formato de "-f", medido columna a columna contra procps en Debian 13.
    FMT_COMPLETO = "%-8s%8s%8s%3s %5s %-8s%9s %s"
    CAB_COMPLETO = ("UID", "PID", "PPID", "C", "STIME", "TTY", "TIME", "CMD")

    def _padre_de(self, fila) -> str:
        """El PPID, que la tabla de procesos no trae.

        No se inventa uno por fila: se sigue el arbol que ya cuenta el resto
        del senuelo. El 1 es de init y no tiene padre; los hilos del nucleo
        ---los que van entre corchetes--- cuelgan de kthreadd, que es el 2; y
        lo demas cuelga de init, que es lo que pasa en una maquina con systemd.
        Las lineas de la sesion son la excepcion y las pone _sesion().
        """
        pid, orden = fila[1], fila[10]
        if pid == "1":
            return "0"
        if orden.startswith("["):
            return "1" if pid == "2" else "2"
        return "1"

    def call(self) -> None:
        user = self.protocol.user.username
        # LAS OPCIONES CON GUION NO SE MIRABAN. Solo se leia el PRIMER
        # argumento y sus letras al estilo BSD, asi que "ps -ef" ---que es la
        # otra forma de teclearlo, tan comun como "ps aux"--- no encontraba ni
        # "a" ni "x" ni "u": filtraba por usuario Y por terminal y no quedaba
        # ni una linea. El atacante veia una cabecera sola.
        args = self.args[0].strip() if self.args else ""
        unix = ""
        solo_pid = None
        siguiente_es_pid = False
        for a in self.args:
            if siguiente_es_pid:
                solo_pid = a
                siguiente_es_pid = False
                continue
            if a.startswith("-") and len(a) > 1:
                letras = a[1:]
                if "p" in letras:
                    trozo = letras.split("p", 1)[1]
                    if trozo:
                        solo_pid = trozo
                    else:
                        siguiente_es_pid = True
                    letras = letras.split("p", 1)[0]
                unix += letras
        # "-e" es "todos los procesos". NO se mete como "ax" en args: eso
        # ademas cambiaria el formato, y "ps -e" usa el corto ---PID TTY TIME
        # CMD--- igual que "ps" a secas.
        todos = "e" in unix or "A" in unix
        completo = "f" in unix or "F" in unix
        if "u" in unix and not completo:
            args += "u"

        procesos = getattr(self.protocol.user.server, "process", None)
        if procesos:
            filas = [self._de_json(p) for p in procesos]
            filas += self._sesion(user, args)
        else:
            filas = [tuple(f) for f in self.RESERVA]

        simple = "u" not in args and "a" not in args and "x" not in args

        # Las columnas numericas se ensanchan para TODAS las filas si una sola
        # lo necesita, que es lo que hace ps de verdad. Sin esto, la fila del
        # node ---VSZ de siete cifras--- corria una columna a la derecha y solo
        # esa: unas columnas desalineadas en un ps es de lo que mas canta.
        visibles = [f for f in filas
                    if (todos or "a" in args or f[0] == user)
                    and (todos or "a" in args or "x" in args
                         or f[6] == "pts/0")]

        def ancho(indice, minimo):
            return max([minimo] + [len(f[indice]) for f in visibles])

        w_pid = ancho(1, 6)
        w_vsz = ancho(4, 6)
        w_rss = ancho(5, 5)
        fmt_usuario = ("%-10s%" + str(w_pid) + "s %4s %4s %" + str(w_vsz)
                       + "s %" + str(w_rss) + "s %-9s%-5s%5s %6s %s")
        fmt_largo = "%" + str(w_pid + 1) + "s %-8s %-5s %5s %s"
        fmt_simple = "%" + str(w_pid + 1) + "s %-8s %8s %s"

        salida = []
        if completo:
            salida.append(self.FMT_COMPLETO % self.CAB_COMPLETO)
        elif simple:
            salida.append(fmt_simple % self.CAB_SIMPLE)
        elif "u" in args:
            salida.append(fmt_usuario % self.CAB_USUARIO)
        else:
            salida.append(fmt_largo % self.CAB_LARGO)

        for f in filas:
            usuario, pid, cpu, mem, vsz, rss, tty, stat, inicio, tiempo, orden = f
            if solo_pid is not None and pid != solo_pid:
                continue
            if solo_pid is None and not todos and "a" not in args \
                    and usuario != user:
                continue
            if solo_pid is None and not todos and "a" not in args \
                    and "x" not in args and tty != "pts/0":
                continue
            if completo:
                salida.append(self.FMT_COMPLETO % (
                    usuario, pid, self._padre_de(f), "0", inicio, tty,
                    self._tiempo(tiempo, con_horas=True), orden))
            elif simple:
                salida.append(fmt_simple % (
                    pid, tty, self._tiempo(tiempo, con_horas=True), orden))
            elif "u" in args:
                salida.append(fmt_usuario % (
                    usuario, pid, cpu, mem, vsz, rss, tty, stat, inicio,
                    self._tiempo(tiempo), orden))
            else:
                salida.append(fmt_largo % (
                    pid, tty, stat, self._tiempo(tiempo), orden))

        # ps recorta a la anchura del terminal salvo con "w". Esto SI lo hace
        # el de verdad, y por eso se conserva.
        if "w" not in args:
            try:
                ancho = int(self.environ.get("COLUMNS", 80))
            except (TypeError, ValueError):
                ancho = 80
            salida = [l[:ancho] for l in salida]
        self.write("\n".join(salida) + "\n")



commands["/bin/ps"] = Command_ps
commands["ps"] = Command_ps


class Command_id(HoneyPotCommand):
    """id. Antes ignoraba TODAS sus opciones.

    "id -u" es de lo primero que teclea un guion para saber si es root, y
    contestaba la linea entera ---"uid=0(root) gid=0(root) groups=0(root)"---
    en vez de un "0". Cualquier comparacion con eso falla, asi que el guion
    tomaba la rama de "no soy root" siendo root.

    Los grupos salen de /etc/passwd y /etc/group del propio senuelo, no del
    objeto de la sesion: asi "id" y "cat /etc/group" no pueden contar cosas
    distintas. La leyenda mete a alyosha en sudo, y sin leer el fichero eso
    no aparecia por ningun lado.
    """

    def _fichero(self, ruta: str) -> list[str]:
        try:
            return self.fs.file_contents(ruta).decode(
                "utf-8", "replace").split("\n")
        except Exception:                                      # noqa: BLE001
            return []

    def _usuario(self, nombre: str | None):
        """(nombre, uid, gid) del usuario pedido, o None si no existe."""
        sesion = self.protocol.user
        for linea in self._fichero("/etc/passwd"):
            campos = linea.split(":")
            if len(campos) < 4:
                continue
            if nombre is None:
                if campos[0] == getattr(sesion, "username", ""):
                    return campos[0], int(campos[2]), int(campos[3])
            elif campos[0] == nombre or campos[2] == nombre:
                return campos[0], int(campos[2]), int(campos[3])
        if nombre is None:
            return (getattr(sesion, "username", "root"),
                    int(getattr(sesion, "uid", 0) or 0),
                    int(getattr(sesion, "gid", 0) or 0))
        return None

    def _grupos(self, nombre: str, gid: int) -> list:
        """[(gid, nombre)] con el principal primero, como los escribe id."""
        por_gid = {}
        extra = []
        for linea in self._fichero("/etc/group"):
            campos = linea.split(":")
            if len(campos) < 4:
                continue
            try:
                g = int(campos[2])
            except ValueError:
                continue
            por_gid[g] = campos[0]
            if nombre and nombre in campos[3].split(","):
                extra.append((g, campos[0]))
        salida = [(gid, por_gid.get(gid, nombre))]
        salida += [g for g in extra if g[0] != gid]
        return salida

    def call(self) -> None:
        pide_uid = pide_gid = pide_grupos = solo_nombres = False
        sueltos = []
        for a in self.args:
            if a.startswith("-") and len(a) > 1 and not a.startswith("--"):
                for letra in a[1:]:
                    if letra == "u":
                        pide_uid = True
                    elif letra == "g":
                        pide_gid = True
                    elif letra == "G":
                        pide_grupos = True
                    elif letra == "n":
                        solo_nombres = True
                    elif letra == "r":
                        pass          # real y efectivo son lo mismo aqui
            elif not a.startswith("-"):
                sueltos.append(a)

        datos = self._usuario(sueltos[0] if sueltos else None)
        if datos is None:
            self.errorWrite("id: '%s': no such user\n" % sueltos[0])
            self.exit_code = 1
            return
        nombre, uid, gid = datos
        grupos = self._grupos(nombre, gid)

        if solo_nombres and not (pide_uid or pide_gid or pide_grupos):
            self.errorWrite("id: printing only names or real IDs requires "
                            "-u, -g, or -G\n")
            self.exit_code = 1
            return
        if pide_uid:
            self.write("%s\n" % (nombre if solo_nombres else uid))
            return
        if pide_gid:
            self.write("%s\n" % (grupos[0][1] if solo_nombres else gid))
            return
        if pide_grupos:
            self.write(" ".join(str(g[1] if solo_nombres else g[0])
                                for g in grupos) + "\n")
            return
        self.write("uid=%d(%s) gid=%d(%s) groups=%s\n"
                   % (uid, nombre, gid, grupos[0][1],
                      ",".join("%d(%s)" % g for g in grupos)))


commands["/usr/bin/id"] = Command_id
commands["id"] = Command_id


class Command_passwd(HoneyPotCommand):
    callbacks: list[Callable]
    passwd: str | None

    def start(self) -> None:
        self.write("Enter new UNIX password: ")
        self.protocol.password_input = True
        self.callbacks = [self.ask_again, self.finish]
        self.passwd = None

    def ask_again(self, line: str) -> None:
        self.passwd = line
        self.write("Retype new UNIX password: ")

    def finish(self, line: str) -> None:
        self.protocol.password_input = False

        if line != self.passwd or self.passwd == "*":
            self.write("Sorry, passwords do not match\n")
        else:
            self.write("passwd: password updated successfully\n")
        self.exit()

    def lineReceived(self, line: str) -> None:
        log.msg(
            eventid="cowrie.command.success",
            realm="passwd",
            input=line,
            format="INPUT (%(realm)s): %(input)s",
        )
        self.password = line.strip()
        self.callbacks.pop(0)(line)


commands["/usr/bin/passwd"] = Command_passwd
commands["passwd"] = Command_passwd


class Command_su(HoneyPotCommand):
    """
    su: pide contrasena (oculta). Si es correcta (contra userdb.txt) CAMBIA de
    identidad (username/uid/gid/home + prompt) y guarda la anterior en una pila
    (proto._su_stack) para que 'exit'/'logout' vuelvan al usuario previo.
    Contrasena incorrecta -> Authentication failure. Usuario inexistente ->
    'does not exist' sin pedir password.
    """

    def start(self) -> None:
        self.login_shell = any(a in ("-", "-l", "--login") for a in self.args)
        args = [a for a in self.args if not a.startswith("-")]
        self.target = args[0] if args else "root"
        try:
            from cowrie.shell.pwd import Passwd

            Passwd().getpwnam(self.target)
        except Exception:
            self.write(
                f"su: user {self.target} does not exist or the user entry does "
                "not contain all the required fields\n"
            )
            self.exit()
            return
        self.write("Password: ")
        self.protocol.password_input = True
        self.callbacks = [self.finish]

    def finish(self, line: str) -> None:
        self.protocol.password_input = False
        from cowrie.core.auth import UserDB
        from cowrie.shell.pwd import Passwd

        ip = getattr(self.protocol, "clientIP", "0.0.0.0")
        try:
            ok = bool(UserDB().checklogin(self.target.encode(), line.encode(), ip))
        except Exception:
            ok = False
        if not ok:
            self.write("su: Authentication failure\n")
            self.exit()
            return
        try:
            pw = Passwd().getpwnam(self.target)
        except Exception:
            self.write("su: Authentication failure\n")
            self.exit()
            return

        proto = self.protocol
        stack = getattr(proto, "_su_stack", None)
        if stack is None:
            stack = proto._su_stack = []
        cur_home = None
        for obj in (proto.user, getattr(proto.user, "avatar", None)):
            if obj is not None and hasattr(obj, "home"):
                cur_home = obj.home
        stack.append(
            (proto.user.username, proto.user.uid, proto.user.gid, cur_home, proto.cwd)
        )
        for obj in (proto.user, getattr(proto.user, "avatar", None)):
            if obj is None:
                continue
            for attr, val in (
                ("username", self.target),
                ("uid", pw["pw_uid"]),
                ("gid", pw["pw_gid"]),
                ("home", pw["pw_dir"]),
            ):
                try:
                    setattr(obj, attr, val)
                except Exception:
                    pass
        if self.login_shell and self.fs.exists(pw["pw_dir"]):
            proto.cwd = pw["pw_dir"]
        self.exit()

    def lineReceived(self, line: str) -> None:
        log.msg(
            eventid="cowrie.command.input",
            realm="su",
            input=line,
            format="INPUT (%(realm)s): %(input)s",
        )
        if getattr(self, "callbacks", None):
            self.callbacks.pop(0)(line)


commands["/bin/su"] = Command_su
commands["/usr/bin/su"] = Command_su
commands["su"] = Command_su


class Command_shutdown(HoneyPotCommand):
    def start(self) -> None:
        if self.args and self.args[0].strip().count("--help"):
            output = [
                "Usage:     shutdown [-akrhHPfnc] [-t secs] time [warning message]",
                "-a:      use /etc/shutdown.allow ",
                "-k:      don't really shutdown, only warn. ",
                "-r:      reboot after shutdown. ",
                "-h:      halt after shutdown. ",
                "-P:      halt action is to turn off power. ",
                "-H:      halt action is to just halt. ",
                "-f:      do a 'fast' reboot (skip fsck). ",
                "-F:      Force fsck on reboot. ",
                '-n:      do not go through "init" but go down real fast. ',
                "-c:      cancel a running shutdown. ",
                "-t secs: delay between warning and kill signal. ",
                '** the "time" argument is mandatory! (try "now") **',
            ]
            for line in output:
                self.write(f"{line}\n")
            self.exit()
        elif (
            len(self.args) > 1
            and self.args[0].strip().count("-h")
            and self.args[1].strip().count("now")
        ):
            self.write("\n")
            self.write(
                f"Broadcast message from root@{self.protocol.hostname} (pts/0) ({time.ctime()}):\n"
            )
            self.write("\n")
            self.write("The system is going down for maintenance NOW!\n")
            reactor.callLater(3, self.finish)
        elif (
            len(self.args) > 1
            and self.args[0].strip().count("-r")
            and self.args[1].strip().count("now")
        ):
            self.write("\n")
            self.write(
                f"Broadcast message from root@{self.protocol.hostname} (pts/0) ({time.ctime()}):\n"
            )
            self.write("\n")
            self.write("The system is going down for reboot NOW!\n")
            reactor.callLater(3, self.finish)
        else:
            self.write("Try `shutdown --help' for more information.\n")
            self.exit()

    def finish(self) -> None:
        stat = failure.Failure(error.ProcessDone(status=""))
        self.protocol.terminal.transport.processEnded(stat)


commands["/sbin/shutdown"] = Command_shutdown
commands["shutdown"] = Command_shutdown
commands["/sbin/poweroff"] = Command_shutdown
commands["poweroff"] = Command_shutdown
commands["/sbin/halt"] = Command_shutdown
commands["halt"] = Command_shutdown


class Command_reboot(HoneyPotCommand):
    def start(self) -> None:
        self.write("\n")
        self.write(
            f"Broadcast message from root@{self.protocol.hostname} (pts/0) ({time.ctime()}):\n\n"
        )
        self.write("The system is going down for reboot NOW!\n")
        reactor.callLater(3, self.finish)

    def finish(self) -> None:
        stat = failure.Failure(error.ProcessDone(status=""))
        self.protocol.terminal.transport.processEnded(stat)


commands["/sbin/reboot"] = Command_reboot
commands["reboot"] = Command_reboot


class Command_history(HoneyPotCommand):
    """El historial de la sesion, con el formato de bash.

    El numero va a la derecha en cinco huecos y luego DOS espacios ---"    1  
    orden"---, medido contra un bash 5.2. Con un ancho distinto, un guion que
    corte por columnas saca basura.
    """

    def call(self) -> None:
        try:
            lineas = self.protocol.historyLines
        except AttributeError:
            # Shell no interactivo: no hay historial que ensenar.
            return

        cuantas = None
        for arg in self.args:
            if arg == "-c":
                self.protocol.historyLines = []
                self.protocol.historyPosition = 0
                return
            if arg in ("-w", "-a", "-r", "-n", "-p", "-s"):
                # Escribir o releer el fichero: no hay nada que hacer y no
                # escriben nada.
                return
            if arg.startswith("-"):
                continue
            if not arg.lstrip("+-").isdigit():
                self.errorWrite(
                    "-bash: history: %s: numeric argument required\n" % arg)
                self.exit_code = 1
                return
            cuantas = int(arg)

        primero = 1
        if cuantas is not None:
            primero = max(1, len(lineas) - cuantas + 1)
        for numero, linea in enumerate(lineas, 1):
            if numero < primero:
                continue
            if isinstance(linea, bytes):
                linea = linea.decode("utf-8", "replace")
            self.write("%5d  %s\n" % (numero, linea))


commands["history"] = Command_history


class Command_date(HoneyPotCommand):
    def call(self) -> None:
        use_utc = False
        fmt = None
        for a in self.args:
            if a in ("-u", "--utc", "--universal"):
                use_utc = True
            elif a.startswith("+"):
                fmt = a[1:]
            elif a.startswith("-"):
                # -d/-r/-s etc. not emulated; ignore flag, keep going
                continue
        now = time.time()
        tm = time.gmtime(now) if use_utc else time.localtime(now)
        if fmt is None:
            zone = "UTC" if use_utc else (time.strftime("%Z", tm) or "UTC")
            self.write(time.strftime(f"%a %b %e %H:%M:%S {zone} %Y", tm) + "\n")
            return
        out = fmt.replace("%s", str(int(now))).replace("%N", "000000000")
        try:
            out = time.strftime(out, tm)
        except Exception:
            pass
        self.write(out + "\n")


commands["/bin/date"] = Command_date
commands["date"] = Command_date


class Command_true(HoneyPotCommand):
    def call(self) -> None:
        self.exit_code = 0


class Command_false(HoneyPotCommand):
    """El unico comando cuyo trabajo ES fallar.

    Lo dice explicito y no se apoya en el apano que habia en honeypot.py
    ---"last_status = 1 si el comando se llama false"---, que era el unico
    codigo de salida de verdad en todo el shell. Desde que cada comando pone
    el suyo y resume() lo lleva a last_status, este tiene que ponerlo como
    los demas o el puente lo dejaria en 0.
    """

    def call(self) -> None:
        self.exit_code = 1


commands["true"] = Command_true
commands["/bin/true"] = Command_true
commands[":"] = Command_true
commands["false"] = Command_false
commands["/bin/false"] = Command_false


class Command_yes(HoneyPotCommand):
    scheduled: Any

    def start(self) -> None:
        self.y()

    def y(self) -> None:
        if self.args:
            self.write(f"{' '.join(self.args)}\n")
        else:
            self.write("y\n")
        self.scheduled = reactor.callLater(0.01, self.y)

    def handle_CTRL_C(self) -> None:
        self.scheduled.cancel()
        self.exit()


commands["/usr/bin/yes"] = Command_yes
commands["yes"] = Command_yes


class Command_php(HoneyPotCommand):
    HELP = (
        "Usage: php [options] [-f] <file> [--] [args...]\n"
        "       php [options] -r <code> [--] [args...]\n"
        "       php [options] [-B <begin_code>] -R <code> [-E <end_code>] [--] [args...]\n"
        "       php [options] [-B <begin_code>] -F <file> [-E <end_code>] [--] [args...]\n"
        "       php [options] -- [args...]\n"
        "       php [options] -a\n"
        "\n"
        "  -a               Run interactively\n"
        "  -c <path>|<file> Look for php.ini file in this directory\n"
        "  -n               No php.ini file will be used\n"
        "  -d foo[=bar]     Define INI entry foo with value 'bar'\n"
        "  -e               Generate extended information for debugger/profiler\n"
        "  -f <file>        Parse and execute <file>.\n"
        "  -h               This help\n"
        "  -i               PHP information\n"
        "  -l               Syntax check only (lint)\n"
        "  -m               Show compiled in modules\n"
        "  -r <code>        Run PHP <code> without using script tags <?..?>\n"
        "  -B <begin_code>  Run PHP <begin_code> before processing input lines\n"
        "  -R <code>        Run PHP <code> for every input line\n"
        "  -F <file>        Parse and execute <file> for every input line\n"
        "  -E <end_code>    Run PHP <end_code> after processing all input lines\n"
        "  -H               Hide any passed arguments from external tools.\n"
        "  -s               Output HTML syntax highlighted source.\n"
        "  -v               Version number\n"
        "  -w               Output source with stripped comments and whitespace.\n"
        "  -z <file>        Load Zend extension <file>.\n"
        "\n"
        "  args...          Arguments passed to script. Use -- args when first argument\n"
        "                   starts with - or script is read from stdin\n"
        "\n"
        "  --ini            Show configuration file names\n"
        "\n"
        "  --rf <name>      Show information about function <name>.\n"
        "  --rc <name>      Show information about class <name>.\n"
        "  --re <name>      Show information about extension <name>.\n"
        "  --ri <name>      Show configuration for extension <name>.\n"
        "\n"
    )

    VERSION = "PHP 5.3.5 (cli)\nCopyright (c) 1997-2010 The PHP Group\n"

    def start(self) -> None:
        if self.args:
            if self.args[0] == "-v":
                self.write(Command_php.VERSION)
            elif self.args[0] == "-h":
                self.write(Command_php.HELP)
            self.exit()

    def lineReceived(self, line: str) -> None:
        log.msg(
            eventid="cowrie.command.success",
            realm="php",
            input=line,
            format="INPUT (%(realm)s): %(input)s",
        )

    def eofReceived(self) -> None:
        self.exit()


commands["/usr/bin/php"] = Command_php
commands["php"] = Command_php


# El orden en que lsattr pinta las banderas, y son VEINTIDOS huecos. No esta
# adivinado: se midio poniendolas una a una con "chattr +X" en un contenedor
# con CAP_LINUX_IMMUTABLE y leyendo donde caia cada letra. La "e" ---extent
# format, que lleva cualquier fichero de ext4--- va SIEMPRE puesta, y por eso
# un lsattr normal contesta "--------------e-------".
BANDERAS_LSATTR = "suSDiadAcEjItTeFCNPVx?"
BANDERA_SIEMPRE = "e"

CHATTR_USO = ("Usage: chattr [-RVf] [-+=aAcCdDeijPsStTuFx] [-p project]"
              " [-v version] files...\n")


class Command_chattr(FallaAlAvisar, HoneyPotCommand):
    """Pone y quita banderas, y las GUARDA.

    Antes solo sabia quejarse si el fichero no existia ---y por la salida
    normal, no por la de error, y devolviendo cero---. Lo demas se lo tragaba
    sin efecto, asi que un "chattr +i" seguido de un "lsattr" se contradecia:
    el atacante protege su implante y el sistema dice que no hay ninguna
    bandera puesta. Es de lo primero que hace quien deja algo en /tmp.

    Las banderas viven en el protocolo, o sea que duran lo que la sesion. En
    una maquina de verdad durarian mas; aqui no hay donde guardarlas sin
    tocar el pickle, y una sesion es justo lo que ve quien lo comprueba.
    """

    def call(self) -> None:
        modos = [a for a in self.args
                 if a[:1] in "+-=" and len(a) > 1 and not a[1:].isdigit()]
        ficheros = [a for a in self.args if a not in modos
                    and not a.startswith("-")]
        if not modos or not ficheros:
            self.errorWrite(CHATTR_USO)
            return

        guardadas = getattr(self.protocol, "atributos", None)
        if guardadas is None:
            guardadas = self.protocol.atributos = {}

        for nombre in ficheros:
            ruta = self.fs.resolve_path(nombre, self.protocol.cwd)
            if not self.fs.exists(ruta):
                self.errorWrite(
                    "chattr: No such file or directory while trying to stat %s\n"
                    % nombre)
                continue
            puestas = set(guardadas.get(ruta, ""))
            for modo in modos:
                letras = set(modo[1:])
                if modo[0] == "+":
                    puestas |= letras
                elif modo[0] == "-":
                    puestas -= letras
                else:
                    puestas = letras
            guardadas[ruta] = "".join(sorted(puestas))
        # Y no escribe nada: chattr es mudo cuando le sale bien.


class Command_lsattr(FallaAlAvisar, HoneyPotCommand):
    """Ensena las banderas. No existia, y el sistema de ficheros lo declara."""

    def call(self) -> None:
        guardadas = getattr(self.protocol, "atributos", {})
        nombres = [a for a in self.args if not a.startswith("-")] \
            or [self.protocol.cwd]
        solo_directorio = "-d" in self.args

        for nombre in nombres:
            ruta = self.fs.resolve_path(nombre, self.protocol.cwd)
            if not self.fs.exists(ruta):
                self.errorWrite(
                    "lsattr: No such file or directory while trying to stat %s\n"
                    % nombre)
                continue
            # UN DIRECTORIO SE LISTA POR DENTRO, salvo con "-d". Y el
            # prefijo es el que se escribio: "lsattr /etc" contesta
            # "/etc/passwd" y "lsattr" a secas contesta "./passwd". Medido.
            if self.fs.isdir(ruta) and not solo_directorio:
                from cowrie.shell import fs as _fs

                prefijo = "." if not self.args else nombre.rstrip("/")
                for hijo in self.fs.get_path(ruta):
                    self.write("%s %s/%s\n"
                               % (self._pinta(
                                   guardadas, ruta + "/" + hijo[_fs.A_NAME]),
                                  prefijo, hijo[_fs.A_NAME]))
                continue
            self.write("%s %s\n" % (self._pinta(guardadas, ruta), nombre))

    @staticmethod
    def _pinta(guardadas: dict, ruta: str) -> str:
        puestas = set(guardadas.get(ruta, "")) | {BANDERA_SIEMPRE}
        return "".join(c if c in puestas else "-" for c in BANDERAS_LSATTR)


commands["/usr/bin/chattr"] = Command_chattr
commands["chattr"] = Command_chattr
commands["/usr/bin/lsattr"] = Command_lsattr
commands["lsattr"] = Command_lsattr


# Caracteres que bash NO necesita entrecomillar al listar una variable.
_SIN_COMILLAS = re.compile(r"^[A-Za-z0-9_@%+=:,./-]*$")


class Command_set(HoneyPotCommand):
    """Lista variables de shell y exportadas, como "set" de bash.

    Bash ENTRECOMILLA los valores que lo necesitan, y por eso un "set" real
    escribe BASH_VERSION='5.2.37(1)-release' (los parentesis) y PS2='> ' (el
    espacio final, que si no se pierde de vista). Escribirlos en crudo, como
    hacia Cowrie, es un formato que ningun bash produce.

    Las de tipo array salen tal cual: DIRSTACK=() no lleva comillas.
    """

    def call(self) -> None:
        # "set -- a b c" CAMBIA LOS PARAMETROS POSICIONALES, que es para lo
        # que se usa en un guion de verdad. Se mira antes que las opciones
        # porque "--" empieza por "-" y caia en la rama de las opciones: los
        # argumentos se perdian y "$#" seguia valiendo 0.
        if "--" in self.args:
            corte = self.args.index("--")
            self.protocol.posicionales = list(self.args[corte + 1:])
            return
        # "set -e", "set -x", "set +u"... NO listan nada: fijan una opcion del
        # shell y se callan. Listar solo lo hace "set" a secas. El de antes
        # volcaba las cincuenta y pico variables ante cualquier cosa, y un
        # "set -e" al principio de un guion ---que lo lleva casi cualquiera---
        # llenaba la pantalla del atacante con el entorno entero.
        if any(a.startswith(("-", "+")) for a in self.args):
            # "-x" enciende el rastro y "+x" lo apaga: bash escribe cada
            # orden con un "+ " delante antes de ejecutarla. Lo pinta
            # runCommand, que es por donde pasan todas.
            for a in self.args:
                if a.startswith("-") and "x" in a[1:]:
                    self.protocol._xtrace = True
                elif a.startswith("+") and "x" in a[1:]:
                    self.protocol._xtrace = False
            return
        if self.args:
            # "set a b c", sin el "--": tambien son posicionales.
            self.protocol.posicionales = list(self.args)
            return
        for nombre in sorted(self.environ):
            self.write(f"{nombre}={self._cita(self.environ[nombre])}\n")

    @staticmethod
    def _cita(valor: str) -> str:
        if valor.startswith("(") and valor.endswith(")"):
            return valor
        if _SIN_COMILLAS.match(valor):
            return valor
        return "'" + valor.replace("'", "'\\''") + "'"


commands["set"] = Command_set


class Command_export(HoneyPotCommand):
    """
    Mark shell variables for export so they appear in the environment of
    child processes. With no operands, list the exported variables.
    """

    def call(self) -> None:
        args = [a for a in self.args if a != "-p"]
        if not args:
            for name in sorted(self.exported):
                self.write(f'declare -x {name}="{self.environ.get(name, "")}"\n')
            return
        for arg in args:
            if "=" in arg:
                key, val = arg.split("=", 1)
                self.environ[key] = val
                self.exported.add(key)
            else:
                self.exported.add(arg)


commands["export"] = Command_export


class Command_unset(HoneyPotCommand):
    """
    Remove variables from both the shell and the exported environment.
    """

    def call(self) -> None:
        for arg in self.args:
            if arg.startswith("-"):
                continue
            self.environ.pop(arg, None)
            self.exported.discard(arg)


commands["unset"] = Command_unset


class Command_nop(HoneyPotCommand):
    def call(self) -> None:
        pass


commands["umask"] = Command_nop
commands["alias"] = Command_nop
commands["jobs"] = Command_nop
commands["kill"] = Command_nop
commands["/bin/kill"] = Command_nop
commands["/bin/pkill"] = Command_nop
commands["/bin/killall"] = Command_nop
commands["/bin/killall5"] = Command_nop
commands["/bin/su"] = Command_su
commands["su"] = Command_su
commands["/bin/chown"] = Command_nop
commands["chown"] = Command_nop
commands["/bin/chgrp"] = Command_nop
commands["chgrp"] = Command_nop
# ":" NO va aqui: ya lo sirve Command_true unas lineas mas arriba, que es el
# que dice lo que hace ---devolver cero---. Registrarlo otra vez como no-op
# dejaba muerto al primero. Da lo mismo en la practica, pero es exactamente la
# forma en que se colaron los fallos de "eval" y de "history": dos registros
# del mismo nombre y gana el ultimo.
commands["do"] = Command_nop
commands["done"] = Command_nop
