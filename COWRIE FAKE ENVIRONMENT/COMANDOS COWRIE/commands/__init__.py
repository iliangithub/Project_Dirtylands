# SPDX-FileCopyrightText: 2009-2011 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2014-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

command_modules = [
    "shasum",
    "adduser",
    "apt",
    "awk",
    # No exporta ningun comando: es el enganche de "--help" (ver ayuda.py).
    # Va en la lista de todos modos para que Cowrie lo cargue al ARRANCAR: si
    # tuviera un error de sintaxis se veria al levantar el senuelo, y no la
    # primera vez que alguien teclee "ls --help".
    # Tampoco exporta comandos: genera /var/log/auth.log al abrir la sesion
    # (ver authlog.py). Va en la lista por lo mismo que ayuda: para que un
    # error de sintaxis se vea al ARRANCAR y no la primera vez que alguien
    # haga "cat /var/log/auth.log".
    "authlog",
    "ayuda",
    "base",
    "base64",
    "bash",
    "bashbuiltins",
    "busybox",
    "cat",
    "chmod",
    "chpasswd",
    # No es un comando de Cowrie: son seis que el sistema de ficheros
    # declara y no estaban emulados (ver coreutils_extra.py).
    "coreutils_extra",
    # arch, tty, stty, nice, timeout, realpath, paste, fold y expr: los
    # declara el sistema de ficheros y no estaba emulado ninguno.
    "coreutils_mas",
    # useradd, usermod, userdel, groupadd y groupdel: escriben de verdad en
    # /etc/passwd, /etc/group y /etc/shadow.
    "usuarios",
    "crontab",
    "curl",
    "cut",
    "dd",
    "df",
    "dig",
    "dmidecode",
    "dpkg",
    "du",
    "env",
    "ethtool",
    "file",
    "find",
    "finger",
    "free",
    "fs",
    "ftpget",
    "gcc",
    "getconf",
    "git",
    "groups",
    "ifconfig",
    "ip",
    "iptables",
    "journalctl",
    "last",
    "ln",
    "locate",
    "ls",
    "lsblk",
    "lscpu",
    "lsb_release",
    "lsof",
    "lspci",
    "md5sum",
    # nano lo anadimos nosotros: emula el editor en vez de servir un error
    # enlatado. Montar el .py NO basta ---esta lista es la que Cowrie importa
    # al arrancar--- y olvidarlo da un "command not found" que no se parece a
    # un fallo de instalacion.
    "mount",
    "nano",
    "nc",
    "netstat",
    # node y psql los anadimos nosotros, y por el mismo motivo: el
    # PACKAGES del generador instala "nodejs npm" y "postgresql-client",
    # asi que la maquina los DECLARA ---which los encuentra, dpkg -l los
    # lista--- y sin emularlos se contradecia justo despues de que el
    # atacante picara con el .env del cebo, que promete una base de datos.
    "node",
    "nohup",
    "nproc",
    "openssl",
    # Tampoco exporta comandos: es el "less" que systemd le pone a
    # systemctl y a journalctl (ver paginador.py). Va en la lista para
    # que un error de sintaxis se vea al ARRANCAR.
    "paginador",
    "perl",
    "pgrep",
    "ping",
    "printenv",
    "psql",
    "pstree",
    "python",
    "readlink",
    "scp",
    "sed",
    "seq",
    "service",
    # setarch y sus alias x86_64, i386, linux32 y linux64: el cuarto
    # de la lista de "lo que dice tener y no sabe ejecutar".
    "setarch",
    "sleep",
    "ss",
    "ssh",
    "stat",
    "sudo",
    "systemctl",
    "systemd_detect_virt",
    "tar",
    "tee",
    "tftp",
    "ulimit",
    "top",
    "tr",
    "uname",
    "uniq",
    "unzip",
    "uptime",
    "wc",
    "wget",
    "which",
    "yum",
    # VA EL ULTIMO A PROPOSITO: hereda de curl, tar y wget para
    # anadirles el "--version" sin reescribirlos, y el ultimo modulo
    # que registra un nombre es el que manda.
    "descargas",
]
