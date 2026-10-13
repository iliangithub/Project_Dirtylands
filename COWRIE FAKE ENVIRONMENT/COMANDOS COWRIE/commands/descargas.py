# SPDX-License-Identifier: BSD-3-Clause
#
# El "--version" de wget, curl y tar, y el gzip que faltaba entero.
#
# LOS TRES NEGABAN SU PROPIA VERSION:
#
#     wget --version   ->  wget: invalid option -- 'version'
#     curl --version   ->  curl: option --version not recognized
#     tar --version    ->  tar: You must specify one of the `-Acdtrux' options
#
# Y son las dos herramientas con las que se baja el binario: quien va a
# usarlas mira primero cual hay, porque las opciones cambian entre versiones.
# Un wget que no sabe decir que wget es no es un wget.
#
# Este modulo NO reescribe los tres comandos: HEREDA de los que ya trae
# Cowrie y solo se pone delante para contestar "--version". Toda la maquinaria
# de descarga ---que es mucha y funciona--- se queda donde esta. Por eso el
# modulo va DESPUES de curl, tar y wget en command_modules: el ultimo que
# registra un nombre es el que manda.
#
# gzip, gunzip y zcat no estaban de ninguna forma, y el sistema de ficheros
# los declara: "gzip -d" contestaba "No such file or directory", que es la
# contradiccion de siempre.
#
# Las versiones salen del listado de dpkg, como en todos los demas.
from __future__ import annotations

import gzip as _gzip
import os

from cowrie.commands.base import FallaAlAvisar, escribe_fichero
from cowrie.commands.curl import Command_curl as _CurlBase
from cowrie.commands.tar import Command_tar as _TarBase
from cowrie.commands.wget import Command_wget as _WgetBase
from cowrie.shell.command import HoneyPotCommand

commands = {}


def _version_de(paquete: str, por_defecto: str) -> str:
    try:
        from cowrie.commands.dpkg import datos_de, leer_paquetes

        crudo, _arch = datos_de(leer_paquetes(), paquete,
                                por_defecto=(por_defecto, "amd64"))
    except Exception:                                          # noqa: BLE001
        crudo = por_defecto
    return crudo


def _numero(crudo: str) -> str:
    """El numero a secas: "1.25.0-2" -> "1.25.0"."""
    return crudo.split("-")[0].split("+")[0].split(":")[-1]


class Command_wget(_WgetBase):
    def start(self) -> None:
        if any(a in ("-V", "--version") for a in self.args):
            numero = _numero(_version_de("wget", "1.25.0-2"))
            self.write(
                "GNU Wget %s built on linux-gnu.\n"
                "\n"
                "-cares +digest -gpgme +https +ipv6 +iri +large-file"
                " -metalink +nls \n"
                "+ntlm +opie +psl +ssl/gnutls \n"
                "\n"
                "Wgetrc: \n"
                "    /etc/wgetrc (system)\n"
                "Locale: \n"
                "    /usr/share/locale \n"
                "\n"
                "Copyright (C) 2015 Free Software Foundation, Inc.\n"
                "License GPLv3+: GNU GPL version 3 or later\n"
                "<http://www.gnu.org/licenses/gpl.html>.\n"
                "This is free software: you are free to change and"
                " redistribute it.\n"
                "There is NO WARRANTY, to the extent permitted by law.\n"
                "\n"
                "Originally written by Hrvoje Niksic <hniksic@xemacs.org>.\n"
                "Please send bug reports and questions to"
                " <bug-wget@gnu.org>.\n" % numero)
            self.exit()
            return
        super().start()


class Command_curl(_CurlBase):
    def start(self) -> None:
        if any(a in ("-V", "--version") for a in self.args):
            crudo = _version_de("curl", "8.14.1-2+deb13u4")
            numero = _numero(crudo)
            self.write(
                "curl %s (x86_64-pc-linux-gnu) libcurl/%s OpenSSL/3.5.6"
                " zlib/1.3.1 brotli/1.1.0 zstd/1.5.7 libidn2/2.3.8"
                " libpsl/0.21.2 libssh2/1.11.1 nghttp2/1.64.0 nghttp3/1.8.0"
                " librtmp/2.3 OpenLDAP/2.6.10\n"
                "Release-Date: 2025-06-04, security patched: %s\n"
                "Protocols: dict file ftp ftps gopher gophers http https imap"
                " imaps ipfs ipns ldap ldaps mqtt pop3 pop3s rtmp rtsp scp"
                " sftp smb smbs smtp smtps telnet tftp ws wss\n"
                "Features: alt-svc AsynchDNS brotli GSS-API HSTS HTTP2 HTTP3"
                " HTTPS-proxy IDN IPv6 Kerberos Largefile libz NTLM PSL"
                " SPNEGO SSL threadsafe TLS-SRP UnixSockets zstd\n"
                % (numero, numero, crudo))
            self.exit()
            return
        super().start()


class Command_tar(_TarBase):
    def start(self) -> None:
        if any(a == "--version" for a in self.args):
            numero = _numero(_version_de("tar", "1.35+dfsg-3.1"))
            self.write(
                "tar (GNU tar) %s\n"
                "Copyright (C) 2023 Free Software Foundation, Inc.\n"
                "License GPLv3+: GNU GPL version 3 or later"
                " <https://gnu.org/licenses/gpl.html>.\n"
                "This is free software: you are free to change and"
                " redistribute it.\n"
                "There is NO WARRANTY, to the extent permitted by law.\n"
                "\n"
                "Written by John Gilmore and Jay Fenlason.\n" % numero)
            self.exit()
            return
        super().start()


class _Comprime(FallaAlAvisar, HoneyPotCommand):
    """gzip, gunzip y zcat. Comprimen y descomprimen DE VERDAD.

    No estaban de ninguna forma, y el sistema de ficheros los declara: un
    "gzip -d payload.gz" ---que es el paso siguiente a la descarga en la mitad
    de los guiones--- contestaba "No such file or directory", o sea que la
    maquina se desmentia a si misma.
    """

    NOMBRE = "gzip"
    DESCOMPRIME = False
    A_LA_SALIDA = False

    def _lee(self, ruta: str):
        try:
            return self.fs.file_contents(ruta)
        except Exception:                                      # noqa: BLE001
            return None

    def call(self) -> None:
        descomprime = self.DESCOMPRIME
        a_la_salida = self.A_LA_SALIDA
        conservar = False
        nombres = []
        for a in self.args:
            if a in ("-d", "--decompress", "--uncompress"):
                descomprime = True
            elif a in ("-c", "--stdout", "--to-stdout"):
                a_la_salida = True
            elif a in ("-k", "--keep"):
                conservar = True
            elif a == "--version":
                numero = _numero(_version_de("gzip", "1.13-1"))
                self.write("gzip %s\n"
                           "Copyright (C) 2023 Free Software Foundation,"
                           " Inc.\n" % numero)
                return
            elif a.startswith("-") and a != "-":
                continue
            else:
                nombres.append(a)

        if not nombres:
            datos = self.input_data or b""
            self.writeBytes(self._transforma(datos, descomprime, "stdin"))
            return

        for nombre in nombres:
            ruta = self.fs.resolve_path(nombre, self.protocol.cwd)
            datos = self._lee(ruta)
            if datos is None:
                self.errorWrite("%s: %s: No such file or directory\n"
                                % (self.NOMBRE, nombre))
                continue
            salida = self._transforma(datos, descomprime, nombre)
            if salida is None:
                continue
            if a_la_salida:
                self.writeBytes(salida)
                continue
            if descomprime:
                destino = ruta[:-3] if ruta.endswith(".gz") else ruta + ".out"
            else:
                if ruta.endswith(".gz"):
                    self.errorWrite("%s: %s already has .gz suffix -- unchanged\n"
                                    % (self.NOMBRE, nombre))
                    continue
                destino = ruta + ".gz"
            escribe_fichero(self, destino, salida)
            if not conservar:
                try:
                    self.fs.remove(ruta)
                except Exception:                              # noqa: BLE001
                    pass

    def _transforma(self, datos: bytes, descomprime: bool, nombre: str):
        if not descomprime:
            return _gzip.compress(datos)
        try:
            return _gzip.decompress(datos)
        except Exception:                                      # noqa: BLE001
            self.errorWrite("%s: %s: not in gzip format\n"
                            % (self.NOMBRE, os.path.basename(nombre)))
            return None


class Command_gzip(_Comprime):
    NOMBRE = "gzip"


class Command_gunzip(_Comprime):
    NOMBRE = "gunzip"
    DESCOMPRIME = True


class Command_zcat(_Comprime):
    NOMBRE = "zcat"
    DESCOMPRIME = True
    A_LA_SALIDA = True


for _nombre, _clase in (("wget", Command_wget), ("curl", Command_curl),
                        ("tar", Command_tar), ("gzip", Command_gzip),
                        ("gunzip", Command_gunzip), ("zcat", Command_zcat)):
    commands[_nombre] = _clase
    commands["/usr/bin/" + _nombre] = _clase
    commands["/bin/" + _nombre] = _clase
