# SPDX-License-Identifier: BSD-3-Clause
#
# useradd, usermod, userdel, groupadd y groupdel.
#
# NINGUNO EXISTIA, y "useradd" era peor que no existir: la imagen lo tenia
# apuntando a la MISMA clase que "adduser", que es otro programa. Son dos
# cosas distintas ---adduser es el envoltorio interactivo de Debian, useradd
# el binario de shadow---, asi que un "useradd pepe" contestaba
#
#     Adding user `pepe' ...
#     Adding new group `pepe' (1001) ...
#     Password:
#
# y se quedaba pidiendo una contrasena. El de verdad no imprime NADA, no
# pregunta NADA y devuelve 0. Cualquier guion que cree un usuario ---que es la
# forma clasica de dejarse una puerta abierta--- se quedaba colgado ahi.
#
# Y lo que se cree se escribe DE VERDAD en /etc/passwd, /etc/group y
# /etc/shadow, que es lo unico que aguanta la comprobacion siguiente: el
# atacante mira "grep pepe /etc/passwd" o "id pepe" acto seguido.
#
# Todo medido contra el shadow de un Debian 13.
from __future__ import annotations

from cowrie.commands.base import FallaAlAvisar, escribe_fichero
from cowrie.shell.command import HoneyPotCommand

commands = {}

PASSWD = "/etc/passwd"
GRUPO = "/etc/group"
SHADOW = "/etc/shadow"

# El primer uid de usuario normal en Debian, de /etc/login.defs.
UID_MIN = 1000


class _Cuentas(FallaAlAvisar, HoneyPotCommand):
    """Lo comun: leer y escribir las tres tablas del sistema."""

    NOMBRE = ""

    def lineas(self, ruta: str) -> list:
        try:
            texto = self.fs.file_contents(ruta).decode("utf-8", "replace")
        except Exception:                                      # noqa: BLE001
            return []
        return [l for l in texto.split("\n") if l]

    def guarda(self, ruta: str, lineas: list, modo: int = 33188) -> None:
        escribe_fichero(self, ruta, ("\n".join(lineas) + "\n").encode(),
                        modo=modo)

    def campo(self, ruta: str, nombre: str):
        for linea in self.lineas(ruta):
            if linea.split(":")[0] == nombre:
                return linea.split(":")
        return None

    def siguiente_id(self, ruta: str) -> int:
        usados = set()
        for linea in self.lineas(ruta):
            trozos = linea.split(":")
            if len(trozos) > 2 and trozos[2].isdigit():
                usados.add(int(trozos[2]))
        n = UID_MIN
        while n in usados:
            n += 1
        return n

    def falta_login(self) -> bool:
        self.errorWrite("%s: no login name specified\n" % self.NOMBRE)
        self.errorWrite("Usage: %s [options] LOGIN\n" % self.NOMBRE)
        return True

    def opcion_larga_desconocida(self, arg: str) -> None:
        # shadow no tiene --version: contesta que no la reconoce y suelta el
        # uso entero. Medido.
        self.errorWrite("%s: unrecognized option '%s'\n" % (self.NOMBRE, arg))
        self.errorWrite("Usage: %s [options] LOGIN\n" % self.NOMBRE)


class Command_useradd(_Cuentas):
    NOMBRE = "useradd"

    def call(self) -> None:
        nombre = None
        home = None
        shell = "/bin/sh"
        crear_home = False
        grupos = []
        i = 0
        while i < len(self.args):
            a = self.args[i]
            if a in ("-m", "--create-home"):
                crear_home = True
            elif a in ("-M", "--no-create-home", "-r", "--system",
                       "-N", "--no-user-group", "-U", "--user-group"):
                pass
            elif a in ("-d", "--home-dir"):
                i += 1
                home = self.args[i] if i < len(self.args) else None
            elif a in ("-s", "--shell"):
                i += 1
                shell = self.args[i] if i < len(self.args) else shell
            elif a in ("-G", "--groups"):
                i += 1
                grupos = (self.args[i].split(",") if i < len(self.args) else [])
            elif a in ("-g", "--gid", "-c", "--comment", "-p", "--password",
                       "-u", "--uid", "-e", "--expiredate", "-k", "--skel"):
                i += 1
            elif a.startswith("--"):
                self.opcion_larga_desconocida(a)
                return
            elif a.startswith("-"):
                pass
            else:
                nombre = a
            i += 1

        if nombre is None:
            self.falta_login()
            return
        if self.campo(PASSWD, nombre) is not None:
            # 9 es EXIT_NAME_IN_USE de shadow, no 1.
            self.errorWrite("useradd: user '%s' already exists\n" % nombre)
            self.exit_code = 9
            return

        uid = self.siguiente_id(PASSWD)
        gid = self.siguiente_id(GRUPO)
        home = home or "/home/%s" % nombre

        passwd = self.lineas(PASSWD)
        passwd.append("%s:x:%d:%d::%s:%s" % (nombre, uid, gid, home, shell))
        self.guarda(PASSWD, passwd)

        grupo = self.lineas(GRUPO)
        grupo.append("%s:x:%d:" % (nombre, gid))
        for otro in grupos:
            for j, linea in enumerate(grupo):
                trozos = linea.split(":")
                if trozos[0] == otro:
                    miembros = [m for m in trozos[3].split(",") if m]
                    miembros.append(nombre)
                    trozos[3] = ",".join(miembros)
                    grupo[j] = ":".join(trozos)
        self.guarda(GRUPO, grupo)

        sombra = self.lineas(SHADOW)
        if sombra:
            # Sin contrasena puesta shadow escribe "!", no un hash.
            sombra.append("%s:!:20000:0:99999:7:::" % nombre)
            self.guarda(SHADOW, sombra, modo=33152)

        if crear_home:
            try:
                self.fs.mkdir(home, uid, gid, 4096, 16877)
            except Exception:                                  # noqa: BLE001
                pass
        # Y no escribe NADA: useradd es mudo cuando le sale bien.


class Command_usermod(_Cuentas):
    NOMBRE = "usermod"

    def call(self) -> None:
        nombre = None
        anadir = False
        grupos: list = []
        shell = None
        home = None
        nuevo_nombre = None
        i = 0
        while i < len(self.args):
            a = self.args[i]
            if a in ("-a", "--append"):
                anadir = True
            elif a.startswith("-a") and "G" in a:
                # "-aG" pegadas, que es como se escribe siempre.
                anadir = True
                i += 1
                grupos = (self.args[i].split(",") if i < len(self.args) else [])
            elif a in ("-G", "--groups"):
                i += 1
                grupos = (self.args[i].split(",") if i < len(self.args) else [])
            elif a in ("-s", "--shell"):
                i += 1
                shell = self.args[i] if i < len(self.args) else None
            elif a in ("-d", "--home"):
                i += 1
                home = self.args[i] if i < len(self.args) else None
            elif a in ("-l", "--login"):
                i += 1
                nuevo_nombre = self.args[i] if i < len(self.args) else None
            elif a in ("-L", "--lock", "-U", "--unlock", "-m", "--move-home"):
                pass
            elif a.startswith("--"):
                self.opcion_larga_desconocida(a)
                return
            elif a.startswith("-"):
                i += 1
            else:
                nombre = a
            i += 1

        if nombre is None:
            self.falta_login()
            return
        if self.campo(PASSWD, nombre) is None:
            self.errorWrite("usermod: user '%s' does not exist\n" % nombre)
            self.exit_code = 6
            return

        passwd = self.lineas(PASSWD)
        for j, linea in enumerate(passwd):
            trozos = linea.split(":")
            if trozos[0] != nombre:
                continue
            if shell:
                trozos[6] = shell
            if home:
                trozos[5] = home
            if nuevo_nombre:
                trozos[0] = nuevo_nombre
            passwd[j] = ":".join(trozos)
        self.guarda(PASSWD, passwd)

        if grupos:
            grupo = self.lineas(GRUPO)
            for j, linea in enumerate(grupo):
                trozos = linea.split(":")
                miembros = [m for m in trozos[3].split(",") if m]
                if trozos[0] in grupos:
                    if nombre not in miembros:
                        miembros.append(nombre)
                elif not anadir and nombre in miembros:
                    # Sin "-a", -G REEMPLAZA la lista: se sale de los demas.
                    miembros.remove(nombre)
                trozos[3] = ",".join(miembros)
                grupo[j] = ":".join(trozos)
            self.guarda(GRUPO, grupo)


class Command_userdel(_Cuentas):
    NOMBRE = "userdel"

    def call(self) -> None:
        nombres = [a for a in self.args if not a.startswith("-")]
        if not nombres:
            self.falta_login()
            return
        nombre = nombres[0]
        if self.campo(PASSWD, nombre) is None:
            # 6 es EXIT_NAME_NOT_EXIST de shadow.
            self.errorWrite("userdel: user '%s' does not exist\n" % nombre)
            self.exit_code = 6
            return
        self.guarda(PASSWD, [l for l in self.lineas(PASSWD)
                             if l.split(":")[0] != nombre])
        self.guarda(GRUPO, [l for l in self.lineas(GRUPO)
                            if l.split(":")[0] != nombre])
        sombra = [l for l in self.lineas(SHADOW) if l.split(":")[0] != nombre]
        if sombra:
            self.guarda(SHADOW, sombra, modo=33152)


class Command_groupadd(_Cuentas):
    NOMBRE = "groupadd"

    def call(self) -> None:
        nombres = [a for a in self.args if not a.startswith("-")]
        if not nombres:
            self.errorWrite("groupadd: no group name specified\n")
            self.errorWrite("Usage: groupadd [options] GROUP\n")
            return
        nombre = nombres[0]
        if self.campo(GRUPO, nombre) is not None:
            self.errorWrite("groupadd: group '%s' already exists\n" % nombre)
            self.exit_code = 9
            return
        grupo = self.lineas(GRUPO)
        grupo.append("%s:x:%d:" % (nombre, self.siguiente_id(GRUPO)))
        self.guarda(GRUPO, grupo)


class Command_groupdel(_Cuentas):
    NOMBRE = "groupdel"

    def call(self) -> None:
        nombres = [a for a in self.args if not a.startswith("-")]
        if not nombres:
            self.errorWrite("groupdel: no group name specified\n")
            self.errorWrite("Usage: groupdel [options] GROUP\n")
            return
        nombre = nombres[0]
        if self.campo(GRUPO, nombre) is None:
            self.errorWrite("groupdel: group '%s' does not exist\n" % nombre)
            self.exit_code = 6
            return
        self.guarda(GRUPO, [l for l in self.lineas(GRUPO)
                            if l.split(":")[0] != nombre])


for _clase in (Command_useradd, Command_usermod, Command_userdel,
               Command_groupadd, Command_groupdel):
    _n = _clase.NOMBRE
    commands[_n] = _clase
    commands["/usr/sbin/" + _n] = _clase
    commands["/sbin/" + _n] = _clase
