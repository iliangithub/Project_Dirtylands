# SPDX-FileCopyrightText: 2009-2014 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2015-2025 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import getopt
import os.path
import stat
import string
import time

from cowrie.shell import fs
from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.pwd import Group, Passwd

commands = {}


# --- Enforcement de permisos de lectura (homes privados) --------------------
# Cowrie no comprueba permisos en ls/cat/cd. Estas funciones replican el modelo
# Unix: para acceder a una ruta hay que tener 'x' en cada directorio ancestro y
# el permiso pedido en el destino. root (uid 0) siempre pasa.
# --- El entrecomillado de los nombres --------------------------------------
# coreutils 8.25 cambio el estilo por defecto a "shell-escape" CUANDO LA
# SALIDA ES UN TERMINAL, y aqui no se hacia. En /home/admin hay un directorio
# llamado "ignis api" y el listado lo escribia crudo:
#
#     $ ls
#     ignis api
#
# que se lee como dos entradas. El ls de un Debian 13 escribe 'ignis api', y
# esa comilla es justo la pista de que el nombre lleva un espacio. Sin ella
# el siguiente comando que se teclea falla ---paso--- y el shell queda como
# raro. En una tuberia NO se entrecomilla, que es lo que espera cualquier
# guion que corte la salida de ls.
_SEGUROS = frozenset(string.ascii_letters + string.digits + "%+,-./:=@_^]{}")

# Dentro de $'...' estos tienen nombre corto; el resto van en octal.
_CTRL = {"\a": r"\a", "\b": r"\b", "\f": r"\f", "\n": r"\n",
         "\r": r"\r", "\t": r"\t", "\v": r"\v"}
_CTRL_C = dict(_CTRL, **{'"': r'\"', "\\": "\\\\"})


def _por_tramos(nombre: str) -> list:
    """Parte el nombre en rachas de imprimibles y rachas de control."""
    tramos: list = []
    for c in nombre:
        control = not c.isprintable()
        if tramos and tramos[-1][0] == control:
            tramos[-1][1] += c
        else:
            tramos.append([control, c])
    return tramos


def escapa_nombre(nombre: str) -> str:
    r"""El estilo shell-escape: 'ignis api', 'it'\''s', 'a'$'\n''b'.

    Un nombre que no necesita nada sale desnudo, que es la mitad del asunto:
    si se entrecomillara todo tampoco seria ls. La "#" y la "~" solo dan
    guerra al principio, asi que en medio cuentan como seguras.
    """
    if nombre == "":
        return "''"
    if all(c in _SEGUROS or (c in "#~" and i)
           for i, c in enumerate(nombre)):
        return nombre
    salida = []
    for control, trozo in _por_tramos(nombre):
        if control:
            salida.append("$'" + "".join(
                _CTRL.get(c, "\\%03o" % ord(c)) for c in trozo) + "'")
        else:
            salida.append("'" + trozo.replace("'", "'\\''") + "'")
    return "".join(salida)


def entrecomilla_c(nombre: str) -> str:
    """El estilo de "ls -Q": comillas dobles al estilo de C.

    No es el mismo que shell-escape ---da "ignis api" y no 'ignis api'--- y
    ademas -Q entrecomilla SIEMPRE, tambien los nombres sin nada raro. La
    opcion ni siquiera se aceptaba: getopt contestaba "option -- 'Q' is not
    recognized", que en un ls de verdad no pasa.
    """
    salida = []
    for c in nombre:
        if c in _CTRL_C:
            salida.append(_CTRL_C[c])
        elif not c.isprintable():
            salida.append("\\%03o" % ord(c))
        else:
            salida.append(c)
    return '"' + "".join(salida) + '"'


def reparte_en_columnas(nombres: list, ancho: int) -> list:
    """El reparto en columnas de ls, que NO era el de ls en tres cosas.

    Se escribian los nombres DE IZQUIERDA A DERECHA, con UN espacio de
    separacion y rellenando tambien el ultimo de cada linea. El de verdad los
    escribe HACIA ABAJO ---primero se llena la columna, luego se pasa a la
    siguiente---, separa con DOS espacios y no deja relleno al final de la
    linea. Medido con un terminal de verdad sobre treinta ficheros: las tres
    cosas se ven en la primera orden que teclea cualquiera.

    Ademas cada columna mide lo que mide SU nombre mas largo, no el mas largo
    de todo el directorio.
    """
    if not nombres:
        return []
    total = len(nombres)
    for columnas in range(min(total, max(1, ancho // 2)), 0, -1):
        filas = -(-total // columnas)
        # Una reparticion que dejaria la ultima columna vacia no la hace ls.
        if filas * (columnas - 1) >= total:
            continue
        trozos = [nombres[c * filas:(c + 1) * filas] for c in range(columnas)]
        anchos = [max(len(x) for x in t) for t in trozos]
        if sum(a + 2 for a in anchos) - 2 <= ancho or columnas == 1:
            salida = []
            for f in range(filas):
                linea = ""
                for c, trozo in enumerate(trozos):
                    if f >= len(trozo):
                        continue
                    if linea:
                        linea = linea.ljust(sum(anchos[:c]) + 2 * c)
                    linea += trozo[f]
                salida.append(linea)
            return salida
    return list(nombres)


def _cowrie_perm_ok(node, uid: int, gid: int, want: str) -> bool:
    mode = node[fs.A_MODE]
    if uid == node[fs.A_UID]:
        bit = 0o400 if want == "r" else 0o100
    elif gid == node[fs.A_GID]:
        bit = 0o040 if want == "r" else 0o010
    else:
        bit = 0o004 if want == "r" else 0o001
    return bool(mode & bit)


def _cowrie_access_denied(fsobj, abspath: str, uid: int, gid: int, target_need) -> bool:
    if uid == 0:
        return False
    parts = [p for p in abspath.split("/") if p]
    cur = ""
    for i, part in enumerate(parts):
        cur = cur + "/" + part
        try:
            node = fsobj.getfile(cur, follow_symlinks=True)
        except Exception:
            return False
        if not node:
            return False
        need = target_need if i == len(parts) - 1 else "x"
        if need is None:
            continue
        if not _cowrie_perm_ok(node, uid, gid, need):
            return True
    return False


class Command_ls(HoneyPotCommand):
    def uid2name(self, uid: int) -> str:
        try:
            name: str = Passwd().getpwuid(uid)["pw_name"]
        except Exception:
            return str(uid)
        else:
            return name

    def gid2name(self, gid: int) -> str:
        try:
            group: str = Group().getgrgid(gid)["gr_name"]
        except Exception:
            return str(gid)
        else:
            return group

    def nombre(self, texto: str) -> str:
        """El nombre tal como lo escribe ls, segun el estilo en vigor."""
        if getattr(self, "estilo", "literal") == "c":
            return entrecomilla_c(texto)
        if getattr(self, "estilo", "literal") == "shell":
            return escapa_nombre(texto)
        return texto

    def call(self) -> None:
        path = self.protocol.cwd
        paths = []
        self.showHidden = False
        self.showDirectories = False
        self.showHumanReadable = False
        # "ls -l" NO sigue los enlaces: describe el enlace. Solo "-L" (y "-H"
        # para los de la linea de ordenes) piden lo contrario.
        self.dereference = False
        func = self.do_ls_normal

        # Parse options or display no files
        try:
            opts, args = getopt.gnu_getopt(
                self.args,
                "1@ABCFGHLNOPQRSTUWabcdefghiklmnopqrstuvwx",
                ["help", "version", "param", "literal", "quote-name"],
            )
        except getopt.GetoptError as err:
            self.errorWrite(f"ls: {err}\n")
            self.errorWrite("Try 'ls --help' for more information.\n")
            return
        # UNA COLUMNA CUANDO LA SALIDA NO VA A UN TERMINAL. Es lo que hace
        # ls de verdad, y no es un detalle de formato: "ls /etc | wc -l"
        # contaba 29 donde hay 60, porque cada linea traia tres nombres. Todo
        # lo que cuente o filtre la salida de ls ---que es como se recorre un
        # directorio desde un guion--- salia mal.
        from cowrie.commands.paginador import hay_terminal

        self.una_por_linea = not hay_terminal(self)
        # El mismo "es un terminal" decide el entrecomillado: shell-escape a
        # la pantalla, literal a una tuberia o a un fichero.
        self.estilo = "shell" if hay_terminal(self) else "literal"

        for x, _a in opts:
            if x in ("-l"):
                func = self.do_ls_l
            if x in ("-1"):
                self.una_por_linea = True
            if x in ("-C", "-x"):
                # "-C" pide columnas aunque la salida no sea un terminal.
                self.una_por_linea = False
            if x in ("-h"):
                self.showHumanReadable = True

            if x in ("-a"):
                self.showHidden = True
            if x in ("-d"):
                self.showDirectories = True
            if x in ("-L"):
                self.dereference = True
            if x in ("-Q", "--quote-name"):
                self.estilo = "c"
            if x in ("-N", "--literal"):
                self.estilo = "literal"

        uid = getattr(self.protocol.user, "uid", 0)
        gid = getattr(self.protocol.user, "gid", 0)

        if not args:
            if _cowrie_access_denied(self.protocol.fs, path, uid, gid, "r"):
                self.errorWrite("ls: cannot open directory '.': Permission denied\n")
                return
            func(path)
            return

        # Argumento original de cada ruta resuelta. POR INSTANCIA y no de
        # clase: un diccionario de clase lo compartirian todas las sesiones.
        self._tal_cual: dict = {}
        for arg in args:
            rp = self.protocol.fs.resolve_path(arg, self.protocol.cwd)
            isdir = self.protocol.fs.isdir(rp)
            need = "r" if isdir else None
            if _cowrie_access_denied(self.protocol.fs, rp, uid, gid, need):
                if isdir:
                    self.errorWrite(
                        f"ls: cannot open directory '{arg}': Permission denied\n"
                    )
                else:
                    self.errorWrite(f"ls: cannot access '{arg}': Permission denied\n")
                    self.exit_code = 2
                continue
            paths.append(rp)
            # ls repite el argumento TAL COMO SE ESCRIBIO, no su ruta
            # resuelta: "ls -d uno/dos" contesta "uno/dos", no "/tmp/uno/dos".
            # Se guarda aparte porque get_dir_files solo recibe la resuelta.
            self._tal_cual[rp] = arg

        for p in paths:
            func(p)

    def get_dir_files(self, path):
        try:
            if self.protocol.fs.isdir(path) and not self.showDirectories:
                files = self.protocol.fs.get_path(path)[:]
                if self.showHidden:
                    dot = self.protocol.fs.getfile(path)[:]
                    dot[fs.A_NAME] = "."
                    files.append(dot)
                    dotdot = self.protocol.fs.getfile(os.path.split(path)[0])[:]
                    if not dotdot:
                        dotdot = self.protocol.fs.getfile(path)[:]
                    dotdot[fs.A_NAME] = ".."
                    files.append(dotdot)
                else:
                    files = [x for x in files if not x[fs.A_NAME].startswith(".")]
                files.sort()
            else:
                # follow_symlinks=False: getfile() de Cowrie resuelve los
                # enlaces por defecto, asi que "ls -l /etc/localtime" mostraba
                # el tamano, los permisos y la fecha del FICHERO DE DESTINO en
                # vez de "lrwxrwxrwx ... -> ...". Dentro de un listado de
                # directorio salia bien, porque ahi los nodos se leen tal cual;
                # el fallo solo aparecia al pasar el enlace como argumento, que
                # es justo como lo mira quien comprueba /etc/localtime o
                # /etc/os-release.
                file = self.protocol.fs.getfile(
                    path, follow_symlinks=self.dereference
                )[:]
                file[fs.A_NAME] = getattr(self, "_tal_cual", {}).get(path, path)
                files = [file]
        except Exception:
            # ls sale con 2 cuando no puede acceder a algo, no con 0. Sin
            # esto un "ls /ruta || respaldo" no lanzaba nunca el respaldo.
            #
            # Y LA QUEJA NOMBRA EL OPERANDO TAL COMO SE ESCRIBIO. Salia la
            # ruta ya resuelta, asi que desde /home un "ls admin/ignis"
            # contestaba "cannot access '/home/admin/ignis'" donde coreutils
            # dice "cannot access 'admin/ignis'". Se ve a la primera: el
            # mensaje sabe mas de lo que le han contado.
            cual = getattr(self, "_tal_cual", {}).get(path, path)
            self.errorWrite(f"ls: cannot access '{cual}': No such file or directory\n")
            self.exit_code = 2
            return
        return files

    def do_ls_normal(self, path: str) -> None:
        files = self.get_dir_files(path)
        if not files:
            return

        line = [self.nombre(x[fs.A_NAME]) for x in files]
        if not line:
            return
        if getattr(self, "una_por_linea", False):
            for f in line:
                self.write(f + "\n")
            return
        try:
            wincols = self.protocol.user.windowSize[1]
        except AttributeError:
            wincols = 80
        for fila in reparte_en_columnas(line, wincols):
            self.write(fila + "\n")

    @staticmethod
    def _fecha(marca) -> str:
        """La fecha tal como la escribe "ls", que no es ISO.

        Aqui salia "2026-04-15 12:01", que es lo que da --time-style=long-iso.
        El formato por defecto de coreutils es "Aug 22 09:21" y, para lo que
        tenga mas de seis meses, cambia la hora por el ANO: "Mar  1  2024". El
        dia va con %e, o sea alineado a la derecha en dos huecos.
        """
        ahora = time.time()
        cuando = time.localtime(marca)
        seis_meses = 182 * 24 * 3600
        if abs(ahora - marca) > seis_meses:
            return time.strftime("%b %e  %Y", cuando)
        return time.strftime("%b %e %H:%M", cuando)

    def do_ls_l(self, path: str) -> None:
        files = self.get_dir_files(path)
        if not files:
            return
        formatted_sizes = []
        filesize_str_extent = 0
        if len(files):
            filesize_str_extent = max(len(str(x[fs.A_SIZE])) for x in files)
            if self.showHumanReadable:
                for x in files:
                    size = x[fs.A_SIZE]
                    if size >= 1024 * 1024 * 1024:
                        formatted_size = f"{size / 1024 / 1024 / 1024:.1f}G"
                    elif size >= 1024 * 1024:
                        formatted_size = f"{size / 1024 / 1024:.1f}M"
                    elif size >= 1024:
                        formatted_size = f"{size / 1024:.1f}K"
                    else:
                        formatted_size = str(size)
                    formatted_sizes.append(formatted_size)
                filesize_str_extent = max(len(size) for size in formatted_sizes)
            else:
                formatted_sizes = [str(x[fs.A_SIZE]) for x in files]

        user_name_str_extent = 0
        if len(files):
            user_name_str_extent = max(len(self.uid2name(x[fs.A_UID])) for x in files)

        group_name_str_extent = 0
        if len(files):
            group_name_str_extent = max(len(self.gid2name(x[fs.A_GID])) for x in files)

        # "total N" abre SIEMPRE un listado largo, y aqui no salia. N son los
        # bloques de 1K que ocupan en disco las entradas listadas: un fichero
        # vacio no ocupa ninguno y cualquier otro ocupa al menos los 4 KB de un
        # bloque del sistema de ficheros.
        def bloques(tam):
            if tam <= 0:
                return 0
            return ((tam + 4095) // 4096) * 4

        # SOLO al listar un directorio. "ls -la fichero" no lleva esa linea,
        # y ponerla siempre era un fallo tan visible como no ponerla nunca.
        if self.protocol.fs.isdir(path) and not self.showDirectories:
            total = sum(bloques(f[fs.A_SIZE]) for f in files
                        if self.showHidden or not f[fs.A_NAME].startswith("."))
            self.write("total %d\n" % total)

        # El contador de enlaces se alinea a la derecha con el mas ancho, como
        # hace ls: si no, en un /etc con 38 enlaces las columnas de la derecha
        # bailan de fila en fila.
        def cuenta_enlaces(f):
            if f[fs.A_TYPE] != fs.T_DIR:
                return 1
            hijos = f[fs.A_CONTENTS] or []
            return 2 + sum(1 for h in hijos if h[fs.A_TYPE] == fs.T_DIR)

        ancho_enlaces = max(
            [1] + [len(str(cuenta_enlaces(f))) for f in files
                   if self.showHidden or not f[fs.A_NAME].startswith(".")])

        for i, file in enumerate(files):
            if file[fs.A_NAME].startswith(".") and not self.showHidden:
                continue

            perms = ["-"] * 10
            if file[fs.A_MODE] & stat.S_IRUSR:
                perms[1] = "r"
            if file[fs.A_MODE] & stat.S_IWUSR:
                perms[2] = "w"
            if file[fs.A_MODE] & stat.S_IXUSR:
                perms[3] = "x"
            if file[fs.A_MODE] & stat.S_ISUID:
                perms[3] = "S"
            if file[fs.A_MODE] & stat.S_IXUSR and file[fs.A_MODE] & stat.S_ISUID:
                perms[3] = "s"

            if file[fs.A_MODE] & stat.S_IRGRP:
                perms[4] = "r"
            if file[fs.A_MODE] & stat.S_IWGRP:
                perms[5] = "w"
            if file[fs.A_MODE] & stat.S_IXGRP:
                perms[6] = "x"
            if file[fs.A_MODE] & stat.S_ISGID:
                perms[6] = "S"
            if file[fs.A_MODE] & stat.S_IXGRP and file[fs.A_MODE] & stat.S_ISGID:
                perms[6] = "s"

            if file[fs.A_MODE] & stat.S_IROTH:
                perms[7] = "r"
            if file[fs.A_MODE] & stat.S_IWOTH:
                perms[8] = "w"
            if file[fs.A_MODE] & stat.S_IXOTH:
                perms[9] = "x"
            if file[fs.A_MODE] & stat.S_ISVTX:
                perms[9] = "T"
            if file[fs.A_MODE] & stat.S_IXOTH and file[fs.A_MODE] & stat.S_ISVTX:
                perms[9] = "t"

            linktarget = ""

            if file[fs.A_TYPE] == fs.T_DIR:
                perms[0] = "d"
            elif file[fs.A_TYPE] == fs.T_LINK:
                perms[0] = "l"
                linktarget = f" -> {self.nombre(file[fs.A_TARGET])}"

            permstr = "".join(perms)
            ctime = time.localtime(file[fs.A_CTIME])

            # El contador de enlaces iba escrito a fuego a 1, y un directorio
            # NUNCA tiene 1: son 2 (el propio "." y su entrada en el padre) mas
            # uno por cada subdirectorio. Un "/home" con cinco cuentas tiene 7,
            # y ver un 1 ahi delata el listado de un solo vistazo.
            enlaces = str(cuenta_enlaces(file)).rjust(ancho_enlaces)

            line = "{} {} {} {} {} {} {}{}".format(
                permstr,
                enlaces,
                self.uid2name(file[fs.A_UID]).ljust(user_name_str_extent),
                self.gid2name(file[fs.A_GID]).ljust(group_name_str_extent),
                formatted_sizes[i].rjust(filesize_str_extent),
                self._fecha(file[fs.A_CTIME]),
                self.nombre(file[fs.A_NAME]),
                linktarget,
            )

            self.write(f"{line}\n")


commands["/bin/ls"] = Command_ls
commands["ls"] = Command_ls
commands["/bin/dir"] = Command_ls
commands["dir"] = Command_ls
