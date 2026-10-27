# SPDX-FileCopyrightText: 2009-2014 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2014-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause


from __future__ import annotations

import ast
import copy
import ipaddress
import os
import random
import re
import shlex
import socket
from typing import Any

from twisted.internet import error
from twisted.python import failure, log
from twisted.python.compat import iterbytes

from cowrie.core.config import CowrieConfig
from cowrie.shell import fs
from cowrie.shell.parser import CommandParser
from cowrie.shell.pipe import PipeProtocol

# Matches a ${VAR} or $VAR reference anywhere inside a token
# El "?" va aparte del resto de nombres porque no es un caracter de
# identificador: sin el, "$?" se quedaba literal y cualquier script que
# comprobara "cmd; if [ $? -ne 0 ]" veia la cadena "$?" en vez de un numero.
# El "?" y los parametros posicionales ---$#, $@, $*--- no son nombres de
# variable y hay que nombrarlos aparte. Sin $# en esta lista, un "echo $#"
# escribia el dolar suelto: "$".
_ENV_VAR_RE = re.compile(
    r"\$\{([_a-zA-Z0-9]+|[?#@*$])\}|\$([_a-zA-Z0-9]+|[?#@*$])")

# Marcador interno para "$?". Lleva caracteres de control a proposito: no puede
# aparecer en nada que escriba un atacante, asi que no hay forma de colarlo.
# "||(" , "&&(" y ";(" : el operador y el parentesis pegados, que shlex
# devuelve como un solo token. El grupo 2 son los parentesis, que pueden ser
# varios: "((" abre dos subshells.
_OPERADOR_PEGADO = re.compile(r"^(&&|\|\||;)(\(+)$")

# Un subshell que espera turno dentro de cmdpending. No puede ser un texto
# normal: tiene que ser imposible que un atacante lo escriba.
MARCA_SUBSHELL = "\x00SUBSHELL\x00"

MARCA_ESTADO = "\x00__estado__\x00"

# LA IP QUE SE ANUNCIA EN SSH_CONNECTION, COMPROBANDO QUE SEA UNA IP.
#
# kippoIP sale de [honeypot] internet_facing_ip tal cual, sin que nadie mire
# lo que pone. El cowrie.cfg de la VPS se pego desde la plantilla del README
# con el hueco sin rellenar, y el senuelo le enseno esto a quien entro:
#
#     root@pc-dev-003-ignis:~# env
#     SSH_CLIENT=203.0.113.7 60962 22
#     SSH_CONNECTION=203.0.113.7 60962 [IP VPS] 22
#
# Un corchete ahi no lo escribe ningun sshd del mundo: es una plantilla sin
# sustituir, y se lee como tal a la primera. Ademas parte el formato, porque
# el valor lleva un espacio: SSH_CONNECTION pasa de cuatro campos a cinco.
#
# Cowrie no lo valida, y hace bien: no es asunto suyo lo que le escriban en
# la configuracion. Aqui si, porque lo que cuesta no hacerlo es el senuelo
# entero. Si el valor no es una IP se cae a la del socket ---el mismo truco
# que usa Cowrie cuando la clave no esta puesta--- y se deja dicho en el log,
# que es donde se mira cuando algo va raro.
_IP_DE_RESPALDO: str | None = None


def _ip_local() -> str:
    """La IP de salida de esta maquina. El connect de UDP no manda nada."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return str(s.getsockname()[0])
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def ip_del_servidor(crudo: object) -> str:
    """El internet_facing_ip, o un respaldo si lo que hay no es una IP."""
    global _IP_DE_RESPALDO
    try:
        ipaddress.ip_address(str(crudo))
    except ValueError:
        pass
    else:
        return str(crudo)
    if _IP_DE_RESPALDO is None:
        log.msg(
            "internet_facing_ip no es una IP (%r): SSH_CONNECTION habria "
            "ensenado la plantilla sin rellenar" % (crudo,)
        )
        _IP_DE_RESPALDO = _ip_local()
    return _IP_DE_RESPALDO


# LOS CARACTERES QUE BASH ESCAPA AL COMPLETAR UN NOMBRE DE FICHERO.
# Es la lista literal de rl_filename_quote_characters (bashline.c). Se copia
# entera ---con el "=", el ":" y el "@", que sorprenden--- porque un
# tabulador que completa "a=b" tal cual, donde bash escribe "a\=b", tambien
# se nota.
CARACTERES_A_ESCAPAR = " \t\n\\\"'@<>=;|&()#$`?*[!:{~"


def parte_ultimo_token(linea: str) -> tuple[str, str, str]:
    r"""Parte la linea en (lo de antes, el token a completar, su comilla).

    El troceo del tabulador era line.split(), o sea POR ESPACIOS, y eso deja
    de valer en cuanto un nombre lleva uno. En /home/admin hay un directorio
    "ignis api" y se veian los dos fallos seguidos:

        cd ignis\ ap<TAB>   ->  el clue era "ap"  (no completaba nada)
        cd ign<TAB>         ->  "cd ignis api"    (cd: ignis: No such file)

    El primero por partir por espacios; el segundo porque el nombre se
    insertaba sin escapar. Aqui se recorre la linea entera llevando la cuenta
    de comillas y barras, que es lo que hace _rl_find_completion_word.

    Lo de antes del token vuelve TAL CUAL ---no reconstruido con
    " ".join(split())--- para no aplastar los espacios de mas ni las comillas
    de los argumentos anteriores, que era el tercer destrozo del mismo sitio:
    un "cp  'a b'  dest<TAB>" perdia las dos cosas.

    La comilla que se devuelve es la que quedo ABIERTA al final de la linea,
    o "" si el token va sin comillas o ya las cerro. Un token con las
    comillas cerradas tambien lo reescribe bash con barras.
    """
    inicio = 0
    en_token = False
    comilla = ""
    texto: list[str] = []
    i = 0
    n = len(linea)
    while i < n:
        c = linea[i]
        if comilla:
            if c == comilla:
                comilla = ""
            elif c == "\\" and comilla == '"' and i + 1 < n:
                i += 1
                texto.append(linea[i])
            else:
                texto.append(c)
            i += 1
            continue
        if c in " \t":
            en_token = False
            texto = []
            i += 1
            inicio = i
            continue
        if not en_token:
            en_token = True
            inicio = i
            texto = []
        if c == "\\" and i + 1 < n:
            i += 1
            texto.append(linea[i])
        elif c in "'\"":
            comilla = c
        else:
            texto.append(c)
        i += 1
    if not en_token:
        return linea, "", ""
    return linea[:inicio], "".join(texto), comilla


def escapa_completado(texto: str, comilla: str, cerrar: bool) -> str:
    r"""Devuelve el token ya listo para insertarlo en la linea.

    Dentro de comillas simples no hay nada que escapar; dentro de dobles,
    solo los cuatro de siempre; sin comillas, una barra delante de cada
    caracter de CARACTERES_A_ESCAPAR. La tilde inicial se deja en paz: es una
    expansion y no un nombre, y un "\~/x" no lleva a ninguna parte.

    "cerrar" es falso cuando el completado es parcial ---varios candidatos
    con un prefijo comun---: ahi bash deja la comilla abierta para que se
    siga escribiendo dentro de ella.
    """
    if comilla == "'":
        return "'" + texto + ("'" if cerrar else "")
    if comilla == '"':
        escapado = "".join("\\" + c if c in '"\\$`' else c for c in texto)
        return '"' + escapado + ('"' if cerrar else "")
    return "".join(
        c if (c == "~" and k == 0) or c not in CARACTERES_A_ESCAPAR
        else "\\" + c
        for k, c in enumerate(texto)
    )


# UN "$" QUE NO SE EXPANDE, y su hermano el acento invertido.
#
# El lexer va en modo posix, o sea que TIRA LAS COMILLAS mientras trocea: para
# cuando un token llega a la expansion ya no se sabe si el "$1" venia de
# '$1' ---literal--- o de "$1" ---se expande---. Durante mucho tiempo eso se
# tapo expandiendo solo las variables que existian y dejando el resto tal
# cual, que salvaba los programas de awk y sed a cambio de que
# "echo a$NADAb" imprimiera "a$NADAb" donde bash imprime "ab".
#
# La solucion es marcar ANTES de que el lexer toque nada: se recorre la linea
# cruda, y los "$" y "`" que esten dentro de comillas simples ---o escapados
# con barra--- se cambian por estas marcas. El lexer las trata como una letra
# mas, la expansion no las ve, y se devuelven a su forma justo antes de
# ejecutar. Asi se puede expandir de verdad todo lo demas.
#
# Son caracteres de control de un solo byte a proposito: tienen que
# sobrevivir al troceo pegados a su palabra, asi que van tambien en
# wordchars. Si alguno se escapara sin restaurar, el atacante veria un
# caracter raro; por eso el banco comprueba la salida entera y no un trozo.
DOLAR_LITERAL = "\x01"
TILDE_LITERAL = "\x02"
# LA FRONTERA DE LA COMILLA. En bash, "echo 'x'$A'y'" imprime "xunoy": la
# comilla que abre detras de $A TERMINA el nombre de la variable. Al tirar las
# comillas el token queda "x$Ay" y el nombre pasa a ser "Ay", que no existe.
# Se deja una marca en cada apertura y cierre, que corta el nombre igual que
# lo cortaba la comilla, y se quita al restaurar.
FRONTERA = "\x03"
ARIT_INI, ARIT_FIN = "\x04", "\x05"
# Una almohadilla DENTRO de ${...}. Fuera es un comentario y el lexer corta la
# linea ahi, asi que "${#A}" y "${F#a.}" llegaban partidos por la mitad: el
# primero se quedaba en "${" y el segundo en "${F".
ALMOHADILLA = "\x06"
# Un comodin que estaba entre comillas. Sin esto, "grep '[0-9]' fichero" o
# "sed 's/*//'" se convertirian en nombres de fichero antes de llegar al
# comando, que es lo contrario de lo que pide quien los entrecomilla.
ASTERISCO, INTERROGA, CORCHETE = "\x0e", "\x0f", "\x10"

# UNA SUSTITUCION $(...) QUE TODAVIA NO SE HA EJECUTADO.
#
# Se resolvia AL TROCEAR, y ahi las asignaciones de la misma linea todavia no
# han corrido: "i=1; echo $(echo $i)" imprimia una linea vacia. Es el mismo
# fallo que ya se corrigio para las variables sueltas y para "$?", y se
# arregla igual: se guarda el texto y lo ejecuta _expandir_ahora cuando le
# llega el turno al comando. Va en hexadecimal para que dentro pueda haber
# cualquier cosa ---espacios, comillas, tuberias--- sin que el lexer la parta.
SUST_INI, SUST_FIN = "\x14", "\x15"

# UN CARACTER DE OPERADOR ESCAPADO CON BARRA.
#
# "expr 2 \> 1" o "grep \* fichero": la barra dice que ese ">" o ese "*" son
# UN ARGUMENTO, no un operador del shell. La barra se la comia el troceo y lo
# de detras volvia a ser operador, asi que el "2" acababa redirigido a un
# fichero llamado "1" y expr no recibia nada. Se guarda como marca con el
# codigo del caracter y se devuelve al final, ya como texto.
LITERAL = "\x16"
_ESCAPABLES = "<>|&;()"

# LAS FRONTERAS DE UN BUCLE DESENROLLADO.
#
# Un bucle se convierte en su cuerpo repetido, o sea en una fila plana de
# ordenes, y en una fila plana no hay donde saltar: "break" y "continue" no
# podian existir y contestaban "command not found" ---bien alto, y dentro de
# un bucle que por lo demas funcionaba---. Con una marca entre vueltas y otra
# al final, saltar es tirar ordenes de la cola hasta la marca que toque.
# Van en \x12 y \x13 y no en un \x0b: el tabulador vertical es un espacio
# en blanco PARA PYTHON, y cualquier .strip() del camino se lo llevaba.
# El identificador de la sesion de pam_systemd. Tiene que ser el MISMO que
# SESION_LEYENDA en COWRIE FAKE ENVIRONMENT/sanitize-pickle.py, que es de donde
# sale el cgroup que lo lleva dentro.
SESION_LEYENDA = 89

MARCA_VUELTA = "\x12"
MARCA_FIN_BUCLE = "\x13"

# Un espacio DENTRO de ${...}. Hace falta para "${V: -2}", que en bash se
# escribe con espacio a la fuerza ---sin el, ":-" es otra cosa--- y al lexer
# le parecia el final del token: llegaba partido en "${V:" y "-2}".
ESPACIO_LLAVES = "\x11"
_COMODINES = {"*": ASTERISCO, "?": INTERROGA, "[": CORCHETE}

# El sitio donde estaba el "<<EOF" se marca en vez de borrarse. Hace falta
# para saber A QUE ORDEN alimenta: en "echo antes; cat <<EOF" el cuerpo es del
# cat, y dandoselo al primero de la linea el cat se quedaba esperando una
# entrada que no llegaba nunca... y con el, la sesion.
MARCA_HEREDOC = "\x07"

# LO QUE ES UNA LETRA PARA EL LEXER, en un solo sitio.
#
# Hay DOS lexers ---el de la linea y el del parentesis--- y estaban escritos
# por separado. Al anadir una marca nueva a uno y olvidarla en el otro, lo
# entrecomillado se partia solo dentro de los parentesis, que es la clase de
# fallo que aparece un mes despues y en un caso raro. Con una sola constante
# no puede volver a pasar.
#
# Cada trozo esta aqui por algo:
#   ()`      la sustitucion de ordenes
#   []!      "[ a != b ]": sin ellos test recibia cuatro argumentos
#   *?~      los comodines y el HOME, o "/etc/pass*" llegaba partido en dos
#   \x01-\x10  las marcas de lo que NO hay que expandir (ver arriba)
WORDCHARS_EXTRA = ("@%{}=$:+^,()`[]!*?~" + DOLAR_LITERAL + TILDE_LITERAL
                   + ESPACIO_LLAVES
                   + MARCA_VUELTA + MARCA_FIN_BUCLE
                   + SUST_INI + SUST_FIN
                   + LITERAL
                   + FRONTERA + ARIT_INI + ARIT_FIN + ALMOHADILLA
                   + MARCA_HEREDOC + ASTERISCO + INTERROGA + CORCHETE)


# --- Aritmetica: $(( ... )) -------------------------------------------------
#
# No estaba, y no fallaba callando: "$((" se parecia lo bastante a "$(" como
# para que la sustitucion de ordenes se lo llevara, asi que
#
#     echo $((2*3))   ->  -bash: 2*3: command not found
#
# Un bot que lleve un contador ---"i=$((i+1))"--- o que duerma un rato al
# azar ---"sleep $((RANDOM%10))"--- se encontraba con eso a mitad de guion.
class ErrorAritmetico(Exception):
    """Una expresion que bash no puede evaluar.

    Lleva el mensaje HECHO, porque bash no da uno solo: la division por cero
    es uno, y una expresion que no se entiende son otros tres distintos segun
    por que no se entienda. Contestar "division by 0" a un "((echo a))" ---que
    es lo que hacia--- es raro de leer y no lo dice ningun shell.
    """

    def __init__(self, mensaje: str = 'division by 0 (error token is "0")'):
        super().__init__(mensaje)
        self.mensaje = mensaje


# Lo que puede aparecer en una expresion aritmetica sin ser un nombre ni un
# numero. Cualquier otra cosa es un "invalid arithmetic operator" para bash.
_SIGNOS_ARIT = set("+-*/%<>=!&|^~?:(), \t#")


def error_de_sintaxis(expresion: str) -> str:
    """El mensaje EXACTO que da bash para una expresion que no cuadra.

    Son tres, y se eligen mirando por donde falla: un caracter que no pinta
    nada, un operador sin operando detras, o dos operandos seguidos. Medido
    con "((echo a))", "((1 +))", "((a b))" y "((x@y))" en un bash 5.2.
    """
    texto = expresion.strip()
    for i, c in enumerate(texto):
        if not (c.isalnum() or c == "_" or c in _SIGNOS_ARIT):
            return ('syntax error: invalid arithmetic operator '
                    '(error token is "%s")' % texto[i:])
    cola = re.search(r"([+\-*/%<>=!&|^~]+)\s*$", texto)
    if cola is not None:
        return ('syntax error: operand expected (error token is "%s")'
                % texto[cola.start():])
    seguidos = re.search(r"[A-Za-z_0-9]\s+([A-Za-z_0-9].*)$", texto)
    suelto = seguidos.group(1) if seguidos is not None else texto
    return 'syntax error in expression (error token is "%s")' % suelto


_OCTAL = re.compile(r"\b0[0-7]+\b")
# La notacion "base#digitos" de bash: 2#101, 16#ff, 8#17.
_BASE_N = re.compile(r"\b([2-9]|[1-5][0-9]|6[0-4])#([0-9a-zA-Z@_]+)")


def _de_base(m) -> str:
    try:
        return str(int(m.group(2), int(m.group(1))))
    except ValueError:
        return "0"


# Lo que en bash es una SENTENCIA aritmetica y no solo una expresion.
_INC_DETRAS = re.compile(r"^([A-Za-z_]\w*)\s*(\+\+|--)$")
_INC_DELANTE = re.compile(r"^(\+\+|--)\s*([A-Za-z_]\w*)$")
_ASIGNA = re.compile(
    r"^([A-Za-z_]\w*)\s*(=|\+=|-=|\*=|/=|%=|<<=|>>=|&=|\|=|\^=)\s*(.+)$",
    re.S)
_NOMBRE = re.compile(r"(?<![A-Za-z_0-9])[A-Za-z_][A-Za-z_0-9]*")

# Solo estos nodos. No es por elegancia: aqui entra texto del atacante, y
# pasarselo a eval() seria darle un interprete de Python dentro del senuelo.
_BINARIOS = {
    ast.Add: lambda a, b: a + b,
    ast.Sub: lambda a, b: a - b,
    ast.Mult: lambda a, b: a * b,
    ast.Pow: lambda a, b: a ** b,
    ast.LShift: lambda a, b: a << b,
    ast.RShift: lambda a, b: a >> b,
    ast.BitAnd: lambda a, b: a & b,
    ast.BitOr: lambda a, b: a | b,
    ast.BitXor: lambda a, b: a ^ b,
}
_COMPARA = {
    ast.Eq: lambda a, b: a == b, ast.NotEq: lambda a, b: a != b,
    ast.Lt: lambda a, b: a < b, ast.LtE: lambda a, b: a <= b,
    ast.Gt: lambda a, b: a > b, ast.GtE: lambda a, b: a >= b,
}


def _entero(nodo) -> int:
    if isinstance(nodo, ast.Constant) and isinstance(nodo.value, int) \
            and not isinstance(nodo.value, bool):
        return nodo.value
    if isinstance(nodo, ast.UnaryOp):
        valor = _entero(nodo.operand)
        if isinstance(nodo.op, ast.USub):
            return -valor
        if isinstance(nodo.op, ast.UAdd):
            return valor
        if isinstance(nodo.op, ast.Invert):
            return ~valor
        if isinstance(nodo.op, ast.Not):
            return int(not valor)
    if isinstance(nodo, ast.BinOp) and type(nodo.op) in _BINARIOS:
        izq, der = _entero(nodo.left), _entero(nodo.right)
        return _BINARIOS[type(nodo.op)](izq, der)
    if isinstance(nodo, ast.BinOp) and isinstance(nodo.op, (ast.Div,
                                                            ast.FloorDiv,
                                                            ast.Mod)):
        izq, der = _entero(nodo.left), _entero(nodo.right)
        if der == 0:
            raise ErrorAritmetico
        # BASH TRUNCA HACIA CERO, Python redondea hacia abajo: "-7/2" es -3
        # para bash y -4 para Python. El resto va con el mismo signo que el
        # dividendo, por lo mismo.
        if isinstance(nodo.op, ast.Mod):
            return izq - der * int(izq / der)
        return int(izq / der)
    if isinstance(nodo, ast.Compare) and len(nodo.ops) == 1 \
            and type(nodo.ops[0]) in _COMPARA:
        return int(_COMPARA[type(nodo.ops[0])](_entero(nodo.left),
                                               _entero(nodo.comparators[0])))
    if isinstance(nodo, ast.BoolOp):
        valores = [_entero(v) for v in nodo.values]
        if isinstance(nodo.op, ast.And):
            return int(all(valores))
        return int(any(valores))
    raise ErrorAritmetico("")


def evalua_aritmetica(expresion: str, entorno: dict) -> int:
    """El valor de lo que va dentro de $(( )).

    Un nombre que no sea un numero vale CERO, aunque no exista y aunque su
    contenido sea texto: "echo $((abc))" dice 0 en bash, no un error.
    """
    def por_valor(m):
        crudo = entorno.get(m.group(0), "0").strip()
        try:
            return str(int(crudo, 0))
        except (TypeError, ValueError):
            return "0"

    # El .strip() no es cosmetico: con un espacio delante, ast.parse en modo
    # "eval" lo toma por indentacion y falla, o sea que "$(( 1 + 1 ))" ---con
    # espacios, que es como lo escribe cualquiera--- daba error.
    # LA BASE. "2#101" son cinco, y sin traducirlo el "#101" se lo comia el
    # analizador como un comentario: "echo $((2#101))" decia 2.
    texto = _BASE_N.sub(_de_base, expresion.strip())
    texto = _NOMBRE.sub(por_valor, texto)
    # 010 son OCHO. Python no admite ceros a la izquierda, asi que se
    # traducen antes de analizar.
    texto = _OCTAL.sub(lambda m: str(int(m.group(0), 8)), texto)
    texto = texto.replace("&&", " and ").replace("||", " or ")
    try:
        arbol = ast.parse(texto, mode="eval")
    except SyntaxError:
        raise ErrorAritmetico(error_de_sintaxis(expresion)) from None
    try:
        return _entero(arbol.body)
    except ErrorAritmetico:
        raise
    except Exception:                                          # noqa: BLE001
        raise ErrorAritmetico(error_de_sintaxis(expresion)) from None


def evalua_sentencia(expresion: str, entorno: dict) -> int:
    """Lo mismo que evalua_aritmetica, pero ADEMAS asigna.

    En bash lo de dentro de (( )) y de $(( )) no es solo una cuenta: puede
    cambiar la variable ---"i++", "i+=3", "n=n*2"--- y eso es la mitad de lo
    que se escribe ahi. El evaluador de antes solo sabia leer, asi que un
    "((i++))" contestaba "-bash: i++: command not found" y el contador no
    avanzaba: cualquier bucle escrito asi daba vueltas sin moverse.

    Varias separadas por comas: se evaluan todas y vale la ultima.
    """
    valor = 0
    for trozo in _corta_fuera_de_comillas(expresion, ","):
        trozo = trozo.strip()
        if not trozo:
            continue
        m = _INC_DETRAS.match(trozo)
        if m is not None:
            nombre = m.group(1)
            valor = evalua_aritmetica(nombre, entorno)
            entorno[nombre] = str(valor + (1 if m.group(2) == "++" else -1))
            continue
        m = _INC_DELANTE.match(trozo)
        if m is not None:
            nombre = m.group(2)
            valor = evalua_aritmetica(nombre, entorno) \
                + (1 if m.group(1) == "++" else -1)
            entorno[nombre] = str(valor)
            continue
        m = _ASIGNA.match(trozo)
        if m is not None:
            nombre, operador, resto = m.group(1), m.group(2), m.group(3)
            if operador == "=":
                valor = evalua_aritmetica(resto, entorno)
            else:
                valor = evalua_aritmetica(
                    "(%s) %s (%s)" % (nombre, operador[:-1], resto), entorno)
            entorno[nombre] = str(valor)
            continue
        valor = evalua_aritmetica(trozo, entorno)
    return valor


# "((i++))" como orden suelta. Se reescribe a "let", que es su equivalente
# exacto en bash y ademas es un comando de verdad: asi pasa por donde pasan
# todos y queda registrado. Se pide que no lleve ";" dentro para no tocar el
# "for (( i=0; i<3; i++ ))" de estilo C, que no sabemos hacer y al que
# reescribir solo le cambiaria el error.
_ARIT_SENTENCIA = re.compile(r"(^|[;&|]\s*|\s)\(\(([^();]*)\)\)")


def sentencias_aritmeticas(linea: str) -> str:
    return _ARIT_SENTENCIA.sub(
        lambda m: m.group(1) + "let " + _entrecomilla(m.group(2)), linea)


def _cierra_parentesis(texto: str, desde: int) -> int:
    """El indice del "))" que cierra un "$((" abierto en `desde`."""
    hondo = 0
    i = desde
    while i < len(texto):
        if texto[i] == "(":
            hondo += 1
        elif texto[i] == ")":
            hondo -= 1
            if hondo == 0:
                return i
        i += 1
    return -1


# --- ${VAR:-...} y compania --------------------------------------------------
#
# Solo se entendian "$VAR" y "${VAR}" a secas. Todo lo demas se quedaba en
# pantalla tal cual ---"echo ${NOEX:-def}" imprimia "${NOEX:-def}"--- y son
# formas normales en un guion: el valor por defecto, la longitud y el recorte
# de extension. Medidas contra bash en un terminal de login.
_LLAVES = re.compile(r"\$\{([^{}]*)\}")


def _quita_patron(valor: str, patron: str, por_delante: bool,
                  el_mas_largo: bool) -> str:
    """El recorte de ${F#pat}, ${F##pat}, ${F%pat} y ${F%%pat}.

    El patron es de fichero ---con "*" y "?"---, no una expresion regular.
    """
    import fnmatch
    tamanos = range(len(valor), -1, -1) if el_mas_largo \
        else range(0, len(valor) + 1)
    for n in tamanos:
        trozo = valor[:n] if por_delante else valor[len(valor) - n:]
        if fnmatch.fnmatch(trozo, patron):
            return valor[n:] if por_delante else valor[:len(valor) - n]
    return valor


class FaltaVariable(Exception):
    """El "${V?mensaje}" con V sin definir.

    En bash eso NO es una expansion vacia: el shell avisa y NO EJECUTA el
    comando. Se sube como excepcion porque quien expande ---_expandir_ahora---
    esta demasiado abajo para decidir eso, y quien lanza el comando si.
    """

    def __init__(self, nombre: str, mensaje: str) -> None:
        super().__init__(mensaje)
        self.nombre = nombre
        self.mensaje = mensaje


# El nombre que va delante del operador dentro de ${...}. Antes no se parseaba:
# se buscaba el operador con dentro.find(marca) y el primero que apareciera
# ganaba, asi que ${V:1:2} no era nada y ${V/b/X} tampoco.
_NOMBRE_VAR = re.compile(r"[A-Za-z_][A-Za-z_0-9]*|[0-9]+|[@*?$]")


def _glob_a_regex(patron: str) -> str:
    """Un patron de fichero ---"*", "?", "[a-z]"--- a expresion regular.

    No vale fnmatch.translate(): ese ANCLA a los dos extremos, y ${V/pat/rep}
    busca EN MEDIO. El "*" se traduce a ".*" a proposito, que es codicioso:
    bash coge la coincidencia MAS LARGA de la posicion mas a la izquierda.
    """
    salida: list[str] = []
    i = 0
    while i < len(patron):
        c = patron[i]
        if c == "*":
            salida.append(".*")
        elif c == "?":
            salida.append(".")
        elif c == "[":
            j = i + 1
            if j < len(patron) and patron[j] in "!^":
                j += 1
            if j < len(patron) and patron[j] == "]":
                j += 1
            while j < len(patron) and patron[j] != "]":
                j += 1
            if j >= len(patron):
                salida.append(re.escape(c))
            else:
                clase = patron[i + 1:j]
                if clase[:1] == "!":
                    clase = "^" + clase[1:]
                salida.append("[" + clase + "]")
                i = j
        else:
            salida.append(re.escape(c))
        i += 1
    return "".join(salida)


def _sustituye(valor: str, spec: str) -> str:
    """${V/pat/rep}, ${V//pat/rep}, ${V/#pat/rep} y ${V/%pat/rep}."""
    todas = anclado_ini = anclado_fin = False
    if spec.startswith("/"):
        todas, spec = True, spec[1:]
    elif spec.startswith("#"):
        anclado_ini, spec = True, spec[1:]
    elif spec.startswith("%"):
        anclado_fin, spec = True, spec[1:]
    patron, sep, reemplazo = spec.partition("/")
    if not patron:
        return valor
    if not sep:
        reemplazo = ""
    expresion = _glob_a_regex(patron)
    if anclado_ini:
        expresion = "^(?:" + expresion + ")"
    elif anclado_fin:
        expresion = "(?:" + expresion + ")$"
    try:
        compilada = re.compile(expresion, re.S)
    except re.error:
        return valor
    # Con una funcion, no con la cadena: un reemplazo que lleve "\1" o "\\"
    # es LITERAL en bash y re.sub se lo tomaria como referencia de grupo.
    return compilada.sub(lambda _m: reemplazo, valor, count=0 if todas else 1)


def _cambia_caja(valor: str, marca: str) -> str:
    """${V^^}, ${V,,}, ${V^} y ${V,}."""
    if marca == "^^":
        return valor.upper()
    if marca == ",,":
        return valor.lower()
    if marca == "^":
        return valor[:1].upper() + valor[1:]
    return valor[:1].lower() + valor[1:]


def _subcadena(valor: str, spec: str, entorno: dict) -> str:
    """${V:desde} y ${V:desde:cuantos}, con los dos lados en aritmetica.

    Un "desde" negativo cuenta desde el final ---y por eso hay que escribirlo
    con espacio, ${V: -2}, o bash lo confunde con ${V:-w}---, y un "cuantos"
    negativo es una POSICION final, no una longitud.
    """
    desde, sep, cuantos = spec.partition(":")
    try:
        inicio = evalua_aritmetica(desde.strip(), entorno) if desde.strip() else 0
    except Exception:                                          # noqa: BLE001
        return ""
    if inicio < 0:
        inicio = max(0, len(valor) + inicio)
    if not sep:
        return valor[inicio:]
    try:
        cuenta = evalua_aritmetica(cuantos.strip(), entorno) if cuantos.strip() else 0
    except Exception:                                          # noqa: BLE001
        return ""
    if cuenta < 0:
        final = len(valor) + cuenta
        return valor[inicio:final] if final > inicio else ""
    return valor[inicio:inicio + cuenta]


def expande_llaves(tok: str, entorno: dict) -> str:
    def uno(m):
        dentro = m.group(1).replace(ALMOHADILLA, "#")
        if not dentro:
            return m.group(0)
        # ${#V} es la longitud; ${!V} el valor de la variable QUE NOMBRA V.
        if dentro[0] == "#" and len(dentro) > 1:
            return str(len(entorno.get(dentro[1:], "")))
        if dentro[0] == "!" and len(dentro) > 1:
            return entorno.get(entorno.get(dentro[1:], ""), "")

        emparejado = _NOMBRE_VAR.match(dentro)
        if emparejado is None:
            return m.group(0)
        nombre, op = emparejado.group(0), dentro[emparejado.end():]
        definida = nombre in entorno
        valor = entorno.get(nombre, "")

        if not op:
            # Sin definir se deja TAL CUAL, que es lo que salva a los
            # programas de awk y perl entrecomillados de la linea.
            return valor if definida else m.group(0)

        # ${V:-w} ${V:=w} ${V:?w} ${V:+w} y las mismas sin ":", que solo miran
        # si la variable EXISTE, no si esta vacia.
        marca = resto = None
        if op[:2] in (":-", ":=", ":?", ":+"):
            marca, resto = op[:2], op[2:]
        elif op[0] in "-=?+":
            marca, resto = op[0], op[1:]
        if marca is not None:
            vacio = (not valor) if marca.startswith(":") else (not definida)
            letra = marca[-1]
            if letra == "+":
                return "" if vacio else resto
            if not vacio:
                return valor
            if letra == "-":
                return resto
            if letra == "=":
                # ASIGNA DE VERDAD. Antes devolvia el valor y no lo guardaba,
                # asi que ${V:=x} salia bien una vez y el $V siguiente vacio.
                entorno[nombre] = resto
                return resto
            raise FaltaVariable(nombre, resto or "parameter null or not set")

        for prefijo, por_delante in (("##", True), ("#", True),
                                     ("%%", False), ("%", False)):
            if op.startswith(prefijo):
                return _quita_patron(valor, op[len(prefijo):],
                                     por_delante, len(prefijo) == 2)

        if op[0] == "/":
            return _sustituye(valor, op[1:])

        for prefijo in ("^^", ",,", "^", ","):
            if op.startswith(prefijo):
                return _cambia_caja(valor, prefijo)

        if op[0] == ":":
            return _subcadena(valor, op[1:], entorno)

        return m.group(0)

    return _LLAVES.sub(uno, tok)


# --- if / then / elif / else / fi -------------------------------------------
#
# No se entendian: "if" caia al troceo como si fuera un comando y una linea
# normal de guion contestaba tres errores seguidos:
#
#     if [ -f /etc/passwd ]; then echo si; fi
#     -bash: if: command not found
#     -bash: then: command not found
#     -bash: fi: command not found
#
# A diferencia de los bucles, un condicional NO se puede expandir mirando la
# linea: hay que EJECUTAR la condicion para saber que rama toca. Se ejecuta
# con la misma maquinaria que ya usa un parentesis, que devuelve la salida y
# el codigo, y luego se sigue con la rama elegida.
def _segmentos(linea: str) -> list:
    """Parte por los ";" que no estan entre comillas."""
    partes, actual, comilla = [], [], None
    for c in linea:
        if comilla:
            if c == comilla:
                comilla = None
        elif c in "\"'":
            comilla = c
        elif c == ";":
            partes.append("".join(actual))
            actual = []
            continue
        actual.append(c)
    partes.append("".join(actual))
    return [p.strip() for p in partes]


def parte_condicional(linea: str):
    """(ramas, si_no, cola) de un if de una linea, o None.

    `ramas` es [(condicion, cuerpo)] con el if y sus elif en orden.
    """
    segmentos = _segmentos(linea)
    if not segmentos or not re.match(r"^if\s", segmentos[0]):
        return None
    ramas, si_no, cola = [], None, []
    condicion, cuerpo, donde = [segmentos[0][3:].strip()], None, "condicion"
    # Un "if" dentro del cuerpo abre otro nivel: el "fi" que cierra el nuestro
    # es el que casa por profundidad. Sin esto, "if a; then if b; then x; fi;
    # fi" se cerraba en el primer "fi" y dejaba el segundo suelto.
    hondo = 0
    for seg in segmentos[1:]:
        if donde == "cola":
            cola.append(seg)
            continue
        if donde == "cuerpo" and re.match(r"^if\s", seg):
            hondo += 1
            cuerpo.append(seg)
            continue
        if hondo and (seg == "fi" or seg.startswith("fi ")):
            hondo -= 1
            cuerpo.append(seg)
            continue
        if seg == "fi" or seg.startswith("fi "):
            if cuerpo is not None:
                (ramas.append(("; ".join(condicion), "; ".join(cuerpo)))
                 if si_no is None else None)
            donde = "cola"
            resto = seg[2:].strip()
            if resto:
                cola.append(resto)
            continue
        if donde == "condicion":
            if re.match(r"^then\b", seg):
                primero = seg[4:].strip()
                cuerpo = [primero] if primero else []
                # El anidado puede entrar PEGADO al "then" ---"then if b"---
                # y entonces no pasa por la rama de mas abajo que cuenta los
                # niveles. Se cuenta aqui tambien o el "fi" de dentro cierra
                # el de fuera.
                if re.match(r"^if\s", primero):
                    hondo += 1
                donde = "cuerpo"
            else:
                condicion.append(seg)
            continue
        # donde == "cuerpo"
        if re.match(r"^elif\s", seg):
            ramas.append(("; ".join(condicion), "; ".join(cuerpo)))
            condicion, cuerpo, donde = [seg[4:].strip()], None, "condicion"
        elif re.match(r"^else\b", seg):
            ramas.append(("; ".join(condicion), "; ".join(cuerpo)))
            primero = seg[4:].strip()
            si_no = [primero] if primero else []
            if re.match(r"^if\s", primero):
                hondo += 1
            cuerpo = si_no
        else:
            cuerpo.append(seg)
    if donde != "cola" or not ramas:
        return None
    return (ramas, "; ".join(si_no) if si_no is not None else None,
            "; ".join(c for c in cola if c))


# --- case / esac ------------------------------------------------------------
#
# No se entendia: "case" caia al troceo como si fuera un comando. Y es de lo
# mas tecleado que hay en un dropper, porque es como se detecta la
# arquitectura antes de bajarse el binario que toca:
#
#     case $(uname -m) in x86_64|amd64) A=x86_64;; arm*) A=arm;; esac
#
# A diferencia del "if", este SI se puede resolver mirando la linea: los
# patrones son de fichero y no hay nada que ejecutar.
_CASE_RE = re.compile(r"^\s*case\s+(.+?)\s+in\s+(.*)$", re.S)

# --- Funciones de shell -----------------------------------------------------
#
# "f() { echo x; }" no se entendia: el troceo veia "f()" como un comando y
# "}" como otro, y contestaba dos "command not found" seguidos. Un guion que
# se define una funcion y la llama ---cosa normal en cuanto pasa de diez
# lineas--- no hacia absolutamente nada de lo que pedia.
_CABECERA_FUNCION = re.compile(
    r"^\s*(?:function\s+)?([A-Za-z_]\w*)\s*\(\s*\)\s*\{")


def parte_funcion(linea: str):
    """(nombre, cuerpo, lo que viene detras) de "f(){ ... }", o None.

    La llave de cierre se busca CONTANDO, no con una expresion regular. Con
    una, el cuerpo era ".*" codicioso y se llevaba hasta la ultima llave de
    la linea: en

        f(){ local x=5; }; f; echo [${x:-nada}]

    el cuerpo llegaba hasta el "}" del ${...} del final, el resto de la linea
    se perdia y el senuelo contestaba "]: command not found". Cualquier
    funcion seguida de una expansion con llaves ---o de otra funcion--- se
    partia por el sitio que no era.
    """
    cabecera = _CABECERA_FUNCION.match(linea)
    if cabecera is None:
        return None
    i = cabecera.end()
    hondura, comilla = 1, None
    while i < len(linea):
        c = linea[i]
        if comilla:
            if c == comilla:
                comilla = None
        elif c in "\"'":
            comilla = c
        elif linea.startswith("${", i):
            # Una expansion no abre bloque: se salta entera.
            i += 2
            continue
        elif c == "{":
            hondura += 1
        elif c == "}":
            hondura -= 1
            if hondura == 0:
                cola = linea[i + 1:].lstrip()
                if cola.startswith(";"):
                    cola = cola[1:]
                return (cabecera.group(1), linea[cabecera.end():i].strip(),
                        cola.strip())
        i += 1
    return None
_POSICIONAL = re.compile(r"\$\{?([0-9]|[@*#])\}?")


def cuerpo_con_argumentos(cuerpo: str, args: list) -> str:
    """Mete los argumentos en los $1, $@, $* y $# del cuerpo."""
    def uno(m):
        que = m.group(1)
        if que in ("@", "*"):
            return " ".join(args)
        if que == "#":
            return str(len(args))
        i = int(que)
        if i == 0:
            return "bash"
        return args[i - 1] if i <= len(args) else ""

    return _POSICIONAL.sub(uno, cuerpo)


def _sin_comillas(texto: str) -> str:
    texto = texto.strip()
    if len(texto) >= 2 and texto[0] == texto[-1] and texto[0] in "\"'":
        return texto[1:-1]
    return texto


def _corta_fuera_de_comillas(texto: str, marca: str) -> list:
    partes, actual, comilla = [], [], None
    i = 0
    while i < len(texto):
        c = texto[i]
        if comilla:
            if c == comilla:
                comilla = None
        elif c in "\"'":
            comilla = c
        elif texto.startswith(marca, i):
            partes.append("".join(actual))
            actual = []
            i += len(marca)
            continue
        actual.append(c)
        i += 1
    partes.append("".join(actual))
    return partes


def parte_case(linea: str):
    """(palabra, [(patrones, cuerpo)], cola) de un case, o None."""
    m = _CASE_RE.match(linea)
    if not m:
        return None
    palabra, resto = m.group(1), m.group(2)
    trozos = _corta_fuera_de_comillas(resto, "esac")
    if len(trozos) < 2:
        return None
    cuerpo_case, cola = trozos[0], "esac".join(trozos[1:])
    ramas = []
    for rama in _corta_fuera_de_comillas(cuerpo_case, ";;"):
        rama = rama.strip()
        if not rama:
            continue
        cierre = rama.find(")")
        if cierre < 0:
            return None
        patrones = [_sin_comillas(p)
                    for p in rama[:cierre].lstrip("(").split("|")]
        ramas.append((patrones, rama[cierre + 1:].strip()))
    if not ramas:
        return None
    return palabra, ramas, cola.lstrip(";").strip()


# --- Heredocs: cat <<EOF ----------------------------------------------------
#
# No se entendian, y no fallaban de una forma discreta: el "<<" se troceaba
# como una redireccion de entrada y contestaba
#
#     -bash: <: No such file or directory
#
# y despues EJECUTABA COMO ORDENES cada linea del contenido. Un
# "cat <<EOF > /tmp/x" ---que es como un dropper escribe un fichero sin
# descargarlo--- no escribia nada y ademas soltaba un "command not found" por
# cada linea del fichero que queria dejar.
#
# El delimitador puede ir entrecomillado, y eso cambia lo que pasa dentro:
# con <<EOF se expanden las variables y con <<'EOF' no. Y "<<-" quita los
# tabuladores del principio de cada linea, que es para poder indentar el
# cuerpo dentro de un bucle.
_HEREDOC_RE = re.compile(r"<<(-?)\s*(['\"]?)([A-Za-z_][A-Za-z_0-9]*)\2")


def busca_heredoc(linea: str):
    """(sin el operador, delimitador, quita_tabs, expandir) o None."""
    m = _HEREDOC_RE.search(linea)
    if not m:
        return None
    limpia = (linea[:m.start()] + MARCA_HEREDOC + linea[m.end():]).rstrip()
    return limpia, m.group(3), m.group(1) == "-", m.group(2) == ""


def proteger_comillas(linea: str) -> str:
    """Marca los "$" y "`" que el shell NO debe expandir.

    Las reglas son las de sh: dentro de comillas simples no se expande nada y
    ni siquiera valen las barras; dentro de dobles se expande, salvo lo que
    lleve barra delante; y fuera, una barra protege al caracter siguiente.
    """
    salida = []
    estado = "fuera"          # fuera | simples | dobles
    i = 0
    while i < len(linea):
        c = linea[i]
        # La aritmetica se guarda entera y codificada. Dentro de comillas
        # simples no, que ahi no se expande nada.
        # Lo de dentro de ${...} se protege de la almohadilla, que fuera es
        # el principio de un comentario.
        if estado != "simples" and linea.startswith("${", i):
            cierre = linea.find("}", i)
            if cierre > 0:
                salida.append(linea[i:cierre].replace("#", ALMOHADILLA)
                              .replace(" ", ESPACIO_LLAVES))
                salida.append("}")
                i = cierre + 1
                continue
        # "$#" a secas: el numero de parametros. Para el lexer esa almohadilla
        # abre un comentario y se comia el resto de la linea, asi que un
        # "echo $#" imprimia un dolar suelto.
        if estado != "simples" and linea.startswith("$#", i):
            salida.append("$" + ALMOHADILLA)
            i += 2
            continue
        if estado != "simples" and linea.startswith("$((", i):
            cierre = _cierra_parentesis(linea, i + 1)
            if cierre > 0:
                dentro = linea[i + 3:cierre - 1]
                salida.append(ARIT_INI + dentro.encode().hex() + ARIT_FIN)
                i = cierre + 1
                continue
        if estado == "simples":
            if c == "'":
                estado = "fuera"
                salida.append(FRONTERA)
            salida.append(DOLAR_LITERAL if c == "$"
                          else TILDE_LITERAL if c == "`"
                          else _COMODINES.get(c, c))
            i += 1
            continue
        if c == "\\" and i + 1 < len(linea):
            siguiente = linea[i + 1]
            if siguiente in "$`":
                # La barra desaparece y lo de detras queda literal, que es lo
                # que hace bash con "echo \$A".
                salida.append(DOLAR_LITERAL if siguiente == "$"
                              else TILDE_LITERAL)
                i += 2
                continue
            if siguiente in _COMODINES:
                salida.append(_COMODINES[siguiente])
                i += 2
                continue
            if siguiente in _ESCAPABLES:
                salida.append(LITERAL + "%02x" % ord(siguiente))
                i += 2
                continue
            salida.append(c)
            salida.append(siguiente)
            i += 2
            continue
        if c == "'" and estado == "fuera":
            estado = "simples"
            salida.append(FRONTERA)
        elif c == '"':
            estado = "dobles" if estado == "fuera" else "fuera"
            salida.append(FRONTERA)
        elif estado == "dobles":
            # Dentro de comillas dobles tampoco se expanden los comodines,
            # aunque las variables si.
            salida.append(_COMODINES.get(c, c))
            i += 1
            continue
        salida.append(c)
        i += 1
    return "".join(salida)


def restaurar_comillas(tok: str) -> str:
    tok = (tok.replace(DOLAR_LITERAL, "$").replace(TILDE_LITERAL, "`")
            .replace(ALMOHADILLA, "#").replace(ASTERISCO, "*")
            .replace(INTERROGA, "?").replace(CORCHETE, "[")
            .replace(ESPACIO_LLAVES, " ")
            .replace(FRONTERA, ""))
    # El LITERAL no se deshace AQUI a proposito: si un ">" escapado volviera a
    # ser un ">" antes de repartir la linea en tuberias y redirecciones, el
    # shell lo tomaria otra vez por un operador y estariamos donde estabamos.
    # Lo deshace restaura_literales(), ya con cada comando y sus argumentos
    # separados.
    return tok


def restaura_literales(tok: str) -> str:
    """Devuelve a su caracter los operadores que iban escapados con barra."""
    if LITERAL not in tok:
        return tok
    return re.sub(LITERAL + "([0-9a-f]{2})",
                  lambda m: chr(int(m.group(1), 16)), tok)


def _trozos_aritmeticos(tok: str):
    """Devuelve (antes, expresion, despues) del primer $(( )) codificado."""
    i = tok.find(ARIT_INI)
    if i < 0:
        return None
    j = tok.find(ARIT_FIN, i)
    if j < 0:
        return None
    try:
        expresion = bytes.fromhex(tok[i + 1:j]).decode()
    except ValueError:
        return None
    return tok[:i], expresion, tok[j + 1:]

# Single-line `for VAR in LIST; do BODY; done` construct
# El final: o un ";" y lo que venga detras, o una tuberia / una redireccion /
# un && pegados al "done". Lo segundo no se contemplaba ---la expresion pedia
# que la linea acabara ahi--- y un "for ...; done | wc -l" no era un bucle
# para nadie: contestaba un error de sintaxis.
_FINAL_BUCLE = (r"done\b\s*(?:;\s*(?P<cola>.*?)"
                r"|(?P<tuberia>(?:\|\||\||&&|>>|>|2>).*?))?\s*$")
_FOR_RE = re.compile(
    r"^\s*for\s+([A-Za-z_]\w*)\s+in\s+(.+?)\s*;\s*do\s+(.+?)\s*;?\s*"
    + _FINAL_BUCLE
)


def _seq_values(args: list[str]) -> list[str]:
    """Emulate coreutils seq for FIRST / FIRST LAST / FIRST STEP LAST."""
    try:
        nums = [float(x) for x in args]
    except ValueError:
        return []
    if len(nums) == 1:
        first, step, last = 1.0, 1.0, nums[0]
    elif len(nums) == 2:
        first, last = nums
        step = 1.0
    elif len(nums) == 3:
        first, step, last = nums
    else:
        return []
    if step == 0:
        return []
    intmode = all(n.is_integer() for n in nums)
    out: list[str] = []
    x = first
    while (step > 0 and x <= last + 1e-9) or (step < 0 and x >= last - 1e-9):
        out.append(str(int(x)) if intmode else f"{x:g}")
        x += step
        if len(out) > 100000:  # safety valve
            break
    return out


def _for_list_values(list_str: str, environ: dict[str, str]) -> list[str]:
    s = list_str.strip()
    # Las variables se resuelven ANTES de mirar la forma de la lista. Sin
    # esto, "for i in $(seq 1 $N)" le pasaba a seq un "$N" literal y la lista
    # salia vacia: el bucle no daba ni una vuelta y no decia nada.
    if "$" in s:
        s = _ENV_VAR_RE.sub(
            lambda m: environ.get(m.group(1) or m.group(2), m.group(0))
            if (m.group(1) or m.group(2)) in environ else m.group(0), s)
    # $(seq ...) or `seq ...`
    m = re.match(r"^\$\(\s*seq\s+(.+?)\s*\)$", s) or re.match(
        r"^`\s*seq\s+(.+?)\s*`$", s
    )
    if m:
        return _seq_values(m.group(1).split())
    # brace range {a..b} or {a..b..step}
    m = re.match(r"^\{(-?\d+)\.\.(-?\d+)(?:\.\.(-?\d+))?\}$", s)
    if m:
        a, b = int(m.group(1)), int(m.group(2))
        st = int(m.group(3)) if m.group(3) else (1 if b >= a else -1)
        if st == 0:
            return []
        vals = []
        x = a
        while (st > 0 and x <= b) or (st < 0 and x >= b):
            vals.append(str(x))
            x += st
            if len(vals) > 100000:
                break
        return vals
    # $var / ${var}
    if s.startswith("$"):
        name = s[1:].strip("{}")
        return environ.get(name, "").split()
    # literal whitespace-separated word list
    return s.split()


_ARRANQUE_BUCLE = re.compile(r"^\s*(for|while|until|if|case)\s")

# "algo | while read VAR; do ...; done", que es como se recorre un fichero
# linea a linea en cualquier guion. El "while" no arrancaba la linea, asi que
# no lo miraba nadie: caia al troceo y contestaba "while: command not found".
_TUBERIA_A_BUCLE = re.compile(
    r"^(?P<izq>.+?)\s*\|\s*while\s+(?P<cond>.+?)\s*;\s*do\s+"
    r"(?P<cuerpo>.+?)\s*;?\s*done\b\s*(?:;\s*(?P<cola>.*?))?\s*$")

# La condicion de ese while, cuando es un "read": "IFS= read -r linea".
_LEE = re.compile(
    r"^(?:IFS=(?P<ifs>\S*)\s+)?read\b(?P<opciones>(?:\s+-\w+)*)"
    r"(?P<nombres>(?:\s+[A-Za-z_]\w*)*)\s*$")

# Tope de vueltas al recorrer una entrada linea a linea. Un fichero enorme
# convertiria la linea expandida en algo inmanejable, y lo que se busca es
# que el guion del atacante siga, no procesar un log entero.
_MAX_LINEAS_LEIDAS = 200


def _entrecomilla(valor: str) -> str:
    """El valor, en comillas simples, listo para volver a pasar por el shell."""
    return "'" + valor.replace("'", "'\\''") + "'"


def reparte_campos(linea: str, nombres: list, ifs_vacio: bool) -> list:
    """Lo que hace "read" con una linea: parte en campos y el ULTIMO se
    queda con todo lo que sobra.

    Con IFS vacio ---"IFS= read -r l"--- no parte ni recorta nada, que es
    justo para lo que se escribe asi.
    """
    if not nombres:
        nombres = ["REPLY"]
    if ifs_vacio:
        return [(nombres[0], linea)] + [(n, "") for n in nombres[1:]]
    campos = linea.split()
    salida = []
    for i, nombre in enumerate(nombres):
        if i == len(nombres) - 1:
            # Al ULTIMO le toca lo que sobre, pero SIN los espacios de los
            # bordes: "read l" sobre "  a  " deja l valiendo "a", no "a  ".
            resto = linea.split(None, i)
            salida.append((nombre, resto[i].rstrip() if len(resto) > i else ""))
        else:
            salida.append((nombre, campos[i] if i < len(campos) else ""))
    return salida


def parte_antes_de_bucle(linea: str):
    """Separa "A=1; for i in $A; do ...; done" en sus dos mitades.

    Los bucles se expanden ANTES de trocear, leyendo el entorno tal y como
    esta en ese momento. Si la asignacion va en la MISMA linea, todavia no ha
    corrido, asi que la lista del "for" salia vacia... y como
    expand_for_loops solo mira lineas que EMPIECEN por "for", ni siquiera se
    intentaba: el "for" caia al troceo como si fuera un comando y contestaba
    "for: command not found".

    Devuelve (lo de antes, el bucle) o None. Lo de antes se ejecuta primero y
    el bucle se encola como una linea mas de guion, que es la maquinaria que
    ya existe para que "ARCHS=...\nfor a in $ARCHS" funcione en dos lineas.

    El ";" tiene que ser un separador de VERDAD: uno dentro de comillas
    ---"echo 'a; for b'"--- no parte nada.
    """
    estado = None
    for i, c in enumerate(linea):
        if estado is None:
            if c in "\"'":
                estado = c
            elif c == ";" and _ARRANQUE_BUCLE.match(linea[i + 1:]):
                antes, resto = linea[:i].strip(), linea[i + 1:].strip()
                # Solo si lo de detras es un bucle o un condicional COMPLETO
                # de los que se saben expandir. Partir por partir cambiaria un
                # "while: command not found" por un error de sintaxis, que no
                # es mejor: seria mover el fallo, no arreglarlo.
                if antes and (_FOR_RE.match(resto) or _WHILE_RE.match(resto)
                              or parte_condicional(resto) is not None
                              or parte_case(resto) is not None):
                    return antes, resto
            elif c == ";" and _TUBERIA_A_BUCLE.match(linea[i + 1:]):
                # "A=1; cat $A | while read l; do ...; done": lo de delante
                # tiene que correr ANTES, o la tuberia se lee con el entorno
                # viejo.
                antes, resto = linea[:i].strip(), linea[i + 1:].strip()
                if antes:
                    return antes, resto
        elif c == estado:
            estado = None
    return None


def _con_cola(expandido: str, m) -> str:
    """Pega lo que iba DETRAS del "done".

    Las dos expresiones pedian que la linea terminara ahi, asi que
    "for i in a b; do echo $i; done; echo fin" no era un bucle para nadie: ni
    se expandia ni se avisaba, caia al troceo y contestaba
    "for: command not found". Y encadenar algo detras de un bucle es lo normal
    en un guion.
    """
    # UNA TUBERIA DETRAS DEL "done" SE LLEVA LA SALIDA DEL BUCLE ENTERO, no
    # la de su ultima vuelta. Se envuelve en un parentesis, que es lo que
    # significa, y de ahi en adelante lo lleva la maquinaria de los grupos.
    tuberia = (m.groupdict().get("tuberia") or "").strip()
    if tuberia:
        return "(%s) %s" % (expandido, tuberia) if expandido else ""
    cola = (m.groupdict().get("cola") or "").strip()
    if not cola:
        return expandido
    return expandido + "; " + cola if expandido else cola


def expand_for_loops(line: str, environ: dict[str, str]) -> str:
    """Expand a single-line for-loop into a ';'-joined command sequence.

    Returns the line unchanged when it is not a for-loop, so non-matching
    input keeps Cowrie's normal parsing behaviour (no regression).
    """
    m = _FOR_RE.match(line)
    if not m:
        return line
    var, list_str, body = m.group(1), m.group(2), m.group(3)
    values = _for_list_values(list_str, environ)
    if not values:
        return ""
    ref_brace = re.compile(r"\$\{" + re.escape(var) + r"\}")
    ref_plain = re.compile(r"\$" + re.escape(var) + r"(?![A-Za-z0-9_])")
    cmds = []
    for v in values:
        b = ref_brace.sub(v, body)
        b = ref_plain.sub(v, b)
        cmds.append(MARCA_VUELTA + "; " + b)
    return _con_cola("; ".join(cmds) + "; " + MARCA_FIN_BUCLE, m)


# Single-line `while COND; do BODY; done`. The condition is not evaluated; the
# body is run a small bounded number of times so `while true; do ... ; done`
# never turns into an infinite loop that would hang the session.
_WHILE_RE = re.compile(
    r"^\s*while\s+(.+?)\s*;\s*do\s+(.+?)\s*;?\s*" + _FINAL_BUCLE
)
_WHILE_MAX_ITER = 3


def expand_while_loops(line: str) -> str:
    m = _WHILE_RE.match(line)
    if not m:
        return line
    condicion = m.group(1).strip()
    # LA CONDICION NO SE EVALUA, y por una razon: "while true" no puede dar
    # vueltas de verdad o cuelga la sesion, asi que el cuerpo se ejecuta un
    # numero corto de veces y ya. Pero las dos condiciones CONSTANTES si se
    # miran, que son gratis y estaban dando lo contrario de lo que deben:
    # "while false; do echo x; done" imprimia tres x donde bash no imprime
    # nada. Lo demas ---"while [ -f x ]", "while read linea"--- sigue con el
    # numero corto de vueltas.
    if condicion == "false":
        return _con_cola("", m)
    body = m.group(2)
    vueltas = [MARCA_VUELTA + "; " + body] * _WHILE_MAX_ITER
    return _con_cola("; ".join(vueltas) + "; " + MARCA_FIN_BUCLE, m)


# Compound-command keywords for detecting an unfinished construct (PS2 '> ').
_COMPOUND_OPEN = re.compile(r"\b(if|for|while|until|select|case)\b")
_COMPOUND_CLOSE = re.compile(r"\b(fi|done|esac)\b")
_COMPOUND_LEAD = re.compile(r"^\s*(if|for|while|until|select|case)\b")
_CONT_MAX_LINES = 200  # safety valve: give up buffering after this many lines


def comillas_abiertas(texto: str) -> bool:
    """True si queda una comilla sin cerrar.

    ESTO ES LO QUE HACE QUE BASH SIGA LEYENDO cuando alguien pega un bloque
    entre comillas: un `python3 -c "..."` de varias lineas, un `bash -c`, un
    `node -e`. Bash saca su prompt '> ' y no ejecuta nada hasta que la comilla
    se cierra, porque hasta entonces el salto de linea es UN CARACTER MAS del
    texto, no el final de la orden.

    Sin esto, la primera linea se ejecutaba sola y las demas llegaban como
    ordenes sueltas. En el log del senuelo se veia esto, que no lo hace ningun
    Linux:

        ORDEN                                python3 -c 'import socket
        ORDEN                                for h,p in [(...)]:
        ORDEN QUE EL SENUELO NO SUPO EJECUTAR    s.settimeout(4)
        ORDEN QUE EL SENUELO NO SUPO EJECUTAR    try:

    Y no es un detalle: el atacante que dejo ese rastro estaba probando tres
    formas de llegar a una base de datos ---psql, node y python--- y las tres
    pasan por pegar un bloque entre comillas.

    Las reglas son las de bash, que no son simetricas:

      - Dentro de comilla SIMPLE no hay escapes: ni la barra invertida. Una
        comilla simple solo la cierra otra comilla simple.
      - Dentro de comilla DOBLE, la barra invertida escapa a la siguiente.
      - Fuera de comillas, la barra invertida escapa a la siguiente.
    """
    comilla: str | None = None
    i = 0
    while i < len(texto):
        c = texto[i]
        if comilla == "'":
            if c == "'":
                comilla = None
        elif comilla == '"':
            if c == "\\" and i + 1 < len(texto):
                i += 1
            elif c == '"':
                comilla = None
        elif c == "\\" and i + 1 < len(texto):
            i += 1
        elif c in "'\"":
            comilla = c
        i += 1
    return comilla is not None


def command_incomplete(text: str) -> bool:
    """True when ``text`` is an unfinished compound command that bash would
    keep reading with a ``> `` continuation prompt.

    Only inputs that BEGIN with a shell keyword (``if``/``for``/``while``/
    ``until``/``select``/``case``) can be "incomplete" this way — this avoids
    misreading an ordinary command that merely contains a word like ``if`` or
    ``for`` (e.g. ``cat if.txt``, ``grep -w for file``) as unfinished. Also
    continues on an odd trailing backslash (explicit line continuation).
    """
    stripped = text.rstrip()
    # explicit line continuation: line ends with an ODD number of backslashes
    trailing = len(stripped) - len(stripped.rstrip("\\"))
    if trailing % 2 == 1:
        return True
    # Una comilla sin cerrar, que es la forma en que llega un bloque pegado.
    # Va ANTES de mirar las palabras compuestas porque no tiene nada que ver
    # con ellas: `python3 -c "import socket` no empieza por "for" ni por "if".
    if comillas_abiertas(text):
        return True
    if not _COMPOUND_LEAD.match(text):
        return False
    opens = len(_COMPOUND_OPEN.findall(text))
    closes = len(_COMPOUND_CLOSE.findall(text))
    return opens > closes


# Detras de estas palabras NO va un punto y coma: "for x in 1 2; do; echo" no
# es un bucle para nadie. Al unir con "; " a secas, un bucle escrito en varias
# lineas ---que es como se escriben--- salia con un "do;" y la expresion que
# los reconoce pide "do" y luego el cuerpo, asi que contestaba
# "syntax error near unexpected token `newline'".
_SIN_PUNTO_Y_COMA = ("do", "then", "else", "in", "{")


def flatten_continuation(lines: list[str]) -> str:
    """Join buffered continuation lines into a single ';'-separated command so
    the existing single-line loop expanders can handle it."""
    # LO QUE QUEDO ABIERTO FUE UNA COMILLA: se juntan con un salto de linea DE
    # VERDAD y sin tocar la sangria. Dentro de unas comillas el salto es un
    # caracter mas del texto y la sangria es parte del programa que va dentro:
    # juntando con "; " y recortando los espacios, al `python3 -c` le llegaba
    # todo en una linea y contestaba un IndentationError que un python de
    # verdad no da nunca ahi. Se mira la PRIMERA linea, que es la que abrio.
    if lines and comillas_abiertas(lines[0]):
        return "\n".join(lines)

    parts = [ln.strip() for ln in lines if ln.strip()]
    if not parts:
        return ""
    salida = parts[0]
    for parte in parts[1:]:
        # UN punto y coma, no todos: en un "case", el ";;" que cierra una rama
        # es parte de la sintaxis y quitarlo entero junta dos ramas en una.
        anterior = salida.rstrip()
        if anterior.endswith(";") and not anterior.endswith(";;"):
            anterior = anterior[:-1].rstrip()
        ultima = anterior.rsplit(None, 1)[-1] if anterior else ""
        # Y detras de un ";;" tampoco: ese ya cierra la rama de un "case".
        pega = ultima in _SIN_PUNTO_Y_COMA or anterior.endswith(";;")
        salida = anterior + (" " if pega else "; ")
        salida += parte
    return salida


_REDIR_OPS = (">", ">>", ">&", "<", "<&")


def merge_redirection_tokens(tokens: list[str]) -> list[str]:
    """Glue a file descriptor back onto its redirection: `2` `>` -> `2>`.

    The lexer runs with punctuation_chars=True, which splits `2>/dev/null`
    into ['2', '>', '/dev/null']. That stray '2' then gets treated as a
    command and the shell answers "2: command not found", which no real shell
    would ever say. Since `cmd >/dev/null 2>&1` shows up in nearly every
    attack script, leaving it split gives the honeypot away immediately.

    This lives here, and not in cowrie.shell.parser, on purpose: that module
    is stock Cowrie and is not mounted into the container, so a helper placed
    there would silently not exist -- which is exactly the crash this function
    fixes (AttributeError: 'CommandParser' object has no attribute
    'merge_redirection_tokens').

    Known trade-off: `echo 2 > f` and `echo 2> f` tokenize identically because
    the lexer has already dropped the whitespace by the time we get here, so
    both are treated as a redirection. The first form is rare and the second
    is everywhere, so merging is the right side to err on.
    """
    merged: list[str] = []
    i = 0
    total = len(tokens)

    while i < total:
        token = tokens[i]
        following = tokens[i + 1] if i + 1 < total else None

        if token.isdigit() and following in _REDIR_OPS:
            token += following
            i += 2
        else:
            i += 1

        # `2>& 1` and `>& 2`: the target descriptor is part of the operator.
        if token.endswith("&") and token[:-1].endswith((">", "<")):
            if i < total and tokens[i].isdigit():
                token += tokens[i]
                i += 1

        merged.append(token)

    return merged


# El LS_COLORS que exporta un usuario normal. NO esta escrito a mano: es la
# salida literal de "dircolors -b" de un Debian 13, que es lo que ejecuta el
# ~/.bashrc de /etc/skel ---y el nuestro, que lo trae en su linea 76---. root
# no lo tiene porque el /root/.bashrc de Debian trae esa parte comentada.
LS_COLORS = (
    "rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:"
    "cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=00:tw=30;42:"
    "ow=34;42:st=37;44:ex=01;32:*.7z=01;31:*.ace=01;31:*.alz=01;31:"
    "*.apk=01;31:*.arc=01;31:*.arj=01;31:*.bz=01;31:*.bz2=01;31:"
    "*.cab=01;31:*.cpio=01;31:*.crate=01;31:*.deb=01;31:*.drpm=01;31:"
    "*.dwm=01;31:*.dz=01;31:*.ear=01;31:*.egg=01;31:*.esd=01;31:"
    "*.gz=01;31:*.jar=01;31:*.lha=01;31:*.lrz=01;31:*.lz=01;31:"
    "*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.lzo=01;31:*.pyz=01;31:"
    "*.rar=01;31:*.rpm=01;31:*.rz=01;31:*.sar=01;31:*.swm=01;31:"
    "*.t7z=01;31:*.tar=01;31:*.taz=01;31:*.tbz=01;31:*.tbz2=01;31:"
    "*.tgz=01;31:*.tlz=01;31:*.txz=01;31:*.tz=01;31:*.tzo=01;31:"
    "*.tzst=01;31:*.udeb=01;31:*.war=01;31:*.whl=01;31:*.wim=01;31:"
    "*.xz=01;31:*.z=01;31:*.zip=01;31:*.zoo=01;31:*.zst=01;31:"
    "*.avif=01;35:*.jpg=01;35:*.jpeg=01;35:*.jxl=01;35:*.mjpg=01;35:"
    "*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:"
    "*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:"
    "*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:"
    "*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:"
    "*.mkv=01;35:*.webm=01;35:*.webp=01;35:*.ogm=01;35:*.mp4=01;35:"
    "*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:"
    "*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:"
    "*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:"
    "*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:"
    "*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:"
    "*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:"
    "*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:"
    "*.opus=00;36:*.spx=00;36:*.xspf=00;36:*~=00;90:*#=00;90:*.bak=00;90:"
    "*.crdownload=00;90:*.dpkg-dist=00;90:*.dpkg-new=00;90:"
    "*.dpkg-old=00;90:*.dpkg-tmp=00;90:*.old=00;90:*.orig=00;90:"
    "*.part=00;90:*.rej=00;90:*.rpmnew=00;90:*.rpmorig=00;90:"
    "*.rpmsave=00;90:*.swp=00;90:*.tmp=00;90:*.ucf-dist=00;90:"
    "*.ucf-new=00;90:*.ucf-old=00;90:"
)

class HoneyPotShell:
    def __init__(
        self, protocol: Any, interactive: bool = True, redirect: bool = False,
        dash: bool = False
    ) -> None:
        self.protocol = protocol
        self.interactive: bool = interactive
        self.redirect: bool = redirect  # to support output redirection
        # EN DEBIAN, /bin/sh ES dash, NO bash. Cowrie los trataba igual: `sh`
        # abria otra shell identica a la de la sesion, con el mismo prompt de
        # bash, asi que parecia que la orden no hacia nada ---y `exit` salia
        # de una shell que el atacante no sabia que existia---.
        #
        # Todo lo que distingue a este modo esta MEDIDO contra dash 0.5.12
        # (el de trixie) en un pseudo-terminal, no recordado. Ver showPrompt()
        # y command_not_found_message().
        self.dash: bool = dash
        # Con que nombre se invoco. dash lo usa en sus errores tal cual.
        self.nombre_sh: str = getattr(protocol, "_nombre_invocado", "sh") or "sh"
        # dash numera las lineas que recibe y las nombra en sus errores
        # ("sh: 2: asd: not found"). Cuenta TAMBIEN las que funcionan.
        self.linea_dash: int = 0
        self.cmdpending: list[list[str]] = []
        self.cmdfondo: list[bool] = []
        # Heredoc a medias: la orden que espera su cuerpo, y el cuerpo.
        self.heredoc: tuple | None = None
        self.heredoc_lineas: list[str] = []
        self.heredoc_datos: bytes | None = None
        # Las funciones que se haya definido el atacante en esta sesion.
        self.funciones: dict[str, str] = {}
        # Lineas de un guion (`./w`, `sh w`) que aun no se han ejecutado. Ver
        # lineReceived: se ejecutan de UNA EN UNA, no todas de golpe.
        self.lineas_de_guion: list[str] = []
        # shell/script.py lo lee al acabar un `./guion`. Lo ASIGNA la
        # maquinaria de Cowrie al terminar cada comando, pero si el guion no
        # ejecuta ninguno no llegaria a existir, y leerlo daria AttributeError.
        self.last_exit_code: int = 0
        # Buffer for multi-line (PS2 '> ') continuation of an unfinished
        # compound command; empty means we are at a normal PS1 prompt.
        self.cont_buffer: list[str] = []
        # Operator (';' / '&&' / '||') linking each cmdpending group to the
        # previous one, and the exit status of the last command run — together
        # these drive '&&'/'||' short-circuiting and '$?'.
        self.cmdops: list[str] = []
        self.last_status: int = 0
        # Lo que deja un parentesis al capturarse, hasta que el tokenizador lo
        # mete en la cola. Ver _capturar_subshell().
        self._subshell_pendiente: tuple[str, str | None, bool] | None = None
        # A nested shell (e.g. a command substitution) inherits the live
        # environment of whichever shell is currently running; the very first
        # shell of a session falls back to the login environment, all of which
        # is exported.
        if protocol.cmdstack:
            parent = protocol.cmdstack[-1]
            self.environ: dict[str, str] = copy.copy(parent.environ)
            self.exported: set[str] = copy.copy(parent.exported)
        else:
            self.environ = copy.copy(protocol.environ)
            self.exported = set(protocol.environ.keys())
        if hasattr(protocol.user, "windowSize"):
            self.environ["COLUMNS"] = str(protocol.user.windowSize[1])
            self.environ["LINES"] = str(protocol.user.windowSize[0])

        # TERM, que por telnet no lo pone nadie.
        #
        # Cowrie lo fija en getPty(), y getPty es una peticion del PROTOCOLO
        # SSH: por el 23 no se llama nunca. Resultado: en una sesion de telnet
        # "echo $TERM" devolvia vacio y "env" no lo listaba siquiera. En una
        # sesion de verdad ---por SSH o por telnet--- TERM SIEMPRE esta puesto;
        # es de lo primero que mira cualquier cosa que dibuje en pantalla, y un
        # TERM vacio no se explica en una maquina que acaba de darte un prompt.
        #
        # Se pone por defecto y no se pisa el de SSH: si getPty ya trajo el del
        # cliente, ese es el bueno y es un dato real del atacante.
        if not self.environ.get("TERM"):
            self.environ["TERM"] = "xterm"
            self.exported.add("TERM")

        self._completar_entorno(protocol)

        # /var/log/auth.log, SOLO en la shell de la sesion.
        #
        # La maquina declara rsyslog.service activo y el dpkg lo da por
        # instalado, pero el contenedor de construccion nunca lo arranca ---y
        # rsyslog solo crea sus ficheros al correr--- asi que el fichero no
        # existia. Un demonio de registro funcionando sin registro es la
        # contradiccion, y ese fichero lo mira todo el mundo: quien entra
        # comprueba si su acceso quedo anotado.
        #
        # Se genera aqui y no se guarda en el pickle por lo mismo que
        # /proc/uptime: ahi nace correcto y a los cinco minutos miente. Y
        # peor, porque cron abre una sesion PAM cada hora.
        #
        # Solo para la PRIMERA shell: las que abre un `bash` o una tuberia no
        # son un login nuevo y no deben reescribir nada.
        if not protocol.cmdstack:
            try:
                from cowrie.commands.authlog import generar

                generar(protocol)
            except Exception:                              # noqa: BLE001
                pass
        self.lexer: shlex.shlex | None = None
        self.parser = CommandParser()

        # No showPrompt() here on purpose. Cowrie's own
        # HoneyPotInteractiveProtocol.connectionMade() does:
        #
        #     self.cmdstack = [honeypot.HoneyPotShell(self)]
        #     self.cmdstack[0].showPrompt()
        #
        # so printing it here as well painted the prompt twice on login
        # ("user@host:~$ user@host:~$"), which no real shell does and which
        # gives the honeypot away before the attacker types anything.
        #
        # Whoever creates a shell is responsible for its first prompt: the
        # protocol does it for the session shell, and bash.py does it for the
        # nested shell it spawns.

    def _emit(self, eventid: str, fmt: str, **kwargs) -> None:
        """Publish an event where the output plugins will actually hear it.

        Cowrie 3.x dispatches events through protocol.events.dispatch(). The
        old form, log.msg(eventid=...), still writes to the text log but never
        reaches the output plugins, so the event silently vanishes from
        cowrie.json and from the Telegram alerts with no error anywhere. That
        is what kept every executed command from being reported: logins came
        from stock code and showed up, ours did not.

        log.msg stays as a fallback so the module keeps working if it is ever
        run against a Cowrie old enough not to have the dispatcher.
        """
        events = getattr(self.protocol, "events", None)
        if events is not None:
            events.dispatch(eventid, fmt, **kwargs)
        else:
            log.msg(eventid=eventid, format=fmt, **kwargs)

    # ------------------------------------------------------------------
    # Un guion entero llega de golpe, con sus saltos de linea
    # ------------------------------------------------------------------
    #
    # Cuando el atacante hace `./w` o `sh w`, Cowrie no lee el fichero linea a
    # linea: entrega el TEXTO COMPLETO aqui. Su comentario en shell/script.py
    # lo dice ---"newlines separate statements... rather than joined onto one
    # line"--- pero su shell no lo cumplia: el salto de linea acababa dentro
    # de un unico comando y un `for ... done` en la linea 3 se perdia. Eso es
    # justo lo que traen los guiones de Mirai, asi que no se capturaba nada.
    #
    # CUIDADO CON COMO SE ARREGLA. El primer intento fue trocear y llamar a
    # lineReceived una vez por linea. Ejecutaba bien ---la salida salia--- pero
    # DEJABA LA SESION COLGADA: lineReceived termina en runCommand(), que es
    # ASINCRONO, asi que se lanzaban varias tuberias solapadas sobre el mismo
    # shell, se pisaba cmdpending y el prompt no volvia nunca.
    #
    # Tampoco vale juntar las lineas con ';': la expansion de bucles necesita
    # que `ARCHS=...` se haya EJECUTADO antes de expandir `for a in $ARCHS`, y
    # juntandolas se expande el bucle cuando la variable aun no existe.
    #
    # Asi que se ejecutan DE UNA EN UNA: aqui se guarda la cola y se procesa
    # solo la primera linea; runCommand, al vaciar cmdpending, coge la
    # siguiente. Ese es el mismo punto por el que Cowrie ya encadena los
    # comandos de un "a; b; c", asi que no se toca el modelo asincrono.
    # Cuantas veces se intenta resolver compuestos encadenados en una linea.
    # Cada vuelta se come uno; el tope es para que una linea rara no de vueltas
    # para siempre y se lleve la sesion por delante.
    _MAX_COMPUESTOS = 100

    def _resuelve_compuestos(self, line: str) -> str | None:
        """Come "if", "case" y lo que va DELANTE de un compuesto.

        Devuelve lo que queda por ejecutar, o None si no queda nada.

        Estaba escrito en linea dentro de lineReceived() y solo pasaba UNA
        vez, antes de desenrollar los bucles. Eso dejaba sin resolver los
        condicionales del CUERPO de un bucle, que es donde mas se usan.
        """
        for _ in range(self._MAX_COMPUESTOS):
            try:
                condicional = parte_condicional(line)
            except Exception as e:                             # noqa: BLE001
                log.msg(f"if parse error: {e}")
                condicional = None
            if condicional is not None:
                ramas, si_no, cola = condicional
                elegido = si_no
                for condicion, cuerpo in ramas:
                    salida, estado = \
                        self._execute_single_command_with_redirect(condicion)
                    if salida:
                        # La condicion puede imprimir ---"if grep root
                        # fichero"--- y esa salida sale en pantalla, como en
                        # un shell de verdad. Solo el codigo decide la rama.
                        self.protocol.terminal.write(salida.encode())
                    if estado == 0:
                        elegido = cuerpo
                        break
                line = "; ".join(x for x in (elegido, cola) if x)
                if not line.strip():
                    return None
                continue

            try:
                elegido_case = parte_case(line)
            except Exception as e:                             # noqa: BLE001
                log.msg(f"case parse error: {e}")
                elegido_case = None
            if elegido_case is not None:
                import fnmatch
                palabra, ramas, cola = elegido_case
                # La palabra puede ser una variable o una sustitucion, asi que
                # se expande antes de comparar. Con "$(uname -m)" es lo unico
                # que hace falta ejecutar de todo el case.
                palabra = _sin_comillas(palabra)
                if "$(" in palabra or "`" in palabra:
                    palabra = self.do_command_substitution(palabra).strip()
                palabra = _sin_comillas(self.expand_variables(palabra))
                cuerpo = ""
                for patrones, texto in ramas:
                    if any(fnmatch.fnmatchcase(palabra, p) for p in patrones):
                        cuerpo = texto
                        break
                line = "; ".join(x for x in (cuerpo, cola) if x)
                if not line.strip():
                    return None
                continue

            # UN "while" SE MIRA ANTES DE PARTIR NADA. Si no, cuando su
            # cuerpo lleva un "if" ---que es lo normal--- el troceador de
            # "lo que va delante de un compuesto" corta por ese if y deja un
            # "while ...; do ..." a medias, que ya no es un bucle para nadie.
            girado = self._da_una_vuelta(line)
            if girado is not None:
                line = girado
                if not line.strip():
                    return None
                continue

            # Un compuesto DETRAS de otra cosa en la misma linea: se ejecuta
            # primero lo de delante y el resto se encola, para que su lista se
            # expanda con el entorno ya actualizado. Ver parte_antes_de_bucle().
            partido = parte_antes_de_bucle(line)
            if partido is not None:
                antes, resto = partido
                self.lineas_de_guion = [resto] + self.lineas_de_guion
                return antes

            try:
                reescrito = self._bucle_por_tuberia(line)
            except Exception as e:                             # noqa: BLE001
                # Nunca por delante de la sesion: un fallo aqui deja la linea
                # como estaba y se sigue.
                log.msg(f"pipe-to-while error: {e}")
                reescrito = None
            if reescrito is not None:
                line = reescrito
                if not line.strip():
                    return None
                continue

            return line
        return line

    def en_while_evaluado(self) -> bool:
        """True mientras un "while" con condicion evaluada esta dando vueltas.

        Ese bucle no deja marcas por delante ---se reemite el solo en cada
        vuelta--- asi que "break" y "continue" no las encuentran y creerian
        estar fuera de un bucle.
        """
        return getattr(self, "_vueltas_dadas", 0) > 0

    def corta_while(self, del_todo: bool) -> None:
        """El "break" y el "continue" de un while evaluado.

        Lo que queda por delante en la cola es: el resto del cuerpo de esta
        vuelta y, al final, el propio bucle reemitido. Con "continue" se tira
        el cuerpo y se deja el bucle, que volvera a mirar la condicion; con
        "break" se tira todo, y la cola de despues del "done" sigue en pie
        porque se aparto en la primera vuelta.
        """
        if del_todo:
            self.cmdpending, self.cmdops, self.cmdfondo = [], [], []
            pelado = getattr(self, "_while_en_curso", "")
            if pelado:
                self.lineas_de_guion = [l for l in self.lineas_de_guion
                                        if pelado not in l]
            self._vueltas_dadas = 0
            self._while_en_curso = ""
            return
        # "continue": se tira lo que queda del CUERPO ---la cola de ordenes---
        # y se deja en pie la de lineas, donde esta el bucle reemitido: esa es
        # la vuelta siguiente. El contador no se toca, que la vuelta cuenta.
        self.cmdpending, self.cmdops, self.cmdfondo = [], [], []

    def hay_bucle_pendiente(self, marcas: str) -> bool:
        """¿Queda por delante una marca de bucle? Es lo que distingue un
        "break" dentro de un bucle de uno suelto, que bash solo avisa."""
        if any(c in tok for grupo in self.cmdpending
               for tok in grupo for c in marcas):
            return True
        return any(c in linea for linea in self.lineas_de_guion
                   for c in marcas)

    def salta_hasta(self, marcas: str) -> None:
        """Tira ordenes de la cola hasta pasar la marca. Es "break" y es
        "continue".

        Se hace por CIRUGIA sobre las colas y no con una bandera que vaya
        saltando ordenes de una en una, porque por el camino hay condicionales
        que habria que EJECUTAR para saber por donde siguen, y la condicion de
        una vuelta que ya no se va a dar no debe correr: puede imprimir.
        """
        # "continue" busca la vuelta siguiente O el final del bucle, lo que
        # venga antes: en la ULTIMA vuelta ya no hay siguiente y lo que hace
        # es acabar, no quejarse.
        for i, grupo in enumerate(self.cmdpending):
            if any(c in tok for tok in grupo for c in marcas):
                del self.cmdpending[:i + 1]
                del self.cmdops[:min(i + 1, len(self.cmdops))]
                del self.cmdfondo[:min(i + 1, len(self.cmdfondo))]
                return
        self.cmdpending, self.cmdops, self.cmdfondo = [], [], []
        for i, linea in enumerate(self.lineas_de_guion):
            sitios = [linea.find(c) for c in marcas if c in linea]
            if not sitios:
                continue
            donde = min(sitios)
            resto = linea[donde + 1:].lstrip()
            if resto.startswith(";"):
                resto = resto[1:].lstrip()
            self.lineas_de_guion = ([resto] if resto else []) \
                + self.lineas_de_guion[i + 1:]
            return
        # Sin marca por delante no hay bucle del que salir: no queda nada.
        self.lineas_de_guion = []

    # Cuantas vueltas como mucho antes de rendirse. NO es el numero de vueltas
    # que da un bucle: es el tope para que un "while true" no se lleve la
    # sesion por delante. Un bucle que termina para antes solo.
    _MAX_VUELTAS_WHILE = 100

    def _da_una_vuelta(self, line: str) -> str | None:
        """Un "while": EJECUTA la condicion y decide si toca otra vuelta.

        Antes no se evaluaba. El cuerpo se repetia tres veces y ya, asi que

            i=0; while [ $i -lt 2 ]; do echo x; i=$((i+1)); done

        imprimia tres x donde van dos, y con cinco vueltas habria impreso tres.
        El numero de vueltas de cualquier bucle contado estaba mal SIEMPRE, y
        contar es justo para lo que se usa un while.

        Se puede evaluar porque aqui SI hay con que ejecutar ---es el mismo
        sitio donde se resuelve la condicion de un "if"---, y lo que se
        devuelve es una vuelta mas el propio bucle otra vez: cuando la
        condicion falle, lo que quede sera la cola. Termina solo, y si no
        termina lo para el tope.
        """
        m = _WHILE_RE.match(line)
        if m is None:
            return None
        # CON UNA TUBERIA DETRAS, NO. La salida de un bucle entero entra en la
        # tuberia, y eso pide envolverlo en un parentesis con TODAS las
        # vueltas dentro; aqui las vueltas se generan de una en una y no hay
        # forma de meterlas en el mismo grupo. Ese caso se queda con el
        # desenrollado acotado de siempre, que da un numero de vueltas fijo
        # pero no se lleva la sesion por delante.
        if (m.groupdict().get("tuberia") or "").strip():
            return None
        condicion = m.group(1).strip()
        cuerpo = m.group(2)
        # El bucle sin su cola, para reemitirlo tal cual en cada vuelta.
        pelado = "while %s; do %s; done" % (condicion, cuerpo)

        dadas = getattr(self, "_vueltas_dadas", 0)
        if not dadas:
            # LA COLA SE APARTA EN LA PRIMERA VUELTA, antes de mirar nada. Si
            # viajara dentro de la linea que se reemite, un "break" ---que
            # tira la cola de ordenes pendiente--- se llevaria por delante lo
            # que va DESPUES del "done", y eso si se ejecuta en bash.
            cola = (m.groupdict().get("cola") or "").strip()
            if cola:
                self.lineas_de_guion = [cola] + self.lineas_de_guion
        if dadas >= self._MAX_VUELTAS_WHILE:
            # Un bucle sin fin. Se corta y se sigue con lo que venga detras,
            # que es lo unico que se puede hacer sin colgar la sesion.
            self._vueltas_dadas = 0
            return MARCA_FIN_BUCLE

        if condicion in ("true", ":"):
            sigue = True
        elif condicion == "false":
            sigue = False
        else:
            _salida, estado = self._execute_single_command_with_redirect(
                condicion)
            if _salida:
                # Una condicion puede imprimir, como en un "if".
                self.protocol.terminal.write(_salida.encode())
            sigue = estado == 0

        if not sigue:
            self._vueltas_dadas = 0
            self._while_en_curso = ""
            return MARCA_FIN_BUCLE

        self._vueltas_dadas = dadas + 1
        # Se guarda el texto EXACTO del bucle: un "break" tiene que poder
        # quitarlo de la cola de lineas, no solo de la de ordenes. Si no, lo
        # unico que consigue es empezar el bucle otra vez desde cero ---y como
        # ademas pone el contador a cero, nunca llega al tope: da vueltas
        # hasta que revienta la pila.
        self._while_en_curso = pelado
        # Una vuelta, y el bucle otra vez detras: la condicion se vuelve a
        # mirar con el entorno ya cambiado por el cuerpo. Sin la cola, que ya
        # esta apartada.
        return "%s; %s; %s" % (MARCA_VUELTA, cuerpo, pelado)

    def _bucle_por_tuberia(self, line: str) -> str | None:
        """Convierte "algo | while read V; do CUERPO; done" en algo ejecutable.

        Es como se recorre un fichero linea a linea en cualquier guion, y no
        funcionaba de ninguna manera: el "while" no arrancaba la linea, asi
        que ni el desenrollado lo miraba, y caia al troceo como un comando
        ---"-bash: while: command not found"---.

        Aqui NO se desenrolla a ojo: se ejecuta la parte de la izquierda, se
        cogen sus lineas y se da una vuelta por cada una, con la variable
        puesta. Es lo que hace el bucle de verdad, y ademas es lo unico que
        deja que el cuerpo vea el contenido.

        Devuelve la linea ya expandida, o None si esto no era eso.
        """
        emparejado = _TUBERIA_A_BUCLE.match(line)
        if emparejado is None:
            return None
        lectura = _LEE.match(emparejado.group("cond").strip())
        if lectura is None:
            # "algo | while [ -f x ]; do ...": no lee la entrada, asi que no
            # hay nada que repartir. Se deja para el desenrollado de siempre.
            return None

        salida, _estado = self._execute_single_command_with_redirect(
            emparejado.group("izq").strip())
        lineas = salida.split("\n")
        if lineas and lineas[-1] == "":
            # El ultimo salto no abre una vuelta mas: "read" devuelve falso
            # con la entrada agotada.
            lineas.pop()

        nombres = lectura.group("nombres").split()
        # "IFS=" a secas ---la forma de no recortar nada--- deja el grupo
        # vacio; sin prefijo llega a None, que no es lo mismo.
        ifs_vacio = lectura.group("ifs") == ""
        cuerpo = emparejado.group("cuerpo")
        vueltas = []
        for texto in lineas[:_MAX_LINEAS_LEIDAS]:
            asignaciones = "; ".join(
                "%s=%s" % (nombre, _entrecomilla(valor))
                for nombre, valor in reparte_campos(texto, nombres, ifs_vacio))
            vueltas.append(MARCA_VUELTA + "; " + asignaciones + "; " + cuerpo)
        cola = (emparejado.group("cola") or "").strip()
        return "; ".join(vueltas + [MARCA_FIN_BUCLE]
                         + ([cola] if cola else []))

    def lineReceived(self, line: str) -> None:
        if "\n" in line and not self.interactive:
            lineas = [t.strip() for t in line.split("\n")]
            lineas = [t for t in lineas if t and not t.startswith("#")]
            if not lineas:
                self.runCommand()
                return
            self.lineas_de_guion = lineas[1:] + self.lineas_de_guion
            line = lineas[0]

        self._emit("cowrie.command.input", "CMD: %(input)s", input=line)
        self.linea_dash += 1

        # --- Heredoc en curso: se recoge el cuerpo hasta el delimitador -----
        if self.heredoc is not None:
            orden, delim, quita_tabs, expandir = self.heredoc
            cuerpo = line[1:] if quita_tabs and line.startswith("\t") else line
            if (line.strip() if quita_tabs else line) == delim:
                texto = "".join(l + "\n" for l in self.heredoc_lineas)
                if expandir:
                    texto = self.expand_variables(texto)
                self.heredoc = None
                self.heredoc_lineas = []
                # El cuerpo se le da al comando como entrada estandar, que es
                # lo que es: "cat <<EOF" es un cat leyendo de ahi.
                self.heredoc_datos = texto.encode()
                line = orden
            else:
                self.heredoc_lineas.append(cuerpo)
                if self.interactive:
                    self.showContinuationPrompt()
                return

        marca = busca_heredoc(line)
        if marca is not None:
            orden, delim, quita_tabs, expandir = marca
            self.heredoc = (orden, delim, quita_tabs, expandir)
            self.heredoc_lineas = []
            if self.interactive:
                self.showContinuationPrompt()
            return

        # --- Multi-line continuation (PS2 '> ') --------------------------------
        # Interactive bash keeps reading with a '> ' prompt until an unfinished
        # compound command (while/for/if/case without its terminator, or a
        # trailing backslash) is complete. Non-interactive shells (pipes, sh -c,
        # command substitution) never prompt, so they skip this path.
        if self.interactive:
            if self.cont_buffer:
                self.cont_buffer.append(line)
                combined = "\n".join(self.cont_buffer)
                if len(self.cont_buffer) < _CONT_MAX_LINES and command_incomplete(
                    combined
                ):
                    self.showContinuationPrompt()
                    return
                lines = self.cont_buffer
                self.cont_buffer = []
                line = flatten_continuation(lines)
            elif command_incomplete(line):
                self.cont_buffer = [line]
                self.showContinuationPrompt()
                return
        # ----------------------------------------------------------------------

        # "((i++))" es una orden, no un parentesis: se reescribe a "let" antes
        # de que el troceador vea esos parentesis y lo tome por un subshell.
        # Sin esto contestaba "-bash: i++: command not found" y el contador
        # no se movia, o sea que un bucle escrito asi daba vueltas sin
        # avanzar.
        reescrito_arit = line
        if "((" in line:
            reescrito_arit = sentencias_aritmeticas(line)
        # De quien se queja bash si la cuenta no cuadra: de "((" si se
        # escribio asi, de "let" si se escribio let. Aqui es el unico sitio
        # que lo sabe, porque despues de la reescritura ya no se distinguen.
        self.protocol._arit_parentesis = reescrito_arit != line
        line = reescrito_arit

        # Los "if", los "case" y lo que va DELANTE de un compuesto. En bucle:
        # cada vuelta se come uno, y la rama elegida puede traer otro.
        resuelto = self._resuelve_compuestos(line)
        if resuelto is None:
            self._fin_de_linea()
            return
        line = resuelto

        # Una DEFINICION de funcion: se guarda y se sigue con lo que venga
        # detras. No se ejecuta nada del cuerpo hasta que la llamen.
        definicion = parte_funcion(line)
        if definicion is not None:
            self.funciones[definicion[0]] = definicion[1]
            line = definicion[2]
            if not line:
                self._fin_de_linea()
                return

        # Expand single-line for/while loops before tokenizing so attacker
        # loops execute instead of failing with "for: command not found".
        # Non-loop input is returned unchanged (no regression).
        try:
            expanded = expand_for_loops(line, self.environ)
            if expanded == line:
                # El "while" normal lo lleva _da_una_vuelta(), que EJECUTA su
                # condicion. Aqui solo llega el que tiene una tuberia detras,
                # que ese si necesita el desenrollado acotado: ver el comentario
                # de _da_una_vuelta().
                expanded = expand_while_loops(line)
        except Exception as e:
            log.msg(f"loop expansion error: {e}")
            expanded = line
        if expanded != line:
            if expanded == "":
                self._fin_de_linea()
                return
            line = expanded
            # OTRA VUELTA. El cuerpo de un bucle puede llevar un "if" o un
            # "case", y para cuando el bucle se desenrolla ya se ha pasado por
            # ahi: un "for i in 1 2 3; do if [ $i = 2 ]; then ...; fi; done"
            # contestaba TRES "command not found" por vuelta ---if, then y
            # fi--- y ademas ejecutaba las dos ramas.
            resuelto = self._resuelve_compuestos(line)
            if resuelto is None:
                self._fin_de_linea()
                return
            line = resuelto
        else:
            # A loop keyword that did not form a construct we can expand: emit a
            # bash-style syntax error instead of "for: command not found".
            if re.match(r"^\s*(for|while|until)\s", line):
                self.protocol.terminal.write(
                    b"-bash: syntax error near unexpected token `newline'\n"
                )
                self._fin_de_linea()
                return
            kw = re.match(r"^\s*(done|do|then|fi|esac)(?:\s|;|$)", line)
            if kw:
                self.protocol.terminal.write(
                    f"-bash: syntax error near unexpected token `{kw.group(1)}'\n".encode()
                )
                self._fin_de_linea()
                return
        # El lexer va en posix, o sea que tira las comillas. Lo que NO debe
        # expandirse se marca antes de que las toque; ver proteger_comillas().
        self.lexer = shlex.shlex(instream=proteger_comillas(line),
                                 punctuation_chars=True, posix=True)
        # Add these special characters that are not in the default lexer
        self.lexer.wordchars += WORDCHARS_EXTRA

        tokens: list[str] = []
        # Reset the per-line operator list; next_op is the operator that will
        # link the NEXT completed group to the previous one.
        self.cmdops = []
        # Paralela a cmdpending: dice si el grupo lleva un "&" detras. Va
        # aparte y no dentro de los tokens para no tener que distinguirla de
        # un argumento que se llame igual.
        self.cmdfondo = []
        next_op = ";"
        # True justo despues de encolar un parentesis, que es un operando sin
        # tokens: ver el "&&"/"||" de mas abajo.
        recien_subshell = False
        al_fondo = False

        while True:
            try:
                tokkie: str | None = self.lexer.get_token()
                # log.msg("tok: %s" % (repr(tok)))

                if tokkie is None:  # self.lexer.eof put None for mypy
                    if tokens:
                        self.cmdpending.append(tokens)
                        self.cmdops.append(next_op)
                        self.cmdfondo.append(al_fondo)
                    break
                else:
                    tok: str = tokkie

                # EL PARENTESIS PEGADO AL OPERADOR.
                #
                # shlex agrupa los signos de puntuacion seguidos, asi que
                # "||(" llega como UN token, no como "||" y "(". Y "||(" no
                # es "||" para nadie, asi que se colaba como una palabra mas:
                #
                #     chmod 777 i ||(cp /bin/ls ii; ...)
                #     -> chmod: cannot access '||(': No such file or directory
                #
                # chmod se comia el operador como si fuera un fichero. Con un
                # espacio delante funcionaba, pero los bots lo escriben
                # siempre pegado, que es justo el caso que hay que emular.
                #
                # Se parte aqui y no en el texto de la linea a proposito: aqui
                # el lexer ya ha resuelto las comillas, asi que un "||(" que
                # el atacante escriba ENTRECOMILLADO llega como palabra y no
                # se toca.
                # El parentesis se pega al token SIGUIENTE, no se devuelve
                # suelto: con espacio, el lexer entrega "(echo" en una pieza,
                # y el resto del parser cuenta con esa forma. Devolviendo un
                # "(" a solas, el ")" del final se quedaba sin pareja y salia
                # impreso ("SI)" en vez de "SI").
                _pegado = _OPERADOR_PEGADO.match(tok)
                if _pegado:
                    _siguiente = self.lexer.get_token()
                    self.lexer.push_token(
                        _pegado.group(2) + (_siguiente if _siguiente else ""))
                    tok = _pegado.group(1)

                # && / || are recorded so runCommand can short-circuit; ; is
                # unconditional. Empty left-hand side is a syntax error.
                if tok == "&&" or tok == "||":
                    if tokens:
                        self.cmdpending.append(tokens)
                        self.cmdops.append(next_op)
                        self.cmdfondo.append(al_fondo)
                        next_op = tok
                        tokens = []
                        continue
                    elif recien_subshell:
                        # UN PARENTESIS TAMBIEN ES UN OPERANDO. Se encola
                        # aparte, asi que al llegar aqui `tokens` esta vacio y
                        # esto se tomaba por un "&&" sin nada a la izquierda:
                        #
                        #     (false) || echo respaldo
                        #     -> "syntax error near unexpected token `||'"
                        #
                        # Lo de la derecha no llegaba a ejecutarse nunca. El
                        # caso contrario ---"algo || (respaldo)"--- si
                        # funcionaba, y es el que mas se ve, por eso aguanto
                        # tanto sin verse.
                        recien_subshell = False
                        next_op = tok
                        continue
                    else:
                        self.protocol.terminal.write(
                            f"-bash: syntax error near unexpected token `{tok}'\n".encode()
                        )
                        break
                elif tok == "&":
                    # UN "&" SUELTO NO ES UN ARGUMENTO. Antes se colaba como
                    # una palabra mas y "echo b &" imprimia "b &". Separa como
                    # un ";" y ademas manda al fondo lo que va delante.
                    if tokens:
                        self.cmdpending.append(tokens)
                        self.cmdops.append(next_op)
                        self.cmdfondo.append(True)
                        next_op = ";"
                        tokens = []
                    continue
                elif tok == ";":
                    recien_subshell = False
                    if tokens:
                        self.cmdpending.append(tokens)
                        self.cmdops.append(next_op)
                        self.cmdfondo.append(al_fondo)
                        al_fondo = False
                        next_op = ";"
                        tokens = []
                    continue
                elif tok == "$?":
                    tok = MARCA_ESTADO
                elif tok == "(" or (tok.startswith("(") and not tok.startswith("$(")):
                    # Parentheses can only appear at the start of a command, not in the middle
                    if tokens:
                        # Parentheses in the middle of a command line is a syntax error
                        self.protocol.terminal.write(
                            f"-bash: syntax error near unexpected token `{tok}'\\n".encode()
                        )
                        break
                    if tok == "(":
                        self.do_subshell_execution_from_lexer()
                    else:
                        self.do_subshell_execution(tok)
                    # El parentesis entra en la cola como un grupo mas, con el
                    # operador que lo precede. Asi runCommand puede cortarlo
                    # con un && o un || y lo ejecuta EN SU SITIO, no antes que
                    # lo que va delante.
                    capturado = self._subshell_pendiente
                    self._subshell_pendiente = None
                    if capturado is not None:
                        self.cmdpending.append([
                            MARCA_SUBSHELL, capturado[0], capturado[1] or "",
                            "1" if capturado[2] else "0",
                            *capturado[3]])
                        self.cmdops.append(next_op)
                        self.cmdfondo.append(al_fondo)
                        next_op = ";"
                        recien_subshell = True
                    continue
                elif re.search(r"\$\((?!\()", tok) or "`" in tok:
                    # Un "$(" que NO sea "$((": lo segundo es aritmetica y la
                    # resuelve _expandir_ahora al ejecutar, no aqui, porque
                    # necesita las variables ya asignadas.
                    tok = self.do_command_substitution(tok, aplazar=True)

                # LAS VARIABLES NO SE EXPANDEN AQUI. Se dejan tal cual y las
                # resuelve runCommand() justo antes de ejecutar cada comando.
                #
                # Aqui se expandia la linea ENTERA de una vez, y eso hacia que
                # una asignacion no la viera lo que venia detras en la misma
                # linea:
                #
                #     A=uno; echo $A      -> no imprimia nada
                #     A=uno; echo x${A}y  -> imprimia "x${A}y"
                #
                # que en bash dicen "uno" y "xunoy". Y no es que
                # expand_variables no sepa hacerlo: sabe. Era CUANDO se
                # llamaba. En lineas separadas funcionaba, porque para
                # entonces la asignacion ya habia corrido.
                #
                # El camino ya estaba abierto y probado: "$?" se aplaza asi
                # desde hace tiempo, con MARCA_ESTADO, y por el mismo motivo
                # ---su valor tampoco se sabe hasta que llega el turno del
                # comando---. Esto extiende el mismo tratamiento al resto.

                tokens.append(tok)
            except Exception as e:
                self.protocol.terminal.write(
                    b"-bash: syntax error: unexpected end of file\n"
                )
                # Could run runCommand here, but i'll just clear the list instead
                log.msg(f"exception: {e}")
                self.cmdpending = []
                self._fin_de_linea()
                return

        if self.cmdpending:
            # Coalesce fd redirection tokens so we don't treat `2` as a command
            self.cmdpending = [
                merge_redirection_tokens(tokens)
                for tokens in self.cmdpending
            ]
            # if we have a complete command, go and run it
            self.runCommand()
        else:
            # if there's no command, display a prompt again
            self._fin_de_linea()

    # ------------------------------------------------------------------
    # El entorno de una sesion de verdad
    # ------------------------------------------------------------------
    #
    # Cowrie monta el entorno en dos sitios (shell/session.py para SSH y
    # telnet/session.py para el 23) y en los dos se queda corto. Se completa
    # aqui, y no ahi, porque los dos ficheros se llaman "session.py": el
    # cmdpatch aplana todos los modulos en una sola carpeta y chocarian.
    #
    # Lo que sigue esta MEDIDO, no recordado: un Debian 13 con openssh-server y
    # inetutils-telnetd, entrando por las dos vias como root y como usuario
    # normal, y comparando "printenv" y "set".
    #
    # Lo que Cowrie ponia de mas:
    #
    #   TMOUT=1800   Un Debian NO lo pone. Es un valor de Cowrie, y ademas
    #                delata al que lo busca: TMOUT solo aparece en maquinas
    #                endurecidas a mano, no en un PC de trabajo.
    #   UID          Existe, pero como variable de SHELL. Bash NO la exporta,
    #                asi que en un Linux real "printenv UID" no devuelve nada
    #                aunque "echo $UID" si. Igual COLUMNS y LINES.
    #
    # Lo que faltaba, y por que cada una:
    #
    #   PWD          La pone el shell. Se refresca antes de cada comando en
    #                runCommand(), porque el "cd" la cambia.
    #   SHLVL        Por SSH ya estaba; por telnet no.
    #   MAIL         SOLO por telnet: la pone /bin/login, y sshd no. Medido:
    #                por SSH no aparece y por telnet vale /var/mail/<usuario>.
    #   SSH_CLIENT   SOLO por SSH, claro. Su ausencia es de lo primero que
    #   SSH_CONNECTION   mira un script que quiere saber si esta en una sesion
    #   SSH_TTY      remota de verdad.
    #   MOTD_SHOWN   La pone pam_motd, que esta en la pila PAM de sshd y no en
    #                la de login. Tambien medido en las dos vias.
    #   LS_COLORS    Solo para los usuarios normales: su ~/.bashrc ejecuta
    #                "dircolors", y el /root/.bashrc de Debian lo trae
    #                comentado. Por eso root NO la tiene.
    #   XDG_*        Las pone pam_systemd. Nuestro ps_command_output.json
    #                declara systemd-logind y hasta un "systemd --user", asi
    #                que una sesion sin estas variables se contradice con
    #                nuestro propio "ps aux".
    #
    # Y las de bash que solo salen en "set": BASH, BASH_VERSION, HOSTTYPE...
    # La version no se inventa: nuestro dpkg declara bash 5.2.37-2+b9, que es
    # el que dice "5.2.37(1)-release".

    BASH_VERSION = "5.2.37(1)-release"

    def _marcar_ultimo(self, orden: str, ruta_path: str) -> None:
        """Deja en "_" la ruta del programa, como hace bash antes de ejecutar."""
        if not orden:
            return
        destino = orden
        if not orden.startswith((".", "/")):
            for carpeta in [d for d in ruta_path.split(":") if d]:
                candidato = f"{carpeta}/{orden}"
                if self.protocol.fs.exists(candidato):
                    destino = candidato
                    break
        self.environ["_"] = destino
        self.exported.add("_")

    def _completar_entorno(self, protocol) -> None:
        usuario = getattr(getattr(protocol, "user", None), "username", "root")
        uid = getattr(getattr(protocol, "user", None), "uid", 0)
        hogar = self.environ.get("HOME") or ("/root" if uid == 0 else f"/home/{usuario}")
        por_telnet = "Telnet" in type(protocol).__name__

        # --- lo que sobraba ---------------------------------------------
        self.environ.pop("TMOUT", None)
        self.exported.discard("TMOUT")
        for nombre in ("UID", "COLUMNS", "LINES"):
            self.exported.discard(nombre)

        # --- exportadas que faltaban ------------------------------------
        def exporta(nombre, valor):
            self.environ[nombre] = valor
            self.exported.add(nombre)

        exporta("PWD", getattr(protocol, "cwd", None) or hogar)
        exporta("SHLVL", "1")

        if por_telnet:
            exporta("MAIL", f"/var/mail/{usuario}")
        else:
            ip_cliente = getattr(protocol, "clientIP", "127.0.0.1")
            ip_servidor = ip_del_servidor(
                getattr(protocol, "kippoIP", "127.0.0.1"))
            puerto = getattr(protocol, "realClientPort", 0) or random.randint(32768, 60999)
            # El puerto del servidor es el 22 y no el 2222 en que escucha
            # Cowrie: el atacante entro por el 22, que es lo que el DNAT
            # traduce, y es lo que veria un sshd de verdad en esta maquina.
            exporta("SSH_CLIENT", f"{ip_cliente} {puerto} 22")
            exporta("SSH_CONNECTION", f"{ip_cliente} {puerto} {ip_servidor} 22")
            # pts/0 y no otro: es el que ensenan nuestro "ps", "who" y "w".
            exporta("SSH_TTY", "/dev/pts/0")
            exporta("MOTD_SHOWN", "pam")

        if uid != 0:
            exporta("LS_COLORS", LS_COLORS)

        # pam_systemd. El identificador de sesion es corto y crece con los
        # logins; en una maquina levantada hace meses cae en estas decenas.
        #
        # FIJO, NO AL AZAR. Se sorteaba uno en cada login, y ese numero
        # tambien va dentro del cgroup de la sesion ---
        # "0::/user.slice/user-0.slice/session-89.scope"--- que vive en el
        # pickle y es el mismo para todas. Con uno al azar,
        # "echo $XDG_SESSION_ID" y "cat /proc/self/cgroup" se desmentian en
        # dos ordenes seguidas. El numero manda desde SESION_LEYENDA en
        # sanitize-pickle.py y una prueba cruza los dos ficheros.
        exporta("XDG_SESSION_ID", str(SESION_LEYENDA))
        exporta("XDG_RUNTIME_DIR", f"/run/user/{uid}")
        exporta("XDG_SESSION_TYPE", "tty")
        exporta("XDG_SESSION_CLASS", "user")

        # --- variables de SHELL: se ven en "set", no en "printenv" -------
        # Lo que el ~/.bashrc de /etc/skel deja puesto en una sesion
        # INTERACTIVA. No es teoria: se comprobo con un bash -i leyendo ese
        # mismo fichero, el mismo que el atacante puede abrir con un "cat".
        # Un .bashrc que declara cosas y un shell que no las cumple es una
        # contradiccion a un solo comando de distancia.
        #
        # root NO las tiene: su /root/.bashrc de Debian trae esa parte
        # comentada, y por eso su historial se queda en los 500/500 que pone
        # bash por defecto.
        if uid != 0:
            self.environ.setdefault("HISTCONTROL", "ignoreboth")
            self.exported.discard("HISTCONTROL")
            # alias ls='ls --color=auto', dentro del "if [ -x /usr/bin/dircolors ]"
            # del propio .bashrc. Las demas del fichero van comentadas.
            if not getattr(protocol, "aliases", None):
                protocol.aliases = {"ls": "ls --color=auto"}
        elif not hasattr(protocol, "aliases"):
            protocol.aliases = {}

        historial = ("500", "500") if uid == 0 else ("1000", "2000")
        de_shell = {
            "BASH": "/bin/bash",
            "BASH_VERSION": self.BASH_VERSION,
            "BASHOPTS": (
                "checkwinsize:cmdhist:complete_fullquote:expand_aliases:extquote:"
                "force_fignore:globasciiranges:globskipdots:hostcomplete:"
                "interactive_comments:patsub_replacement:progcomp:promptvars:"
                "sourcepath"
            ),
            "DIRSTACK": "()",
            "EUID": str(uid),
            "UID": str(uid),
            "HISTFILE": f"{hogar}/.bash_history",
            "HISTSIZE": historial[0],
            "HISTFILESIZE": historial[1],
            "HOSTNAME": getattr(protocol, "hostname", "localhost"),
            "HOSTTYPE": "x86_64",
            "MACHTYPE": "x86_64-pc-linux-gnu",
            "OSTYPE": "linux-gnu",
            "MAILCHECK": "60",
            "OPTERR": "1",
            "OPTIND": "1",
            "PPID": str(random.randint(40000, 49000)),
            "PS1": "${debian_chroot:+($debian_chroot)}\\u@\\h:\\w\\$ ",
            "PS2": "> ",
            "PS4": "+ ",
            "SHELLOPTS": (
                "braceexpand:emacs:hashall:histexpand:history:"
                "interactive-comments:monitor"
            ),
        }
        for nombre, valor in de_shell.items():
            self.environ.setdefault(nombre, valor)
            self.exported.discard(nombre)

    def _aritmetica(self, tok: str) -> str:
        """Sustituye cada $(( ... )) por su valor.

        Va antes que las variables sueltas porque dentro de la expresion los
        nombres se leen SIN el dolar ---"$((X+1))"---, asi que tienen que
        seguir ahi cuando se evalua.
        """
        while True:
            partes = _trozos_aritmeticos(tok)
            if partes is None:
                return tok
            antes, expresion, despues = partes
            # Una sustitucion DENTRO de la aritmetica: "$(( $(echo 2) + 1 ))".
            # Se guarda el texto crudo en la pasada de las comillas, asi que
            # aqui todavia lleva el "$(...)" sin ejecutar.
            if "$(" in expresion or "`" in expresion:
                expresion = self.do_command_substitution(expresion)
            try:
                # POR LA SENTENCIA, no por la expresion: dentro de
                # $(( )) tambien se asigna, y "$((i++))" tiene que dejar la i
                # movida.
                valor = str(evalua_sentencia(expresion, self.environ))
            except ErrorAritmetico as fallo:
                mensaje = fallo.mensaje or error_de_sintaxis(expresion)
                self.protocol.terminal.write(
                    ("-bash: %s: %s\n" % (expresion, mensaje)).encode())
                valor = ""
            tok = antes + valor + despues

    def _tilde(self, tok: str) -> str:
        """El "~" del principio, que es el HOME de quien esta conectado.

        Solo al PRINCIPIO y solo si va solo o seguido de barra: en medio de
        una palabra es un caracter mas ---"a~b" es un nombre de fichero
        valido--- y expandirlo ahi seria inventarse rutas.
        """
        if not tok.startswith("~"):
            return tok
        if len(tok) > 1 and tok[1] != "/":
            return tok
        return self.environ.get("HOME", "/root") + tok[1:]

    def _comodines(self, tok: str) -> list:
        """Los nombres que casan con el patron, o el patron tal cual.

        Un patron que no casa con nada se deja SIN TOCAR, que es lo que hace
        bash: "ls *.tar" en un directorio sin tares dice
        "cannot access '*.tar'", no "cannot access ''".

        El resultado se devuelve como se escribio: si el patron era relativo,
        los nombres tambien, o un "ls pas*" en /etc contestaria con rutas
        absolutas que ningun ls escribe.
        """
        if not any(c in tok for c in "*?["):
            return [tok]
        # OJO: el sistema de ficheros cuelga del PROTOCOLO, no del shell. Con
        # "self.fs" esto lanzaba AttributeError, el except se lo tragaba y los
        # comodines se quedaban sin expandir sin que nada lo dijera.
        try:
            rutas = self.protocol.fs.resolve_path_wc(tok, self.protocol.cwd)
        except Exception:                                      # noqa: BLE001
            return [tok]
        if not rutas:
            return [tok]
        if not tok.startswith("/"):
            base = self.protocol.cwd.rstrip("/") + "/"
            rutas = [r[len(base):] if r.startswith(base) else r
                     for r in rutas]
        return sorted(rutas)

    def _expandir_ahora(self, tokens: list[str]) -> list[str]:
        """Sustituye lo que haya que sustituir en UN comando, justo antes de
        ejecutarlo: aritmetica, llaves, variables, el "~" y los comodines.

        Un token que sea EXACTAMENTE $VAR o ${VAR} y este vacio o sin definir
        desaparece entero, como una expansion sin comillas en un shell de
        verdad: "echo $NADA" imprime una linea vacia, no la palabra "$NADA".

        Los comodines van los ULTIMOS y sobre el token todavia marcado: lo
        que venia entrecomillado lleva sus asteriscos escondidos y no se
        convierte en una lista de ficheros.
        """
        salida: list[str] = []
        for tok in tokens:
            if ARIT_INI in tok:
                tok = self._aritmetica(tok)
            if ESPACIO_LLAVES in tok:
                tok = tok.replace(ESPACIO_LLAVES, " ")
            if "${" in tok:
                tok = expande_llaves(tok, self.environ)
            tok = tok.replace(ALMOHADILLA, "#")
            if "$" in tok:
                entero = _ENV_VAR_RE.fullmatch(tok)
                if entero is not None:
                    nombre = entero.group(1) or entero.group(2)
                    valor = self._special_var(nombre)
                    if valor is None:
                        valor = self.environ.get(nombre)
                    if not valor:
                        continue
                    tok = valor
                else:
                    tok = self.expand_variables(tok)
            if SUST_INI in tok:
                tok = self._sustituciones(tok)
            tok = self._tilde(tok)
            for nombre in self._comodines(tok):
                salida.append(restaurar_comillas(nombre))
        return salida

    def _sustituciones(self, tok: str) -> str:
        """Ejecuta las $(...) que se dejaron guardadas al trocear."""
        while True:
            i = tok.find(SUST_INI)
            if i < 0:
                return tok
            j = tok.find(SUST_FIN, i)
            if j < 0:
                return tok.replace(SUST_INI, "")
            try:
                dentro = bytes.fromhex(tok[i + 1:j]).decode()
            except ValueError:
                return tok[:i] + tok[j + 1:]
            tok = tok[:i] + self.run_subshell_command(dentro) + tok[j + 1:]

    def expand_variables(self, tok: str) -> str:
        """
        Replace ${VAR} or $VAR references embedded in a token with their value.

        Only variables that are currently set are expanded; an unknown
        reference is left verbatim so that field references in quoted awk, sed
        and perl programs (e.g. $1, $0, $NF) survive, since the lexer has
        already discarded the single/double quoting that would tell them apart.

        This is a deliberate compromise, not correct shell behaviour: a real
        shell expands "$1" (double-quoted) but not '$1' (single-quoted). We
        cannot honour that distinction until the lexer preserves quoting per
        token. Once a proper lexer/parser is in place, expand every reference
        according to its quoting and let unset variables expand to empty.
        """

        def replace(match: re.Match[str]) -> str:
            name = match.group(1) or match.group(2)
            sv = self._special_var(name)
            if sv is not None:
                return sv
            # Sin definir vale vacio, como en cualquier shell. Antes se
            # devolvia la referencia tal cual ---"a$NADAb" salia "a$NADAb"---
            # y era el precio de no saber si venia entrecomillada. Ya se sabe:
            # lo entrecomillado llega marcado y ni siquiera pasa por aqui.
            return self.environ.get(name, "")

        return _ENV_VAR_RE.sub(replace, tok)

    def _special_var(self, name: str) -> str | None:
        """Dynamic bash variables that are not stored in the environment.

        ``$RANDOM`` yields a fresh integer in 0..32767 on every reference, just
        like bash. Returning ``None`` means "not special": the caller then falls
        back to the normal environment lookup, so ordinary variables and
        awk/sed field refs ($1, $NF, ...) are unaffected.
        """
        if name == "0":
            # En un shell de LOGIN bash se llama a si mismo "-bash", con
            # guion; dentro de "sh" es "sh" a secas. Medido en los dos.
            return self.nombre_sh if getattr(self, "dash", False) else "-bash"
        if name == "RANDOM":
            return str(random.randint(0, 32767))
        # EL PID DEL SHELL. "echo $$" escribia "$$" tal cual, y ese numero se
        # usa en todas partes para nombrar ficheros temporales
        # ---"/tmp/.$$"---, asi que un guion que lo hiciera creaba un fichero
        # llamado literalmente ".$$". Sale del MISMO sitio que el PID del bash
        # de la sesion en "ps aux", que es lo unico que no lo delata.
        if name in ("$", "BASHPID"):
            from cowrie.commands.base import PID_SESION

            return str(PID_SESION)
        if name == "PPID":
            from cowrie.commands.base import PID_SESION

            # El padre del bash es su sshd de sesion; por telnet, el telnetd.
            # Los dos numeros salen de la misma tabla que pinta "ps".
            por_telnet = "Telnet" in type(self.protocol).__name__
            return str(PID_SESION - (17 if por_telnet else 11))
        # LOS PARAMETROS POSICIONALES. Los pone "set -- a b c" y los mueve
        # "shift"; viven en el protocolo porque los dos son comandos y el
        # shell que los lee es otro objeto.
        posicionales = getattr(self.protocol, "posicionales", None) or []
        if name == "#":
            return str(len(posicionales))
        if name in ("@", "*"):
            return " ".join(posicionales)
        if name.isdigit():
            indice = int(name)
            if 1 <= indice <= len(posicionales):
                return posicionales[indice - 1]
            # Devolver None ---y no ""--- deja que el $1 de un programa de awk
            # o de sed siga su camino normal por el entorno.
            return None
        if name == "?":
            # No se resuelve AQUI. El analizador procesa la linea entera de
            # golpe, asi que en "cmd; echo $?" el valor se calcularia antes de
            # que cmd se ejecute y saldria el de la linea anterior. Se deja un
            # marcador y lo sustituye runCommand() justo antes de ejecutar cada
            # comando, que es cuando last_status ya vale lo que debe.
            return MARCA_ESTADO
        return None

    def do_subshell_execution_from_lexer(self) -> None:
        """
        Execute a subshell command reading tokens from the lexer until matching closing parenthesis.
        Output goes directly to the terminal.
        """
        cmd_tokens = []
        opening_count = 1
        closing_count = 0

        while opening_count > closing_count:
            if self.lexer is None:
                break
            tok = self.lexer.get_token()
            if tok is None:
                break

            if tok == ")":
                closing_count += 1
                if opening_count == closing_count:
                    break
                else:
                    cmd_tokens.append(tok)
            elif tok == "(":
                opening_count += 1
                cmd_tokens.append(tok)
            else:
                cmd_tokens.append(tok)

        # LA REDIRECCION DEL SUBSHELL VA DESPUES DEL PARENTESIS.
        #
        # Aqui se volcaba la salida al terminal sin mirar lo que venia detras,
        # asi que en `(cmd) > w` el contenido acababa en la PANTALLA y `w` se
        # quedaba vacio. Es exactamente lo que usa el cargador de Mirai:
        #
        #     (wget URL -O- || busybox wget URL -O-) > w; chmod 777 w; ./w
        #
        # El resultado era que `./w` ejecutaba un fichero de cero bytes: nos
        # quedabamos con el cargador y sin ninguna de las diez arquitecturas. Y
        # de paso el atacante veia su binario volcado en pantalla, que en un
        # Linux de verdad no pasa jamas.
        #
        # Se mira el token siguiente antes de escribir nada. Si no es una
        # redireccion se devuelve al lexer y todo sigue igual que antes.
        destino = None
        anexar = False
        destino, anexar, tuberia = self._destino_de_subshell()

        cmd_str = " ".join(cmd_tokens)
        # Se captura, no se ejecuta: el turno lo decide runCommand. Ver
        # _capturar_subshell().
        self._subshell_pendiente = (f"({cmd_str})", destino, anexar, tuberia)
    def _destino_de_subshell(self) -> tuple[str | None, bool, list]:
        """A donde va la salida del parentesis: fichero, tuberia o pantalla.

        Mira el token siguiente. Si es `>` o `>>`, ese es el fichero; si es
        `|`, lo que viene detras es una tuberia y se lleva entera; si no, lo
        devuelve al lexer. Se hace AL TROCEAR y no al ejecutar, porque para
        entonces el lexer ya se ha consumido entero.

        LA TUBERIA NO SE MIRABA. Un "(echo a; echo b) | wc -l" ejecutaba el
        parentesis, escribia su salida EN PANTALLA y luego corria el "wc"
        sobre nada: se veian las dos lineas del echo en vez del 2. O sea que
        la tuberia no es que fallara, es que desaparecia.
        """
        destino = None
        anexar = False
        tuberia: list = []
        if self.lexer is None:
            return destino, anexar, tuberia
        try:
            siguiente = self.lexer.get_token()
        except Exception:                                  # noqa: BLE001
            siguiente = None
        if siguiente in (">", ">>"):
            anexar = siguiente == ">>"
            try:
                destino = self.lexer.get_token()
            except Exception:                              # noqa: BLE001
                destino = None
        elif siguiente == "|":
            # Hasta el siguiente separador de VERDAD: lo que venga detras de
            # un ";" ya no es de esta tuberia.
            while True:
                try:
                    tok = self.lexer.get_token()
                except Exception:                          # noqa: BLE001
                    tok = None
                if tok is None:
                    break
                if tok in (";", "&&", "||", "&"):
                    self.lexer.push_token(tok)
                    break
                tuberia.append(tok)
        elif siguiente is not None:
            self.lexer.push_token(siguiente)
        return destino, anexar, tuberia

    def _capturar_subshell(self, expr: str) -> None:
        """Guarda el parentesis para ejecutarlo CUANDO LE TOQUE.

        Antes se ejecutaba aqui mismo, dentro del tokenizador, y eso tenia dos
        consecuencias que se veian a simple vista:

          - No honraba el `&&` ni el `||` que lo precedieran. `true || (echo
            X)` imprimia X, porque al trocear la linea todavia no se ha
            ejecutado nada y no hay estado que consultar.
          - Salia FUERA DE ORDEN. `echo uno;(echo dos);echo tres` imprimia
            "dos" el primero, porque el parentesis corria mientras los otros
            dos solo se estaban apuntando.

        Ahora se apunta en la cola como un grupo mas y lo ejecuta runCommand,
        que es quien sabe con que estado viene la linea.
        """
        destino, anexar, tuberia = self._destino_de_subshell()
        self._subshell_pendiente = (expr, destino, anexar, tuberia)

    def _salida_de_subshell(self, salida: str, destino: str | None,
                            anexar: bool) -> None:
        """Vuelca la salida de un parentesis en su fichero o en la pantalla."""
        if destino:
            self._volcar_a_fichero(salida, destino, anexar)
        else:
            self.protocol.terminal.write(salida.encode())

    def _volcar_a_fichero(self, texto: str, destino: str, anexar: bool) -> None:
        """Escribe la salida de un subshell en un fichero del honeyfs.

        Hace lo mismo que `pipe.py` con una redireccion normal: crea el fichero
        virtual, lo respalda con uno real dentro de `download_path` y ajusta el
        tamano. Asi lo que se escriba se puede leer luego con `cat`, ejecutar
        con `./`, y ademas queda capturado en disco como cualquier otra muestra.
        """
        import stat as _stat
        import time as _time

        datos = texto.encode()
        ruta = self.protocol.fs.resolve_path(destino, self.protocol.cwd)
        try:
            existente = self.protocol.fs.getfile(ruta)
        except Exception:                                  # noqa: BLE001
            existente = None

        real = None
        if existente and existente[fs.A_TYPE] == fs.T_FILE and existente[fs.A_REALFILE]:
            real = existente[fs.A_REALFILE]
        else:
            nombre = "{}-{}-subsh_{}".format(
                _time.strftime("%Y%m%d-%H%M%S"),
                self.protocol.getProtoTransport().transportId,
                re.sub("[^A-Za-z0-9]", "_", destino),
            )
            real = os.path.join(
                CowrieConfig.get("honeypot", "download_path"), nombre)
            permisos = (_stat.S_IRUSR | _stat.S_IWUSR
                        | _stat.S_IRGRP | _stat.S_IROTH)
            try:
                self.protocol.fs.mkfile(
                    ruta, self.protocol.user.uid, self.protocol.user.gid,
                    0, _stat.S_IFREG | permisos)
            except fs.FileNotFound:
                self.protocol.terminal.write(
                    f"-bash: {destino}: No such file or directory\n".encode())
                return
            except fs.PermissionDenied:
                self.protocol.terminal.write(
                    f"-bash: {destino}: Permission denied\n".encode())
                return

        try:
            with open(real, "ab" if anexar else "wb") as fh:
                fh.write(datos)
            tam = os.path.getsize(real)
            self.protocol.fs.update_realfile(
                self.protocol.fs.getfile(ruta), real)
            self.protocol.fs.update_size(ruta, tam)
        except OSError as exc:
            log.msg(f"no se pudo volcar el subshell en {destino}: {exc}")

    def do_subshell_execution(self, start_tok: str) -> None:
        """
        Execute a subshell command (command) without output substitution.
        Output goes directly to the terminal.
        """
        if start_tok[0] == "(":
            cmd_expr = start_tok
            pos = 1
            opening_count = 1
            closing_count = 0

            # parse the remaining tokens to find the matching closing parenthesis
            while opening_count > closing_count:
                if cmd_expr[pos] == ")":
                    closing_count += 1
                    if opening_count == closing_count:
                        # Mismo caso que en do_subshell_execution_from_lexer, y
                        # esta es la rama que se usa de verdad: shlex devuelve
                        # el parentesis pegado al primer comando ("(echo"), asi
                        # que se entra por aqui y no por la otra. La salida
                        # tiene que ir al fichero si hay una redireccion
                        # detras, no a la pantalla.
                        self._capturar_subshell(cmd_expr[: pos + 1])
                        break
                    else:
                        pos += 1
                elif cmd_expr[pos] == "(":
                    opening_count += 1
                    pos += 1
                else:
                    if opening_count > closing_count and pos == len(cmd_expr) - 1:
                        if self.lexer:
                            tokkie = self.lexer.get_token()
                            if tokkie is None:  # self.lexer.eof put None for mypy
                                break
                            else:
                                cmd_expr = cmd_expr + " " + tokkie
                    pos += 1

    def do_command_substitution(self, start_tok: str,
                                aplazar: bool = False) -> str:
        """
        Perform command substitution, replacing $(cmd) or `cmd` with output.

        Con `aplazar`, en vez de ejecutar deja el texto guardado en una marca:
        lo ejecuta _expandir_ahora cuando le toca el turno al comando, que es
        cuando las asignaciones de la misma linea ya han corrido. La RECOGIDA
        del texto sigue siendo aqui a la fuerza, porque una sustitucion puede
        abarcar varios tokens y para juntarlos hace falta el lexer.
        """
        result = ""
        if start_tok[0] == "(":
            cmd_expr = start_tok
            pos = 1
        elif "$(" in start_tok:
            dollar_pos = start_tok.index("$(")
            result = start_tok[:dollar_pos]
            cmd_expr = start_tok[dollar_pos:]
            pos = 2
        elif "`" in start_tok:
            backtick_pos = start_tok.index("`")
            result = start_tok[:backtick_pos]
            cmd_expr = start_tok[backtick_pos:]
            pos = 1
        else:
            log.msg(f"failed command substitution: {start_tok}")
            return start_tok

        opening_count = 1
        closing_count = 0

        while opening_count > closing_count:
            if pos >= len(cmd_expr):
                # The current lexer token ended before the expression was
                # closed; pull the next token and keep scanning.
                if self.lexer:
                    tokkie = self.lexer.get_token()
                    if tokkie is None:
                        break
                    cmd_expr = cmd_expr + " " + tokkie
                    continue
                else:
                    break
            if cmd_expr[pos] in (")", "`"):
                closing_count += 1
                if opening_count == closing_count:
                    if cmd_expr[0] == "(":
                        self.protocol.terminal.write(
                            self.run_subshell_command(cmd_expr[: pos + 1]).encode()
                        )
                    elif aplazar:
                        dentro = cmd_expr[: pos + 1]
                        result += (SUST_INI + dentro.encode().hex() + SUST_FIN)
                    else:
                        result += self.run_subshell_command(cmd_expr[: pos + 1])

                    if pos < len(cmd_expr) - 1:
                        remainder = cmd_expr[pos + 1 :]
                        if "$(" in remainder or "`" in remainder:
                            result = self.do_command_substitution(
                                result + remainder, aplazar)
                        else:
                            result += remainder
                else:
                    pos += 1
            elif cmd_expr[pos : pos + 2] == "$(":
                opening_count += 1
                pos += 2
            elif cmd_expr[pos] == "(":
                # A bare ( opens a nested subshell inside $(...); count it so the
                # first ) does not falsely close the outer $(...).
                opening_count += 1
                pos += 1
            else:
                pos += 1

        return result

    def run_subshell_command(self, cmd_expr: str) -> str:
        # extract the command from $(...) or `...` or (...) expression
        if cmd_expr.startswith("$("):
            cmd = cmd_expr[2:-1]
        else:
            cmd = cmd_expr[1:-1]

        # For subshells with multiple commands, we need to capture all output
        # Create a custom output accumulator
        if cmd_expr.startswith("("):
            return self._execute_subshell_with_full_output(cmd)
        else:
            # Command substitution - use existing method
            return self._execute_command_substitution(cmd)

    def _execute_subshell_with_full_output(self, cmd: str,
                                           entorno: dict | None = None) -> str:
        """Execute subshell commands and capture ALL output, not just the last command.

        UN SOLO ENTORNO PARA TODO EL GRUPO. Cada orden de dentro corre en su
        propio HoneyPotShell, y cada uno se hacia su COPIA del entorno del de
        fuera: por eso "(A=1; echo $A)" imprimia una linea vacia y el cuerpo
        de una funcion no podia usar una variable que el mismo acababa de
        asignar. Ahora las ordenes del grupo comparten el diccionario, que es
        lo que hace un subshell de verdad; lo que NO hacen es devolverlo al de
        fuera, y de eso se encarga quien llama.
        """
        grupo = copy.copy(self.environ) if entorno is None else entorno
        self._entorno_grupo = grupo
        # Split commands by separators and execute each one
        lexer = shlex.shlex(instream=cmd, punctuation_chars=True, posix=True)
        lexer.wordchars += WORDCHARS_EXTRA

        accumulated_output = ""
        current_cmd_tokens: list[str] = []
        # El estado del ultimo comando de dentro se deja aqui en vez de
        # devolverlo: run_subshell_command tambien la usa la sustitucion
        # `$(...)`, que solo quiere el texto, y cambiarle el tipo de retorno
        # romperia a quien la llame desde el propio Cowrie.
        self._estado_subshell = 0
        # DENTRO DEL PARENTESIS, && Y || TAMBIEN CORTAN.
        #
        # Aqui habia un "Note: We're ignoring && and || conditional logic for
        # now" y las dos se trataban como un ';' cualquiera: se ejecutaba todo
        # pasara lo que pasara. Fuera del parentesis si se respetaban, asi que
        # el mismo shell se comportaba de dos maneras distintas.
        #
        # No es un detalle academico, es un DELATOR. El patron mas comun de
        # Mirai es exactamente este:
        #
        #     (wget URL -O- || busybox wget URL -O-) > w
        #
        # El respaldo con busybox solo debe correr si el primero FALLA. Al
        # ejecutar los dos, el atacante ve su comando de reserva funcionando
        # cuando no tocaba, y eso no pasa en ningun Linux.
        #
        # `op` es el separador que precede al comando que toca ejecutar, y
        # `estado` el codigo de salida del anterior. Un ';' no condiciona nada.
        op = ";"
        estado = 0

        # La pone Command_exit cuando lo llaman dentro de un parentesis.
        self.protocol._salir_subshell = False
        # Y el estado que lleva el parentesis hasta ahora, para que un "exit"
        # a secas se lo pueda llevar: cada orden de un "(a; b)" corre en su
        # PROPIO shell, asi que el de "exit" no ha visto lo que hizo "a".
        self.protocol._estado_en_curso = 0

        def ejecutar(cmd_str: str) -> str:
            nonlocal estado
            if getattr(self.protocol, "_salir_subshell", False):
                return ""       # ya hubo un "exit" ahi dentro
            if (op == "&&" and estado != 0) or (op == "||" and estado == 0):
                return ""       # cortocircuito: ni se ejecuta ni se anota
            salida, estado = self._execute_single_command_with_redirect(
                cmd_str, grupo)
            self.protocol._estado_en_curso = estado
            return salida

        while True:
            tok = lexer.get_token()
            if tok is None:
                if current_cmd_tokens:
                    accumulated_output += ejecutar(" ".join(current_cmd_tokens))
                break
            elif tok in (";", "&&", "||"):
                if current_cmd_tokens:
                    accumulated_output += ejecutar(" ".join(current_cmd_tokens))
                    current_cmd_tokens = []
                op = tok
            else:
                current_cmd_tokens.append(tok)

        self._estado_subshell = estado
        return accumulated_output

    def _execute_command_substitution(self, cmd: str) -> str:
        """Execute command substitution - should capture all output."""
        # Command substitution should also capture all output from multiple commands
        output = self._execute_subshell_with_full_output(cmd)
        # trailing newlines are stripped for command substitution
        return output.rstrip("\n")

    def _execute_single_command_with_redirect(
            self, cmd: str, entorno: dict | None = None) -> tuple[str, int]:
        """Ejecuta un comando y devuelve (salida, codigo de salida)."""
        # instantiate new shell with redirect output
        # LA RANURA SE VACIA ANTES. protocol.pp guarda la salida capturada del
        # ULTIMO comando que la uso, y una orden que no crea ninguna ---una
        # asignacion suelta--- la dejaba intacta: al leerla despues se
        # devolvia otra vez lo que habia escrito el comando ANTERIOR. Por eso
        # "(echo A; i=1; echo B)" imprimia "A A B", con la A repetida.
        pp_previo = getattr(self.protocol, "pp", None)
        self.protocol.pp = None
        res = HoneyPotShell(self.protocol, interactive=False, redirect=True)
        if entorno is not None:
            # El entorno del GRUPO, compartido con las otras ordenes del mismo
            # parentesis o del mismo cuerpo de funcion. Se pisa despues del
            # __init__ a proposito: lo que ese pone ---COLUMNS, TERM--- ya
            # esta en el diccionario del grupo, que salio de una copia.
            res.environ = entorno
        self.protocol.cmdstack.append(res)
        # call lineReceived method that indicates that we have some commands to parse
        res.lineReceived(cmd)
        # Se quita POR IDENTIDAD, y solo si sigue ahi: ahora el shell se saca
        # solo en _finish() al vaciar su cola, y un pop() a ciegas se llevaba
        # ADEMAS la shell de la sesion. La conexion se cerraba en seco al
        # primer `(echo A || echo B)`.
        if res in self.protocol.cmdstack:
            self.protocol.cmdstack.remove(res)

        # Se devuelve TAMBIEN el codigo de salida: sin el no se puede honrar
        # un && ni un || dentro del parentesis.
        estado = getattr(res, "last_status", 0)
        if getattr(self.protocol, "pp", None) is None:
            # No escribio nada: se devuelve la ranura como estaba, que puede
            # estar en uso por una tuberia de fuera.
            self.protocol.pp = pp_previo
            return "", estado
        try:
            output: str = res.protocol.pp.redirected_data.decode()
        except AttributeError:
            return "", estado
        else:
            return output, estado

    # ------------------------------------------------------------------
    # Lo que shell/script.py da por hecho, y no teniamos
    # ------------------------------------------------------------------
    #
    # `./w` no pasa por bash.py: pasa por scriptcmd() de shell/protocol.py,
    # que llama a run_script_file() de shell/script.py. Y ese, DESPUES de
    # ejecutar el guion, hace dos cosas con el shell que ha creado:
    #
    #     command.exit_code = shell.last_exit_code
    #     # "The script shell removes itself from cmdstack in _finish()"
    #
    # Nuestro honeypot.py viene de un Cowrie ANTERIOR al 3.0.10 y no tenia
    # _finish(). La consecuencia se vio en produccion y despista
    # muchisimo: el guion se ejecuta y su salida sale BIEN, pero el
    # `last_exit_code` lanza AttributeError, el comando no llega a su exit(),
    # el shell del guion se queda ENCIMA de cmdstack, y como no es interactivo
    # su showPrompt() no imprime nada. El atacante se queda sin prompt. Los
    # comandos siguientes SI se ejecutan ---van a ese shell huerfano--- pero
    # no se ve ni un prompt, asi que parece colgado y no lo esta.

    def _finish(self) -> None:
        """Se saca a si mismo de cmdstack al vaciar su cola.

        No pinta prompt: de eso se encarga el exit() del comando que creo este
        shell. Y se quita POR IDENTIDAD, nunca con pop(), porque encima puede
        haber un wget todavia en vuelo.
        """
        if self in self.protocol.cmdstack:
            self.protocol.cmdstack.remove(self)

    def _fin_de_linea(self) -> None:
        """Se acabo una linea: o va la siguiente del guion, o vuelve el prompt.

        Todo final de linea pasa por aqui. Si no, un guion se quedaria a
        medias y ---peor--- un shell no interactivo no terminaria nunca y la
        sesion del atacante se quedaria colgada sin prompt.
        """
        if self.lineas_de_guion:
            self.lineReceived(self.lineas_de_guion.pop(0))
            return
        if self.interactive:
            self.showPrompt()
            return
        # Un shell NO interactivo que se queda sin nada que hacer no pinta
        # prompt: tiene que CERRARSE. Se vuelve a entrar en runCommand con la
        # cola vacia, que es el unico sitio donde vive esa decision ---cerrar
        # la sesion si es el ultimo de la pila, o _finish() si no---. Sin esto
        # el shell del guion se quedaba encima de cmdstack para siempre.
        #
        # PERO SOLO SI ESTAMOS EN LA PILA. Un subshell de `(...)` o de `$(...)`
        # se crea SUELTO, sin apilarse. Para uno de esos, "len(cmdstack) == 1"
        # es cierto ---el uno es la shell de la sesion, no nosotros--- y
        # runCommand le daba por terminada la SESION ENTERA: la conexion se
        # cerraba en seco al primer `(echo A || echo B)`.
        if self not in self.protocol.cmdstack:
            return
        self.runCommand()

    def runCommand(self):
        pp = None

        def runOrPrompt() -> None:
            if self.cmdpending:
                self.runCommand()
            else:
                self._fin_de_linea()

        if not self.cmdpending:
            # Queda guion por ejecutar: se procesa la siguiente linea AHORA,
            # con el entorno ya actualizado por las anteriores.
            if self.lineas_de_guion:
                self.lineReceived(self.lineas_de_guion.pop(0))
                return
            # protocol.pp NO siempre existe: lo crea el primer comando que
            # se ejecuta. Un subshell cuyo contenido son solo asignaciones
            # ---"A=uno; (A=dos; echo $A)"--- llegaba aqui con pp a None y
            # tumbaba LA SESION ENTERA con un AttributeError, no solo el
            # comando. Sin tuberia es exactamente el mismo caso que
            # next_command a None.
            _pp = getattr(self.protocol, "pp", None)
            if _pp is None or _pp.next_command is None:  # sin tuberia
                if self.interactive:
                    self.showPrompt()
                else:
                    # when commands passed to a shell via PIPE, we spawn a HoneyPotShell in none interactive mode
                    # if there are another shells on stack (cmdstack), let's just exit our new shell
                    # else close connection
                    if len(self.protocol.cmdstack) == 1:
                        ret = failure.Failure(error.ProcessDone(status=""))
                        self.protocol.terminal.transport.processEnded(ret)
                    else:
                        self._finish()
                        return
            else:
                pass  # command with pipes
            return

        cmdAndArgs = self.cmdpending.pop(0)
        op = self.cmdops.pop(0) if self.cmdops else ";"
        fondo = self.cmdfondo.pop(0) if self.cmdfondo else False

        # LAS FRONTERAS DE UN BUCLE DESENROLLADO no ejecutan nada: solo
        # dicen por donde puede volver a coger el hilo un "break" o un
        # "continue".
        if cmdAndArgs and cmdAndArgs[0] in (MARCA_VUELTA, MARCA_FIN_BUCLE):
            runOrPrompt()
            return

        # PWD la mantiene el shell, no el login: si no se refresca, un "cd /tmp"
        # deja "printenv PWD" diciendo el directorio de entrada. Se pone aqui
        # porque es el unico sitio por el que pasan TODOS los comandos.
        actual = getattr(self.protocol, "cwd", None)
        if actual and self.environ.get("PWD") != actual:
            self.environ["PWD"] = actual
            self.exported.add("PWD")

        # Aqui last_status ya refleja el comando ANTERIOR de esta misma linea,
        # que es lo que "$?" tiene que valer.
        # LAS VARIABLES PRIMERO, Y LUEGO "$?". El orden importa y costo un
        # fallo: un "$?" pegado a otra cosa ---"rc=$?"--- no llega como el
        # token "$?", asi que lo convierte en marcador expand_variables(), o
        # sea ESTA llamada. Resolviendo el marcador antes, "rc=$?" imprimia
        # el marcador crudo en pantalla.
        #
        # Este es ademas el unico punto por el que pasan todos los comandos y
        # en el que las asignaciones anteriores de la misma linea YA se han
        # ejecutado, que es de lo que iba todo el cambio.
        #
        # El grupo de un parentesis se salta: su contenido lo expande el
        # shell de dentro, con su propia copia del entorno, y hacerlo dos
        # veces convertiria un "$" que sobreviviera en otra cosa.
        if not (cmdAndArgs and cmdAndArgs[0] == MARCA_SUBSHELL):
            try:
                cmdAndArgs = self._expandir_ahora(cmdAndArgs)
            except FaltaVariable as falta:
                # ${V?mensaje} con V sin definir: bash avisa y NO EJECUTA.
                self.protocol.terminal.write(
                    ("-bash: %s: %s\n" % (falta.nombre, falta.mensaje)).encode())
                self.last_status = 1
                runOrPrompt()
                return

        if any(MARCA_ESTADO in t for t in cmdAndArgs):
            cmdAndArgs = [
                t.replace(MARCA_ESTADO, str(self.last_status)) for t in cmdAndArgs
            ]

        # Short-circuit '&&' / '||' on the previous command's exit status, like
        # bash: 'a && b' skips b when a failed; 'a || b' skips b when a
        # succeeded. A skipped command leaves $? untouched.
        if (op == "&&" and self.last_status != 0) or (
            op == "||" and self.last_status == 0
        ):
            runOrPrompt()
            return

        # Un parentesis que esperaba turno. Se ejecuta AQUI, despues del corto
        # de arriba, que es lo que hace que `true || (echo X)` no imprima nada.
        if cmdAndArgs and cmdAndArgs[0] == MARCA_SUBSHELL:
            _, expresion, destino, anexar, *tuberia = cmdAndArgs
            # EL DIRECTORIO SE DEVUELVE. Un subshell corre en su propio
            # proceso, asi que su "cd" no sale del parentesis: medido en bash
            # y en dash, "cd /root; (cd /tmp; pwd); pwd" dice /tmp y luego
            # /root. El nuestro se quedaba en /tmp Y ADEMAS cambiaba el
            # prompt, que es la senal mas visible que puede dar una shell.
            # Los shells de dentro comparten self.protocol, asi que el unico
            # sitio donde se puede aislar es aqui.
            antes = getattr(self.protocol, "cwd", None)
            try:
                salida = self.run_subshell_command(expresion)
            finally:
                if antes is not None:
                    self.protocol.cwd = antes
            if tuberia:
                # A la tuberia se le da la salida del parentesis como
                # ENTRADA, con la misma pieza que alimenta a un heredoc: es
                # literalmente lo mismo ---un texto que hace de stdin de una
                # orden--- y asi la tuberia entera se monta donde se montan
                # todas, en runCommand.
                self.heredoc_datos = salida.encode()
                grupo = list(tuberia)
                grupo[0] = grupo[0] + MARCA_HEREDOC
                self.cmdpending.insert(0, grupo)
                self.cmdops.insert(0, ";")
                self.cmdfondo.insert(0, False)
                self.last_status = getattr(self, "_estado_subshell", 0)
                runOrPrompt()
                return
            self._salida_de_subshell(salida, destino or None, anexar == "1")
            # EL CODIGO DE SALIDA SALE DEL PARENTESIS aunque no salga el
            # directorio: "(exit 7); echo $?" dice 7 en bash y en dash, y el
            # nuestro decia 0. Es lo que mira un guion para saber si su
            # bloque funciono.
            self.last_status = getattr(self, "_estado_subshell", 0)
            runOrPrompt()
            return

        # Probably no reason to be this comprehensive for just PATH...
        environ = copy.copy(self.environ)
        cmd_tokens: list[str] = []
        cmd_array: list[dict[str, Any]] = []
        while cmdAndArgs:
            piece = cmdAndArgs.pop(0)
            if piece.count("="):
                key, val = piece.split("=", 1)
                environ[key] = val
                continue
            cmd_tokens = [piece, *cmdAndArgs]
            break

        # UNA FUNCION DEFINIDA POR EL ATACANTE. Se ejecuta su cuerpo con los
        # argumentos metidos en los $1, $@ y $#, con la misma maquinaria que
        # un parentesis: asi sale en orden y cada orden de dentro pasa por su
        # comando emulado y queda registrada.
        if cmd_tokens and cmd_tokens[0] in self.funciones:
            cuerpo = cuerpo_con_argumentos(self.funciones[cmd_tokens[0]],
                                           cmd_tokens[1:])
            # El cuerpo entero, no una sola orden: con
            # _execute_single_command_with_redirect, un
            # "f() { echo uno; echo dos; }" solo ejecutaba la ultima. Esta
            # otra es la que ya parte por ";" y acumula, la misma que usa un
            # parentesis.
            # DENTRO DE UNA FUNCION "local" Y "return" SI VALEN, y ninguno
            # de los dos puede saberlo por su cuenta: son comandos y lo que
            # les falta es el contexto. Se les deja apuntado en el protocolo.
            hondura = getattr(self.protocol, "_en_funcion", 0)
            locales_de_fuera = getattr(self.protocol, "_locales", None)
            self.protocol._en_funcion = hondura + 1
            self.protocol._locales = []
            grupo = copy.copy(self.environ)
            try:
                salida = self._execute_subshell_with_full_output(cuerpo, grupo)
            finally:
                locales = self.protocol._locales or []
                self.protocol._locales = locales_de_fuera
                self.protocol._en_funcion = hondura
            # Una funcion NO es un subshell: lo que asigna se queda. Menos lo
            # declarado "local", que muere con ella.
            for nombre, valor in grupo.items():
                if nombre not in locales:
                    self.environ[nombre] = valor
            if salida:
                self.protocol.terminal.write(salida.encode())
            self.last_status = getattr(self, "_estado_subshell", 0)
            runOrPrompt()
            return

        if not cmd_tokens:
            # A statement of only assignments (no command) persists those
            # variables for the rest of the session. They are shell variables,
            # not exported, so self.exported is left untouched.
            #
            # EN SITIO, no reasignando el atributo: el diccionario puede estar
            # COMPARTIDO con las otras ordenes del mismo grupo ---un
            # parentesis, el cuerpo de una funcion---, y un "self.environ =
            # otro" lo desconecta. Por eso "(A=1; echo $A)" no veia la A.
            self.environ.update(environ)
            self.last_status = 0
            runOrPrompt()
            return

        pipe_indices = [i for i, x in enumerate(cmd_tokens) if x == "|"]
        multipleCmdArgs: list[list[str]] = []
        pipe_indices.append(len(cmd_tokens))
        start = 0

        # Gather all arguments with pipes

        for _index, pipe_indice in enumerate(pipe_indices):
            multipleCmdArgs.append(cmd_tokens[start:pipe_indice])
            start = pipe_indice + 1

        first_args, first_ops = self.parser.parse_redirections(multipleCmdArgs.pop(0))
        if not first_args:
            if first_ops:
                # Handle redirection without command (e.g. > file)
                pp = PipeProtocol(
                    self.protocol,
                    None,
                    [],
                    None,
                    None,
                    self.redirect,
                    first_ops,
                )
                # This triggers _setup_redirections which creates files.
                # A failed redirection (e.g. target directory missing) is a
                # failure for '&&'/'||'; a working bare '> file' is success.
                self.last_status = (
                    1 if getattr(pp, "has_redirection_error", False) else 0
                )
            else:
                self.last_status = 0
            runOrPrompt()
            return

        cmd_array.append(
            {
                "command": first_args.pop(0),
                "rargs": first_args,
                "redirects": first_ops,
            }
        )

        for cmd_args in multipleCmdArgs:
            args, ops = self.parser.parse_redirections(cmd_args)
            if not args:
                continue
            cmd_array.append(
                {
                    "command": args.pop(0),
                    "rargs": args,
                    "redirects": ops,
                }
            )

        # "_" la pone bash con la ruta completa del programa que va a ejecutar,
        # y por eso un "printenv" de verdad se lista a si mismo como
        # "_=/usr/bin/printenv". Se resuelve contra el PATH igual que hace el
        # shell; si no aparece (un builtin, o algo que no existe) se deja la
        # palabra tal cual, que es lo que hace bash.
        self._marcar_ultimo(cmd_array[0]["command"], environ.get("PATH", ""))

        # ¿Cual de las ordenes de la tuberia se come el heredoc? La que lleve
        # la marca. Se quita de sus argumentos, que no es un argumento.
        idx_heredoc = -1
        for _i, _cmd in enumerate(cmd_array):
            if MARCA_HEREDOC in _cmd["command"]:
                _cmd["command"] = _cmd["command"].replace(MARCA_HEREDOC, "")
                idx_heredoc = _i
            if any(MARCA_HEREDOC in _a for _a in _cmd["rargs"]):
                _cmd["rargs"] = [_a.replace(MARCA_HEREDOC, "")
                                 for _a in _cmd["rargs"]]
                _cmd["rargs"] = [_a for _a in _cmd["rargs"] if _a]
                idx_heredoc = _i
        # Y AHORA SI: los operadores que iban escapados con barra vuelven a ser
        # su caracter. Ya no hay nada que repartir, asi que un ">" o un "|"
        # aqui es lo que el atacante escribio, un argumento.
        for _cmd in cmd_array:
            _cmd["command"] = restaura_literales(_cmd["command"])
            _cmd["rargs"] = [restaura_literales(_a) for _a in _cmd["rargs"]]

        lastpp = None
        cmdclass = None
        for index, cmd in reversed(list(enumerate(cmd_array))):
            cmdclass = self.protocol.getCommand(
                cmd["command"], environ.get("PATH", "").split(":")
            )
            if cmdclass:
                log.msg(
                    input=cmd["command"] + " " + " ".join(cmd["rargs"]),
                    format="Command found: %(input)s",
                )
                if index == len(cmd_array) - 1:
                    lastpp = PipeProtocol(
                        self.protocol,
                        cmdclass,
                        cmd["rargs"],
                        self.heredoc_datos if index == idx_heredoc else None,
                        None,
                        self.redirect,
                        cmd.get("redirects", []),
                    )
                    pp = lastpp
                else:
                    pp = PipeProtocol(
                        self.protocol,
                        cmdclass,
                        cmd["rargs"],
                        self.heredoc_datos if index == idx_heredoc else None,
                        lastpp,
                        self.redirect,
                        cmd.get("redirects", []),
                    )
                    lastpp = pp
            else:
                self._emit(
                    "cowrie.command.failed",
                    "Command not found: %(input)s",
                    input=cmd["command"] + " " + " ".join(cmd["rargs"]),
                )
                message = self.command_not_found_message(cmd["command"]).encode("utf8")
                redirects = cmd.get("redirects", [])
                if redirects:
                    temp_pp = PipeProtocol(
                        self.protocol,
                        None,
                        [],
                        None,
                        None,
                        self.redirect,
                        redirects,
                    )
                    temp_pp.errReceived(message)
                    for real_path, virtual_path in temp_pp.redirect_real_files:
                        self.protocol.terminal.redirFiles.add((real_path, virtual_path))
                else:
                    self.protocol.terminal.write(message)

                # Import here to avoid circular dependency with protocol module
                from cowrie.shell import protocol

                if (
                    isinstance(self.protocol, protocol.HoneyPotExecProtocol)
                    and not self.cmdpending
                ):
                    exit_status = failure.Failure(error.ProcessDone(status=""))
                    self.protocol.terminal.transport.processEnded(exit_status)

                self.last_status = 127
                runOrPrompt()
                pp = None  # Got a error. Don't run any piped commands
                break
        if pp and getattr(pp, "has_redirection_error", False):
            self.last_status = 1
            runOrPrompt()
            return

        if pp and fondo:
            # El aviso del trabajo, que es lo unico que se ve al mandar algo
            # al fondo. Lo que NO se emula es el "[1]+ Done ..." de despues:
            # bash lo escribe justo antes del prompt siguiente y aqui el
            # comando corre hasta el final antes de volver, asi que no habria
            # donde ponerlo sin mentir sobre el orden.
            self.protocol._trabajo = getattr(self.protocol, "_trabajo", 0) + 1
            self.protocol._pid_fondo = getattr(
                self.protocol, "_pid_fondo", random.randint(2000, 9000)) + 1
            self.protocol.terminal.write(
                ("[%d] %d\n" % (self.protocol._trabajo,
                                 self.protocol._pid_fondo)).encode())

        if pp and getattr(self.protocol, "_xtrace", False):
            # El rastro de "set -x": la orden con un "+ " delante, ANTES de
            # ejecutarla y ya expandida, que es como la escribe bash.
            self.protocol.terminal.write(
                ("+ " + " ".join([cmd_array[0]["command"]]
                                 + list(cmd_array[0]["rargs"]))
                 + "\n").encode())

        if pp:
            # Optimistic exit status: emulated commands generally "succeed"; we
            # only distinguish the trivially-false builtin so 'false && x' and
            # 'false || x' behave. (Full per-command exit codes are future work.)
            self.last_status = 1 if cmd_array[0]["command"] == "false" else 0
            # COMO SE HA ESCRITO LA ORDEN, para quien lo necesite. dash se
            # nombra por su $0 en los errores: invocado como "sh" dice
            # "sh: 2: asd: not found", pero como "/bin/sh" dice "/bin/sh: 2:".
            # Medido en un Debian 13.6 de verdad. Cowrie no le pasa el nombre
            # al comando, asi que se deja aqui, que es donde se conoce.
            self.protocol._nombre_invocado = cmd_array[0]["command"]
            # "--help": SE RESUELVE AQUI, en un solo sitio.
            #
            # De los 111 nombres de comando que registran los modulos, la
            # mayoria IGNORABA "--help" y hacia su trabajo: "ls --help"
            # listaba el directorio y "nproc --help" contestaba 12. Poner una
            # linea en cada modulo era garantizar que alguno se quedase sin
            # ella; aqui no hay nada que recordar.
            #
            # Y va ANTES de instanciar, no dentro del comando, para que la
            # ayuda pase por la tuberia como cualquier otra salida: "ls --help
            # | head -3" tiene que funcionar. Ver commands/ayuda.py.
            try:
                from cowrie.commands import ayuda as _ayuda

                cmdclass = _ayuda.interceptar(
                    cmd_array[0]["command"], cmd_array[0]["rargs"], cmdclass)
            except Exception:                              # noqa: BLE001
                pass
            # Se gasta SOLO cuando lo usa quien lleva la marca. Borrarlo en
            # cualquier orden hacia que "echo antes; cat <<EOF" se lo comiera
            # el echo, y el cat se quedaba esperando una entrada que ya no
            # llegaba: la sesion entera se colgaba ahi.
            if idx_heredoc >= 0:
                self.heredoc_datos = None
            self.protocol.call_command(pp, cmdclass, *cmd_array[0]["rargs"])

    def command_not_found_message(self, cmd: str) -> str:
        """
        Build the error a real shell prints when a command cannot be run.
        For a path-like command (one starting with "." or "/") match bash's
        errno-based messages: an existing directory yields "Is a directory"
        (EISDIR) and a path that does not exist yields "No such file or
        directory" (ENOENT). Anything else yields "command not found".
        """
        # dash no dice ni "-bash" ni "command not found": se nombra por su
        # $0, numera la linea y solo tiene dos respuestas. Medido contra dash
        # 0.5.12 en un pseudo-terminal:
        #
        #     $ ./noexiste   -> sh: 1: ./noexiste: not found
        #     $ /tmp         -> sh: 2: /tmp: Permission denied
        #     $ /etc/passwd  -> sh: 3: /etc/passwd: Permission denied
        #     $ noexiste     -> sh: 4: noexiste: not found
        #
        # Un directorio y un fichero sin permiso de ejecucion dan lo MISMO,
        # al reves que en bash, que distingue "Is a directory".
        if self.dash:
            if cmd[:1] in (".", "/"):
                path = self.protocol.fs.resolve_path(cmd, self.protocol.cwd)
                if self.protocol.fs.exists(path):
                    return (f"{self.nombre_sh}: {self.linea_dash}: {cmd}: "
                            "Permission denied\n")
            return f"{self.nombre_sh}: {self.linea_dash}: {cmd}: not found\n"

        if cmd[:1] in (".", "/"):
            path = self.protocol.fs.resolve_path(cmd, self.protocol.cwd)
            if self.protocol.fs.isdir(path):
                return f"-bash: {cmd}: Is a directory\n"
            if not self.protocol.fs.exists(path):
                return f"-bash: {cmd}: No such file or directory\n"
        return f"-bash: {cmd}: command not found\n"

    def resume(self) -> None:
        # EL PUENTE QUE FALTABA. Habia dos nombres para el mismo dato y nadie
        # los unia: los comandos dejan su codigo de salida en
        # `last_exit_code` ---lo escribe command.exit() justo antes de llamar
        # aqui--- y el corto de `&&` / `||` y el `$?` leen `last_status`.
        #
        # Sin esta linea, `last_status` se quedaba en 0 para todo lo que no
        # fuera un builtin, con dos consecuencias silenciosas: el `&&` se
        # cumplia SIEMPRE y el `||` no se cumplia NUNCA. O sea que
        #
        #     chmod 777 i ||(cp /bin/ls ii; ... )
        #     wget X || curl -O X || busybox wget X
        #
        # ---los dos patrones mas repetidos en los guiones que caen aqui---
        # tomaban siempre la rama equivocada, y `grep -q X && hacer` se
        # cumplia aunque grep no hubiera encontrado nada.
        self.last_status = self.last_exit_code
        if self.interactive:
            self.protocol.setInsertMode()

        # UNA TUBERIA SE CIERRA ANTES DE QUE ARRANQUE LO SIGUIENTE.
        #
        # Sin esto, una tuberia PERDIA SU SALIDA en cuanto no era lo ultimo de
        # la linea:
        #
        #     echo a | cat            ->  a
        #     echo a | cat; echo b    ->  solo b
        #     cat fichero | grep x; ...  ->  se perdia lo que encontrara grep
        #
        # El motivo es de reentrada. protocol.pp es UNA sola ranura. El primer
        # comando de la tuberia termina DENTRO de call_command, su exit()
        # llama aqui, y aqui se lanzaba ya el comando siguiente de la linea,
        # que pone su propio pp en esa ranura. Cuando call_command volvia a
        # cerrar "la tuberia", cerraba la nueva ---que no tenia nada
        # detras--- y la de verdad se quedaba sin vaciar: el "cat" nunca
        # llegaba a ejecutarse.
        #
        # Cerrandola aqui, el resto de la tuberia corre en su sitio y en su
        # orden. Se devuelve la ranura a None para que call_command no la
        # cierre dos veces, que no es inocuo: cerrar es ejecutar el siguiente.
        # Y se sale, porque la linea sigue por dentro de esa llamada: al
        # terminar el ultimo eslabon se vuelve a pasar por aqui.
        pp = getattr(self.protocol, "pp", None)
        if pp is not None and getattr(pp, "next_command", None) is not None:
            self.protocol.pp = None
            pp.outConnectionLost()
            return

        self.runCommand()

    def showPrompt(self) -> None:
        if not self.interactive:
            return

        # SI LA SHELL PINTA SU PROMPT, NADIE ESTA LEYENDO UNA CONTRASENA.
        #
        # password_input lo encienden sudo, su y passwd, y solo lo apagaban en
        # su finish(), o sea al pulsar Enter. Cancelando con Ctrl-C el comando
        # moria con la bandera puesta: la sesion seguia sin eco, lo que se
        # tecleaba no se veia y las flechas manejaban el buffer contra un
        # terminal que no mostraba nada ---parecia que la shell se borraba---.
        #
        # Va aqui y no en cada comando a proposito: son tres hoy y el que se
        # anada manana se olvidaria igual. Aqui no hay nada que recordar.
        self.protocol.password_input = False

        # dash no sabe nada de usuarios ni de directorios: su PS1 por defecto
        # es "$ " a secas, y "# " para root. Medido: `echo $PS1` dentro de un
        # `sh` devuelve exactamente eso.
        if self.dash:
            prompt = "# " if not self.protocol.user.uid else "$ "
            self.protocol.terminal.write(prompt.encode("ascii"))
            self.protocol.ps = (prompt.encode("ascii"), b"> ")
            return

        prompt = ""
        if CowrieConfig.has_option("honeypot", "prompt"):
            prompt = CowrieConfig.get("honeypot", "prompt")
            prompt += " "
        else:
            cwd = self.protocol.cwd
            homelen = len(self.protocol.user.avatar.home)
            if cwd == self.protocol.user.avatar.home:
                cwd = "~"
            elif (
                len(cwd) > (homelen + 1)
                and cwd[: (homelen + 1)] == self.protocol.user.avatar.home + "/"
            ):
                cwd = "~" + cwd[homelen:]

            # Example: [root@svr03 ~]#   (More of a "CentOS" feel)
            # Example: root@svr03:~#     (More of a "Debian" feel)
            prompt = f"{self.protocol.user.username}@{self.protocol.hostname}:{cwd}"
            if not self.protocol.user.uid:
                prompt += "# "  # "Root" user
            else:
                prompt += "$ "  # "Non-Root" user

        self.protocol.terminal.write(prompt.encode("ascii"))
        self.protocol.ps = (prompt.encode("ascii"), b"> ")

    def showContinuationPrompt(self) -> None:
        """PS2: shown while buffering an unfinished compound command."""
        if not self.interactive:
            return
        self.protocol.terminal.write(b"> ")
        self.protocol.ps = (b"> ", b"> ")

    def eofReceived(self) -> None:
        """
        EOF with the shell as the active reader (no command running) logs out.
        """
        log.msg("received eof, logging out")
        status = failure.Failure(error.ProcessDone(status=""))
        self.protocol.terminal.transport.processEnded(status)

    def handle_CTRL_C(self) -> None:
        # Ctrl-C also aborts a multi-line continuation and drops back to PS1,
        # exactly like real bash (the '> ' buffer is discarded).
        self.cont_buffer = []
        self.protocol.lineBuffer = []
        self.protocol.lineBufferIndex = 0
        self.protocol.terminal.write(b"\n")
        self.showPrompt()

    def handle_TAB(self) -> None:
        """
        lineBuffer is an array of bytes
        """
        if not self.protocol.lineBuffer:
            return

        line: bytes = b"".join(self.protocol.lineBuffer)
        # Lo de delante del token se guarda literal y se vuelve a pegar al
        # final. En parte_ultimo_token estan los tres fallos que arregla.
        cabecera, clue, comilla = parte_ultimo_token(line.decode("utf8"))

        # clue now contains the string to complete or is empty.
        basedir = os.path.dirname(clue)
        if basedir and basedir[-1] != "/":
            basedir += "/"

        if not basedir:
            tmppath = self.protocol.cwd
        else:
            tmppath = basedir

        try:
            r = self.protocol.fs.resolve_path(tmppath, self.protocol.cwd)
        except Exception:
            return

        if not self.protocol.fs.exists(r):
            return

        files = []
        for x in self.protocol.fs.get_path(r):
            if clue == "":
                files.append(x)
                continue
            if not x[fs.A_NAME].startswith(os.path.basename(clue)):
                continue
            files.append(x)

        if not files:
            return

        # Clear early so we can call showPrompt if needed
        for _i in range(self.protocol.lineBufferIndex):
            self.protocol.terminal.cursorBackward()
            self.protocol.terminal.deleteCharacter()

        newbuf = ""
        if len(files) == 1:
            es_dir = files[0][fs.A_TYPE] == fs.T_DIR
            # UN DIRECTORIO NO CIERRA LA COMILLA. La barra va DENTRO y la
            # comilla se queda abierta, porque la ruta va a seguir:
            #
            #     cd "/home/adm<TAB>   ->  cd "/home/admin/
            #
            # Cerrarla ---cd "/home/admin"/--- tambien funciona en bash,
            # pero no es lo que escribe bash, y el siguiente tabulador se
            # encuentra un token ya cerrado y reescribe la linea entera con
            # barras. Solo se cierra, y se anade el espacio, cuando el
            # candidato es un fichero: ahi ya no se sigue escribiendo.
            nombre = f"{basedir}{files[0][fs.A_NAME]}" + ("/" if es_dir else "")
            newbuf = cabecera + escapa_completado(nombre, comilla, not es_dir)
            if not es_dir:
                newbuf += " "
            newbyt = newbuf.encode("utf8")
        else:
            if os.path.basename(clue):
                prefix = os.path.commonprefix([x[fs.A_NAME] for x in files])
            else:
                prefix = ""
            newbuf = cabecera + escapa_completado(
                f"{basedir}{prefix}", comilla, False
            )
            newbyt = newbuf.encode("utf8")
            if newbyt == b"".join(self.protocol.lineBuffer):
                self.protocol.terminal.write(b"\n")
                # El listado de candidatos va SIN escapar: bash escribe ahi
                # los nombres tal cual y solo escapa lo que mete en la linea.
                maxlen = max(len(x[fs.A_NAME]) for x in files) + 1
                perline = int(self.protocol.user.windowSize[1] / (maxlen + 1))
                count = 0
                for file in files:
                    if count == perline:
                        count = 0
                        self.protocol.terminal.write(b"\n")
                    self.protocol.terminal.write(
                        file[fs.A_NAME].ljust(maxlen).encode("utf8")
                    )
                    count += 1
                self.protocol.terminal.write(b"\n")
                self.showPrompt()

        self.protocol.lineBuffer = list(iterbytes(newbyt))
        self.protocol.lineBufferIndex = len(self.protocol.lineBuffer)
        self.protocol.terminal.write(newbyt)
