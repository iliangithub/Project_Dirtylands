#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
test_paises.py --- la bandera y el pais que se pegan detras de cada IP.

    python3 "TELEGRAM SCRIPTS/tests/test_paises.py"

Esto va en el camino de CADA alerta, asi que lo que mas importa no es que
acierte el pais: es que no pueda tumbar un aviso. Una alerta sin bandera se
lee igual de bien; una alerta que no llega porque el adorno fallo, no.

Lo que se comprueba:

  - que una tabla que falta, que esta a medias o que no se entiende devuelva
    vacio en vez de reventar o, peor, en vez de devolver basura que parezca un
    pais;
  - que una IP privada no tenga pais, porque no lo tiene y ademas suele ser
    nuestra;
  - que la busqueda binaria acierte en los bordes de cada tramo y dentro de
    los huecos sin asignar, que es donde un fallo de un indice no se nota;
  - que los anchos de registro de paises.py y del generador sigan siendo los
    mismos: si se separan, el seek() cae en mitad de una linea y devuelve dos
    letras cualesquiera con toda la pinta de ser un pais;
  - que la tabla que viaja en el repositorio este bien formada y ordenada;
  - y que no haya ningun pais en la tabla sin nombre en nombres.txt, que se
    veria como un codigo suelto en el movil.
"""

from __future__ import annotations

import ast
import importlib.util
import ipaddress
import os
import shutil
import sys
import tempfile
from pathlib import Path

AQUI = Path(__file__).resolve().parent
GEOIP = AQUI.parent / "geoip"

# ESTA SUITE IMPRIME BANDERAS, y una bandera son dos caracteres que no existen
# en cp1252: en el portatil de trabajo ---Windows, que es donde se pasan las
# treinta y tres del 3.7.10--- Python escribia en la pagina de codigos del
# sistema y el propio print reventaba con UnicodeEncodeError a mitad de la
# suite. Se veia de la peor forma posible: la lista del 3.7.10 corta la salida
# con `tail -1`, asi que en vez de un fallo salia una linea suelta sin ningun
# "ok/fallos", y parecia un formato raro y no una suite muerta.
#
# El mismo remedio que ya usan cortar_el_grifo.py y estoy_dentro.py para sus
# circulos de color, y por el mismo motivo. En la VPS no hacia falta porque
# alli el locale ya es UTF-8, que es justo lo que lo dejaba escondido.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:                                          # noqa: BLE001
    pass

OK = 0
MAL = 0


def comprueba(que, esperado, obtenido):
    global OK, MAL
    if esperado == obtenido:
        OK += 1
        print("  ok    %s" % que)
    else:
        MAL += 1
        print("  FALLO %s\n          esperaba %r\n          obtuvo   %r"
              % (que, esperado, obtenido))


def cargar(nombre, ruta):
    spec = importlib.util.spec_from_file_location(nombre, ruta)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gen = cargar("generador", GEOIP / "generar-tabla-paises.py")

tmp = Path(tempfile.mkdtemp())


def con_tabla(dir_tabla):
    """paises.py apuntando a donde se le diga."""
    os.environ["DIRTYLAND_GEOIP"] = str(dir_tabla)
    return cargar("paises_%d" % abs(hash(str(dir_tabla))), GEOIP / "paises.py")


# --------------------------------------------------------------------------
print("\nLa bandera sale del codigo, no de una lista")
p = con_tabla(GEOIP)
comprueba("TR", "\U0001F1F9\U0001F1F7", p.bandera("TR"))
comprueba("BW", "\U0001F1E7\U0001F1FC", p.bandera("BW"))
comprueba("en minuscula tambien", p.bandera("TR"), p.bandera("tr"))
for malo in ("", "T", "TRK", "12", "??", None):
    comprueba("%r no da bandera" % (malo,), "", p.bandera(malo))


print("\nLos dos ficheros tienen que estar de acuerdo en el ancho")
comprueba("ancho de v4", gen.ANCHO_V4, p.ANCHO_V4)
comprueba("ancho de v6", gen.ANCHO_V6, p.ANCHO_V6)


print("\nResolver solapes no puede PERDER ni una direccion")
# ESTA COMPROBACION EXISTE PORQUE LA TABLA SE SUBIO CON UN AGUJERO. Los RIR se
# pisan de vez en cuando ---un punado entre 261.000--- y la primera version
# llevaba un `fin_anterior` como MAXIMO CORRIDO: en cuanto aparecia un bloque
# grande, descartaba todo lo que viniera detras con un final menor aunque no
# se pisara con nada. En la tabla salia un HUECO donde habia trece paises, y
# una IP de esa zona se quedaba sin bandera sin que nada lo dijera.
for _nombre, _entrada, _espera_paises in (
        ("sin solapes", [[10, 19, "AA"], [20, 29, "BB"]], {"AA", "BB"}),
        ("uno anidado: el pequeno manda en SU trozo, el grande en el resto",
         [[10, 99, "AA"], [40, 49, "BB"]], {"AA", "BB"}),
        ("mismo inicio: gana el mas concreto",
         [[10, 99, "AA"], [10, 19, "BB"]], {"AA", "BB"}),
        ("solape parcial", [[10, 50, "AA"], [40, 80, "BB"]], {"AA", "BB"}),
        ("un bloque grande y sueltos DETRAS, que es el fallo que se colo",
         [[10, 1000, "AA"], [2000, 2009, "BB"], [2010, 2019, "CC"]],
         {"AA", "BB", "CC"}),
):
    _e = sorted(_entrada)
    _r = gen._sin_solapes([x[:] for x in _e])
    comprueba("%s: no se pierde ni una direccion" % _nombre,
              gen._cubierto(_e), gen._cubierto(_r))
    comprueba("%s: no desaparece ningun pais" % _nombre,
              _espera_paises, {c for _i, _f, c in _r})
    comprueba("%s: y el resultado no se pisa consigo mismo" % _nombre,
              True, all(a[1] < b[0] for a, b in zip(_r, _r[1:])))

print("\nUna tabla inventada, para mirar los bordes y los huecos")
# LAS TABLAS SE ESCRIBEN CON SALTOS DE UNIX A MANO ---newline="\n"--- y no es
# cosmetico: son REGISTROS DE ANCHO FIJO (14 y 20 bytes) y de eso vive el
# seek() de paises.py. En Windows, write_text traduce cada "\n" a "\r\n", el
# registro pasa a medir 15, y el seek cae en mitad de una linea: las ocho
# comprobaciones de los bordes devolvian cadena vacia. La tabla de verdad no
# tiene el problema porque la genera la VPS.
# Dos tramos con un hueco en medio, que es justo donde un indice mal puesto
# devuelve el pais del tramo anterior sin que se note.
falsa = tmp / "falsa"
falsa.mkdir()
rangos = [[100, 199, "TR"], [300, 399, "BW"]]
for _cual in ("ubicacion", "registro"):
    (falsa / f"{_cual}-v4.txt").write_text(
        gen.tabla(rangos, gen.ANCHO_V4, False), encoding="utf-8", newline="\n")
    (falsa / f"{_cual}-v6.txt").write_text(
        gen.tabla([[1, 9, "PK"]], gen.ANCHO_V6, True), encoding="utf-8", newline="\n")
(falsa / "nombres.txt").write_text(
    "TR Turquia\nBW Botsuana\nPK Pakistan\nSI Eslovenia\nUS Estados Unidos\n",
    encoding="utf-8", newline="\n")
f = con_tabla(falsa)


def cc(n):
    return f._buscar(str(falsa / "ubicacion-v4.txt"), f.ANCHO_V4, n, False)


comprueba("justo antes del primer tramo", "??", cc(99))
comprueba("el primer numero del tramo", "TR", cc(100))
comprueba("por el medio", "TR", cc(150))
comprueba("el ultimo numero del tramo", "TR", cc(199))
comprueba("el primero del hueco", "??", cc(200))
comprueba("el ultimo del hueco", "??", cc(299))
comprueba("el tramo siguiente", "BW", cc(300))
comprueba("pasado el final de todo", "??", cc(400))


print("\nLo que no tiene pais no se inventa")
comprueba("una IP privada", "", f.etiqueta("192.168.1.1"))
comprueba("el bucle local", "", f.etiqueta("127.0.0.1"))
comprueba("la red del senuelo", "", f.etiqueta("172.20.0.10"))
comprueba("algo que no es una IP", "", f.etiqueta("no-soy-una-ip"))
comprueba("una cadena vacia", "", f.etiqueta(""))
comprueba("None", "", f.etiqueta(None))


print("\nSi la tabla no esta, o esta rota, se calla")
vacio = tmp / "vacio"
vacio.mkdir()
v = con_tabla(vacio)
comprueba("sin tabla ninguna no revienta ni inventa", "", v.etiqueta("8.8.8.8"))

rota = tmp / "rota"
rota.mkdir()
shutil.copy(falsa / "nombres.txt", rota / "nombres.txt")
entera = (falsa / "ubicacion-v4.txt").read_text(encoding="utf-8")
# Un byte de mas: el tamano deja de ser multiplo del registro. Sin la
# comprobacion, el seek cae en mitad de una linea y devuelve dos digitos.
(rota / "ubicacion-v4.txt").write_text(entera + "x", encoding="utf-8", newline="\n")
(rota / "registro-v4.txt").write_text(entera + "x", encoding="utf-8", newline="\n")
r = con_tabla(rota)
comprueba("una tabla cortada no devuelve dos caracteres cualesquiera",
          "", r.etiqueta("0.0.0.150"))


print("\nLas dos fuentes: se ensenan las dos SOLO cuando discrepan")
# Es el arreglo que costo mas caro de entender. La primera version solo traia
# el REGISTRO de los RIR, y una IP anunciada desde Eslovenia salia como
# Estados Unidos porque el bloque se registro alli en 2025 y se alquilo
# despues. Las dos fuentes coinciden en el 92%; donde no, la discrepancia ES
# la senal de que el rango esta alquilado.
dos = tmp / "dos"
dos.mkdir()
shutil.copy(falsa / "nombres.txt", dos / "nombres.txt")
# Misma IP, dos respuestas: la ubicacion dice SI, el registro dice US.
# Direcciones GLOBALES de verdad: una IP reservada (0.0.0.x) no tiene pais y
# la libreria la descarta antes de mirar ninguna tabla, con razon.
(dos / "ubicacion-v4.txt").write_text(
    gen.tabla([[134744064, 134744319, "SI"], [151587072, 151587327, "TR"]], gen.ANCHO_V4, False),
    encoding="utf-8", newline="\n")
(dos / "registro-v4.txt").write_text(
    gen.tabla([[134744064, 134744319, "US"], [151587072, 151587327, "TR"]], gen.ANCHO_V4, False),
    encoding="utf-8", newline="\n")
(dos / "ubicacion-v6.txt").write_text("", encoding="utf-8", newline="\n")
(dos / "registro-v6.txt").write_text("", encoding="utf-8", newline="\n")
d = con_tabla(dos)
comprueba("cuando discrepan, se dicen las dos y se dice cual es cual",
          "\U0001F1F8\U0001F1EE Eslovenia (bloque de \U0001F1FA\U0001F1F8 Estados Unidos)",
          d.etiqueta("8.8.8.8"))
comprueba("cuando coinciden, una sola vez",
          "\U0001F1F9\U0001F1F7 Turquia", d.etiqueta("9.9.9.9"))
comprueba("la ubicacion es la que manda, y va delante",
          "SI", d.codigo("8.8.8.8"))
comprueba("y el registro se puede pedir aparte",
          "US", d.registro("8.8.8.8"))

# Si falta una de las dos, se dice lo que se sabe en vez de callarse.
solo = tmp / "solo"
solo.mkdir()
shutil.copy(falsa / "nombres.txt", solo / "nombres.txt")
(solo / "registro-v4.txt").write_text(
    gen.tabla([[134744064, 134744319, "US"]], gen.ANCHO_V4, False), encoding="utf-8", newline="\n")
u = con_tabla(solo)
comprueba("sin tabla de ubicacion, se dice el registro a secas",
          "\U0001F1FA\U0001F1F8 Estados Unidos", u.etiqueta("8.8.8.8"))
comprueba("y sin ninguna de las dos, nada", "", u.etiqueta("9.9.9.9"))

print("\nNingun pais se queda sin nombre")
_nombres = {}
for _l in (GEOIP / "nombres.txt").read_text(encoding="utf-8").splitlines():
    if _l and not _l.startswith("#"):
        _cc, _n = _l.split(" ", 1)
        _nombres[_cc] = _n
comprueba("estan todos los de la ISO mas los que usan los RIR fuera de ella",
          set(), set(gen.FUERA_DE_LA_ISO) - set(_nombres))
comprueba("y ninguno se quedo con el nombre oficial, que se lee mal",
          [], [n for n in _nombres.values() if "," in n])
comprueba("todos tienen bandera, que se calcula del codigo", 0,
          sum(1 for c in _nombres if not f.bandera(c)))

# --------------------------------------------------------------------------
print("\nDecir por donde va, que el silencio corta la sesion")
#
# Esto baja ~45 MB de seis servidores y antes no escribia una linea hasta
# terminar. Dos problemas, y el segundo es el gordo:
#
#   - No habia forma de distinguir "va lento" de "se ha colgado".
#   - Se ejecuta por SSH a traves del proxy SOCKS5 de Mullvad, y un canal que
#     se queda callado acaba cortado con un "broken pipe". El silencio no
#     confundia: tumbaba la sesion a medio despliegue.


class SalidaFalsa:
    """Recoge lo escrito y CUENTA LOS FLUSH.

    Lo segundo importa tanto como lo primero: sin flush, Python guarda la
    salida en un buffer cuando no habla con un terminal, las lineas saldrian
    todas juntas al final y no habria trafico en el canal. O sea, el arreglo
    no arreglaria nada y esta prueba seguiria en verde mirando el texto.
    """

    def __init__(self):
        self.texto = ""
        self.flushes = 0

    def write(self, t):
        self.texto += t
        return len(t)

    def flush(self):
        self.flushes += 1


class RespuestaFalsa:
    def __init__(self, datos):
        self.datos = datos

    def read(self):
        return self.datos

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def bajar_con(abrir):
    """Ejecuta descargar() con un _abrir de mentira y devuelve lo escrito."""
    real_abrir, real_stdout = gen._abrir, sys.stdout
    falsa = SalidaFalsa()
    gen._abrir, sys.stdout = abrir, falsa
    try:
        error = None
        try:
            gen.descargar("apnic", "https://ejemplo/x")
        except RuntimeError as exc:
            error = exc
    finally:
        gen._abrir, sys.stdout = real_abrir, real_stdout
    return falsa, error


falsa, error = bajar_con(lambda url, espera: RespuestaFalsa(b"x" * 2_000_000))
comprueba("dice que fichero esta bajando", True, "apnic" in falsa.texto)
comprueba("y cuanto ha bajado", True, "1.9 MB" in falsa.texto)
comprueba("sin error", None, error)
comprueba("y lo suelta al momento, no al final", True, falsa.flushes >= 2)


def revienta(url, espera):
    raise OSError("se corto")


falsa, error = bajar_con(revienta)
comprueba("un fallo se ve en la linea", True, "FALLO" in falsa.texto)
# Lo importante: que el aviso no se coma el error. Si se lo comiera, la tabla
# se regeneraria a medias sin que nada lo dijera.
comprueba("y el error sigue subiendo", True, isinstance(error, RuntimeError))

# Una descarga corta tampoco puede pasar por buena.
falsa, error = bajar_con(lambda url, espera: RespuestaFalsa(b"pagina de error"))
comprueba("una descarga a medias sigue siendo un error", True,
          isinstance(error, RuntimeError))


# --------------------------------------------------------------------------
print("\nLa bandera sale en TODAS las alertas, no solo en Cowrie")
#
# Se pusieron banderas en cinco sitios y se quedo uno fuera: en dionaea-watch,
# el bloque de "Malware capturado" pinta la IP del atacante como
# "desde <code>...</code>" y NO llevaba pais ---la variable ahi se llama rip y
# no ip, y por eso se colo---. O sea que la misma IP salia con bandera en un
# bloque del mismo mensaje y sin ella en el de abajo.
#
# Esta comprobacion recorre los ficheros y exige que toda linea que pinte una
# IP de atacante lleve su pais. Es lo que evita que el proximo sitio nuevo se
# quede fuera otra vez.
ALERTAS = AQUI.parent   # la carpeta TELEGRAM SCRIPTS

# Como se reconoce "aqui se esta pintando la IP de un atacante".
HUELLAS = ("abuseipdb.com/check/", "Source: <code>", "desde <code>")
# Y como se reconoce que lleva su pais.
PAIS = ("pais_de", "etiqueta(")

sin_pais = []
sitios = 0
for rel in ("DIONAEA/dionaea-watch.sh", "ssh-watch.sh", "daily-digest.sh"):
    fichero = ALERTAS / rel
    for n, linea in enumerate(fichero.read_text(encoding="utf-8").splitlines(), 1):
        # Las definiciones de repuesto ---"pais_de() { return 0; }"--- y los
        # comentarios no pintan nada.
        recortada = linea.strip()
        if recortada.startswith("#"):
            continue
        if not any(h in linea for h in HUELLAS):
            continue
        sitios += 1
        if not any(x in linea for x in PAIS):
            sin_pais.append("%s:%d" % (rel, n))

comprueba("ninguna alerta de shell pinta una IP sin su pais", [], sin_pais)
# Si alguien anade un sitio nuevo, este numero cambia y hay que mirarlo. Es
# barato, y es lo que impide que la comprobacion se vuelva decorativa: sin el,
# un sitio nuevo sin pais no se detecta si ademas se olvida la huella.
#
# Son seis: dos en dionaea-watch (la conexion y la descarga), tres en
# ssh-watch (los tres tipos de acceso al anfitrion) y una en el resumen
# diario. Las del plugin de Cowrie se cuentan aparte, mas abajo.
comprueba("y siguen siendo los seis sitios de siempre", 6, sitios)

# El plugin de Cowrie se mira aparte porque ahi el pais se anade unas lineas
# despues de la IP, no en la misma. Se comprueba por funcion.
#
# Y con esto queda cubierto TELNET, que era la duda: el plugin no tiene un
# camino para SSH y otro para telnet ---_header() es una sola funcion, y de
# ella sale tambien el "via Telnet" de la cabecera---, asi que la bandera de
# la sesion de telnet es literalmente la misma linea de codigo.
arbol = ast.parse((ALERTAS / "COWRIE/telegram_alert_cowrie.py").read_text(
    encoding="utf-8"))
con_pais = set()
for nodo in ast.walk(arbol):
    if not isinstance(nodo, (ast.FunctionDef, ast.AsyncFunctionDef)):
        continue
    for dentro in ast.walk(nodo):
        if (isinstance(dentro, ast.Call)
                and isinstance(dentro.func, ast.Name)
                and dentro.func.id == "pais_de"):
            con_pais.add(nodo.name)

comprueba("la cabecera de cada aviso lleva pais (y con ella la de telnet)",
          True, "_header" in con_pais)
comprueba("y el [Cowrie] Resumen tambien", True, "_send_digest" in con_pais)


shutil.rmtree(tmp, ignore_errors=True)

print("\n-------------------------------------")
print("ok: %d   fallos: %d" % (OK, MAL))
sys.exit(1 if MAL else 0)
