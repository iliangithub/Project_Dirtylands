#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
paises.py
De que pais es una IP, para ponerlo al lado en las alertas.

Como libreria, que es como lo usa el plugin de Cowrie:

    import paises
    paises.etiqueta("153.117.13.106")     ->  "\U0001f1f5\U0001f1f0 Pakistan"

Y como orden, que es como lo usan los vigilantes del anfitrion (en bash):

    python3 /opt/dirtyland/geoip/paises.py 8.8.8.8 1.1.1.1
    8.8.8.8 \U0001f1fa\U0001f1f8 Estados Unidos
    1.1.1.1 \U0001f1e6\U0001f1fa Australia

NO CONSULTA NADA. Lee la tabla que dejo generar-tabla-paises.py, que se
construye a partir de los ficheros publicos de los cinco RIR. Ni red, ni
claves, ni cuota: por eso puede ponerse en CADA alerta sin pensarlo.

Y NO LA CARGA EN MEMORIA. Los registros de la tabla son todos del mismo largo
y estan ordenados, asi que se busca con saltos dentro del fichero: unos 18
seek() para 150.000 tramos. Medido, 0,018 ms por consulta. Cargar los 4,8 MB
en cada proceso ---y el plugin de Cowrie es uno de los que consulta--- seria
gastar memoria del contenedor para no ir mas rapido.

LA BANDERA NO SE GUARDA, SE CALCULA. El emoji de una bandera son las dos
letras del pais escritas con los "indicadores regionales" de Unicode, asi que
sale del propio codigo: TR -> \U0001f1f9\U0001f1f7. Guardarlas seria guardar
249 emojis que ya estan implicitos.

DOS TABLAS, PORQUE SON DOS PREGUNTAS. "ubicacion" (de db-ip) dice donde ESTA
la maquina, que es lo que responde AbuseIPDB y lo que espera quien lee una
bandera. "registro" (de los RIR) dice quien es el TITULAR del bloque.
Coinciden en el 92% de las IP; cuando no, se ensenan las dos, porque esa
discrepancia significa que el rango esta alquilado.

La primera version solo traia el registro, y por eso una IP anunciada desde
Eslovenia salia como Estados Unidos: el bloque se registro alli en 2025 y se
alquilo despues. Es exactamente lo que hace la infraestructura de ataque.

NUNCA LEVANTA UNA EXCEPCION. Si falta la tabla, si esta a medias o si la IP no
se entiende, devuelve cadena vacia y la alerta sale sin bandera. Una alerta
sin bandera se lee igual de bien; una alerta que no llega porque el adorno
fallo, no.
"""
from __future__ import annotations

import ipaddress
import os
import sys

BASE = os.environ.get("DIRTYLAND_GEOIP", "/opt/dirtyland/geoip")

# Tienen que coincidir con los de generar-tabla-paises.py. Hay una prueba que
# compara los dos ficheros para que no puedan separarse en silencio.
ANCHO_V4 = 14
ANCHO_V6 = 20

_nombres: dict[str, str] | None = None


def _cargar_nombres() -> dict[str, str]:
    global _nombres
    if _nombres is None:
        datos: dict[str, str] = {}
        try:
            with open(os.path.join(BASE, "nombres.txt"), encoding="utf-8") as fh:
                for linea in fh:
                    if linea.startswith("#") or " " not in linea:
                        continue
                    cc, nombre = linea.rstrip("\n").split(" ", 1)
                    datos[cc] = nombre
        except OSError:
            pass
        _nombres = datos
    return _nombres


def bandera(cc: str) -> str:
    """El emoji de la bandera, a partir del codigo de dos letras."""
    cc = (cc or "").upper()
    if len(cc) != 2 or not cc.isalpha():
        return ""
    return chr(0x1F1E6 + ord(cc[0]) - 65) + chr(0x1F1E6 + ord(cc[1]) - 65)


def _buscar(ruta: str, ancho: int, clave: int, hexa: bool) -> str:
    """Busqueda binaria SOBRE EL FICHERO. "??" si no cae en ningun tramo."""
    try:
        tam = os.path.getsize(ruta)
    except OSError:
        return ""
    n, resto = divmod(tam, ancho)
    if not n or resto:
        # Un tamano que no es multiplo del registro significa fichero a medias
        # o formato cambiado. Un seek ahi apuntaria en mitad de una linea y
        # devolveria basura con toda la apariencia de ser un pais.
        return ""
    try:
        with open(ruta, "rb") as fh:
            lo, hi = 0, n
            while lo < hi:
                mid = (lo + hi) // 2
                fh.seek(mid * ancho)
                if int(fh.read(ancho - 3), 16 if hexa else 10) <= clave:
                    lo = mid + 1
                else:
                    hi = mid
            if lo == 0:
                return "??"
            fh.seek((lo - 1) * ancho + ancho - 3)
            return fh.read(2).decode("ascii", "replace")
    except (OSError, ValueError):
        return ""


def _consultar(ip: str, cual: str) -> str:
    """El pais de una IP segun una de las dos tablas, o "" si no se sabe."""
    try:
        dir_ip = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return ""
    # Una IP privada no es de ningun pais, y ademas suele ser nuestra: la del
    # contenedor, la de la red interna o el bucle. Preguntar por ella no tiene
    # respuesta buena.
    if not dir_ip.is_global:
        return ""
    if dir_ip.version == 4:
        cc = _buscar(os.path.join(BASE, f"{cual}-v4.txt"), ANCHO_V4,
                     int(dir_ip), False)
    else:
        cc = _buscar(os.path.join(BASE, f"{cual}-v6.txt"), ANCHO_V6,
                     int(dir_ip) >> 64, True)
    return "" if cc in ("", "??") else cc


def codigo(ip: str) -> str:
    """Donde ESTA la maquina, segun db-ip. Es el dato principal."""
    return _consultar(ip, "ubicacion")


def registro(ip: str) -> str:
    """Donde se REGISTRO el bloque, segun los RIR."""
    return _consultar(ip, "registro")


def _con_bandera(cc: str) -> str:
    nombre = _cargar_nombres().get(cc, cc)
    marca = bandera(cc)
    return f"{marca} {nombre}" if marca else nombre


def etiqueta(ip: str) -> str:
    """Lo que se pega detras de una IP en un aviso.

    Normalmente "<bandera> <Pais>". Pero cuando la ubicacion y el registro NO
    coinciden se dicen las dos:

        \U0001f1f8\U0001f1ee Eslovenia (bloque de \U0001f1fa\U0001f1f8 Estados Unidos)

    Y eso no es un adorno: las dos fuentes coinciden en el 92% de las IP, y
    donde discrepan es en la nube y en los rangos ALQUILADOS ---un
    intermediario alquila bloques a titulares de medio mundo y los anuncia
    desde su centro de datos---. Justo el perfil de la infraestructura desde
    la que atacan a un senuelo. La discrepancia ES la senal.

    Se devuelve vacio y no un "desconocido": quien llama lo pega detras de la
    IP, y una linea que acaba en "desconocido" ocupa sitio para no decir nada.
    """
    donde = codigo(ip)
    quien = registro(ip)
    if not donde and not quien:
        return ""
    if not donde:
        # Sin ubicacion, el registro es lo unico que hay. Se dice tal cual: no
        # se puede afirmar que la maquina este ahi, pero es mejor que nada.
        return _con_bandera(quien)
    if not quien or quien == donde:
        return _con_bandera(donde)
    return "%s (bloque de %s)" % (_con_bandera(donde), _con_bandera(quien))


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("uso: paises.py IP [IP...]", file=sys.stderr)
        return 2
    for ip in argv[1:]:
        # Se imprime la IP delante SIEMPRE, tenga pais o no: quien llama desde
        # bash empareja por esa primera columna, y una linea que desaparece le
        # descuadra el emparejamiento.
        print("%s %s" % (ip, etiqueta(ip)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
