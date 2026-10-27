#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Parche del mssql.py de Dionaea: el bucle que cuelga el senuelo entero.

    sudo /opt/dirtyland/dionaea/parche-mssql.py /opt/dirtyland/dionaea/mssql.py

QUE PASA SIN ESTO. Dionaea se queda dando vueltas ---no se muere--- y deja de
atender y de anotar. Ocurrio dos veces en una semana: el 2026-08-23 a las
17:11, y otra vez el 28 a las 21:17:31, noventa segundos despues de
reiniciarlo. La segunda vez esas dos lineas de MSSQL fueron lo UNICO que llego
a escribir en su log antes de callarse para siempre.

Desde fuera todo parece correcto: "docker ps" dice Up, el proceso existe y el
DNAT sigue contando paquetes que entran. Lo unico que se nota es un nucleo al
100% y que la base deja de crecer.

DONDE ESTA EL FALLO. En handle_io_in(), asi tal cual:

    if p.Length == 0:                       # <-- este guarda SI protege
        logger.warning("Bad TDS Header, Length = 0")
        return offset
    ...
    chunk = data[offset:offset+p.Length]
    p = TDS_Header(chunk)                   # <-- se REESCRIBE p
    offset += p.Length                      # <-- y se avanza con el NUEVO p

La cabecera TDS ocupa 8 bytes y su campo Length es el tamano del paquete
ENTERO, cabecera incluida, asi que no puede valer menos de 8. Pero solo se
rechaza el 0. Con un Length declarado entre 1 y 7 ---que lo pone quien se
conecta--- pasa esto:

  1. chunk sale de menos de 8 bytes, o sea mas corto que la propia cabecera.
  2. TDS_Header(chunk) reparsea ese trozo truncado y rellena con ceros lo que
     falta, asi que el Length del p NUEVO es 0.
  3. offset += 0. El offset no avanza.
  4. El "continue" de mas abajo vuelve al principio con los mismos bytes.

Y ahi se queda. Para siempre, sin escribir una linea, porque ese camino no
registra nada. Por eso el log se corta en seco.

QUE ARREGLA ESTE PARCHE, en dos lineas:

  - Rechaza cualquier Length menor que 8, no solo el 0. Es lo que dice el
    protocolo, y ademas deja constancia del valor recibido en vez de escribir
    "Length = 0" cuando era un 3.
  - Guarda cuanto hay que avanzar ANTES de reescribir p, para que el offset
    avance siempre por el valor ya comprobado. Aunque el reparseo devuelva
    cualquier cosa, el bucle progresa.

NO se toca nada mas. Es codigo suyo, y cuanto menos se le cambie, menos hay
que rehacer cuando se actualice la imagen.

SE NIEGA A ADIVINAR. Si el fichero no es exactamente el que esperamos ---por
ejemplo tras cambiar el digest de la imagen--- no parchea nada y lo dice. Un
parche aplicado a medias sobre un fichero que ya cambio es peor que no
aplicarlo: se monta encima, no da ningun error, y el senuelo se comporta de
una forma que no esta escrita en ningun sitio.
"""

from __future__ import annotations

import io
import sys

# (que se busca, por que se cambia, por que se pone)
CAMBIOS = (
    (
        """                if p.Length == 0:
                    logger.warning("Bad TDS Header, Length = 0")
                    return offset
""",
        """                # PARCHE DIRTYLAND: la cabecera TDS son 8 bytes y su Length
                # incluye la cabecera, asi que un Length < 8 es imposible. Solo
                # se rechazaba el 0, y con un 1..7 el bucle de abajo se queda
                # colgado para siempre. Ver DIONAEA/parche-mssql.py.
                if p.Length < 8:
                    logger.warning("Bad TDS Header, Length = %s", p.Length)
                    return offset
""",
    ),
    (
        """                chunk = data[offset:offset+p.Length]
                p = TDS_Header(chunk)
""",
        """                chunk = data[offset:offset+p.Length]
                # PARCHE DIRTYLAND: cuanto hay que avanzar se guarda ANTES de
                # reescribir p. Si no, se avanza con el Length del reparseo de
                # un trozo truncado ---que sale 0--- y el offset no se mueve.
                avance = p.Length
                p = TDS_Header(chunk)
""",
    ),
    (
        """                offset += p.Length
""",
        """                offset += avance
""",
    ),
)

YA_PARCHEADO = "PARCHE DIRTYLAND"


def main() -> int:
    if len(sys.argv) != 2:
        print("uso: parche-mssql.py <ruta del mssql.py>", file=sys.stderr)
        return 2
    ruta = sys.argv[1]

    try:
        texto = io.open(ruta, encoding="utf-8").read()
    except OSError as err:
        print("no se pudo leer %s: %s" % (ruta, err), file=sys.stderr)
        return 1

    # Idempotente a proposito: el README se sigue copiando y pegando, y
    # ejecutarlo dos veces no puede romper nada.
    if YA_PARCHEADO in texto:
        print("ya estaba parcheado, no se toca nada")
        return 0

    for viejo, _nuevo in CAMBIOS:
        veces = texto.count(viejo)
        if veces != 1:
            print(
                "ESTE mssql.py NO ES EL ESPERADO: el fragmento\n\n%s\n"
                "aparece %d veces (deberia aparecer 1). No se parchea nada.\n"
                "Probablemente ha cambiado la imagen de Dionaea: hay que\n"
                "revisar el fallo a mano antes de montar nada encima."
                % (viejo.rstrip(), veces),
                file=sys.stderr,
            )
            return 1

    for viejo, nuevo in CAMBIOS:
        texto = texto.replace(viejo, nuevo, 1)

    io.open(ruta, "w", encoding="utf-8").write(texto)

    # Se comprueba lo escrito, no se da por bueno el write.
    comprobar = io.open(ruta, encoding="utf-8").read()
    if comprobar.count(YA_PARCHEADO) != 2 or "offset += p.Length" in comprobar:
        print("el parche no quedo como debia", file=sys.stderr)
        return 1
    print("parcheado: %s" % ruta)
    return 0


if __name__ == "__main__":
    sys.exit(main())
