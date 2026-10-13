#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
voy_al_dia.py --- que version hay puesta y cual trae la copia del repositorio.

    ~/voy_al_dia.py            dice si la maquina va al dia
    ~/voy_al_dia.py --marcar   apunta lo desplegado (el ULTIMO paso al desplegar)

COMO LO SABE, sin listas que mantener: `git archive` rellena el fichero
VERSION con el commit al construir el tar, asi que la copia que llega a /tmp
dice de que version es. Al desplegar se copia ese mismo fichero a
/opt/dirtyland/VERSION con --marcar, y a partir de ahi comparar es comparar
dos cadenas.

LA VERSION ANTERIOR HACIA MUCHO MAS y por eso se cambio: llevaba dentro un
mapa de las nueve piezas, fichero a fichero, y comparaba cada uno con su copia
desplegada. Cazaba mas ---un despliegue a medias, por ejemplo--- pero habia
que tocarlo cada vez que se anadia un fichero, y una herramienta que hay que
mantener al dia para que te diga si vas al dia acaba sobrando.

QUE YA NO DETECTA, y conviene saberlo: si copias unas piezas y otras no, esto
dira que vas al dia igualmente, porque solo mira el sello. El sello se pone
al final del despliegue, asi que la forma de no equivocarse es la de siempre:
seguir el README entero y marcar al terminar.
"""

from __future__ import annotations

import os
import sys

REPO = os.environ.get("DIRTYLAND_REPO", "/tmp/dirtyland-repo")
SELLO_REPO = os.path.join(REPO, "3.6 Para facilitarnos la vida", "VERSION")
SELLO_MAQUINA = os.environ.get("DIRTYLAND_SELLO", "/opt/dirtyland/VERSION")


def leer(ruta: str) -> dict:
    """El commit y la fecha de un fichero VERSION, o {} si no se puede."""
    datos: dict[str, str] = {}
    try:
        with open(ruta, encoding="utf-8", errors="replace") as fh:
            for linea in fh:
                if linea.startswith("#"):
                    continue
                partes = linea.split(None, 1)
                if len(partes) == 2:
                    datos[partes[0]] = partes[1].strip()
    except OSError:
        return {}
    # Sin sustituir es que no viene de un `git archive`: la carpeta se trajo a
    # mano, que es justo lo que el README prohibe. Vale mas decirlo que
    # comparar dos marcadores y dar un "al dia" que no significa nada.
    if "$Format" in datos.get("commit", "$Format"):
        return {}
    return datos


def corto(datos: dict) -> str:
    return "%s  %s" % (datos.get("commit", "?")[:7],
                       datos.get("fecha", "?")[:16])


def main() -> int:
    copia = leer(SELLO_REPO)
    if not copia:
        print("No hay copia del repositorio en %s, o no trae sello." % REPO)
        print("Subela siguiendo el README y vuelve a mirar.")
        return 2

    if len(sys.argv) > 1 and sys.argv[1] == "--marcar":
        try:
            os.makedirs(os.path.dirname(SELLO_MAQUINA), exist_ok=True)
            with open(SELLO_REPO, encoding="utf-8") as origen, \
                    open(SELLO_MAQUINA, "w", encoding="utf-8") as destino:
                destino.write(origen.read())
        except OSError as exc:
            print("no se pudo escribir %s: %s" % (SELLO_MAQUINA, exc),
                  file=sys.stderr)
            return 1
        print("marcado: %s" % corto(copia))
        return 0

    puesto = leer(SELLO_MAQUINA)
    print("en la maquina : %s" % (corto(puesto) if puesto else "sin marcar"))
    print("en la copia   : %s" % corto(copia))

    if not puesto:
        print("SIN MARCAR. Despliega siguiendo el README y termina con:")
        print("  sudo ~/voy_al_dia.py --marcar")
        return 1
    if puesto.get("commit") == copia.get("commit"):
        print("AL DIA")
        return 0
    print("ATRASADO")
    return 1


if __name__ == "__main__":
    sys.exit(main())
