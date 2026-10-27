# SPDX-License-Identifier: GPL-2.0-or-later
"""
Andamiaje comun de las pruebas: doble de `requests` y contador de fallos.

El doble sustituye a `requests` en sys.modules ANTES de importar nada del
reporter. Con el puesto, las pruebas son deterministas y no tocan la red ni
aunque alguien se dejara una bandera mal: si una peticion llegase a salir de
verdad, quedaria registrada aqui y la prueba lo diria.

Ojo con el orden: instalar_doble() tiene que llamarse antes del primer
`from common ...`, porque common/http.py importa requests al cargarse.
"""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path

# Raiz del reporter, deducida de la posicion de este fichero. Nada de rutas
# absolutas: las pruebas tienen que correr igual en el portatil y en la VPS.
RAIZ = Path(__file__).resolve().parent.parent
if str(RAIZ) not in sys.path:
    sys.path.insert(0, str(RAIZ))

# Peticiones que llegaron al doble. En modo simulacion aqui solo deberian
# aparecer LECTURAS (GET, y el POST de get_info de MalwareBazaar).
LLAMADAS: list[tuple[str, str]] = []
RESPUESTAS: dict[tuple[str, str], tuple[int, object]] = {}


class Respuesta:
    def __init__(self, status: int, body):
        self.status_code = status
        self._body = body
        self.headers: dict = {}
        self.text = json.dumps(body) if body is not None else ""

    def json(self):
        if self._body is None:
            raise ValueError("sin json")
        return self._body


class Sesion:
    def __init__(self):
        self.headers: dict = {}

    def request(self, method, url, **kw):
        LLAMADAS.append((method, url))
        for (m, trozo), (status, body) in RESPUESTAS.items():
            if m == method and trozo in url:
                return Respuesta(status, body)
        return Respuesta(200, {"query_status": "ok"})


def instalar_doble() -> None:
    modulo = types.ModuleType("requests")
    modulo.Session = Sesion
    modulo.RequestException = Exception
    sys.modules["requests"] = modulo


def responder(metodo: str, trozo_url: str, status: int, body) -> None:
    RESPUESTAS[(metodo, trozo_url)] = (status, body)


# --------------------------------------------------------------------------
class Resultados:
    """Cuenta comprobaciones. Lo que falla se ve; lo que pasa, tambien."""

    def __init__(self, titulo: str) -> None:
        self.titulo = titulo
        self.fallos: list[str] = []
        self.pasadas = 0

    def check(self, nombre: str, condicion: bool, detalle: str = "") -> bool:
        if condicion:
            self.pasadas += 1
            print(f"  ok    {nombre}")
        else:
            self.fallos.append(nombre)
            print(f"  FALLA {nombre}" + (f"  ({detalle})" if detalle else ""))
        return condicion

    def igual(self, nombre: str, obtenido, esperado) -> bool:
        return self.check(nombre, obtenido == esperado,
                          f"obtenido {obtenido!r}, esperado {esperado!r}")

    def seccion(self, texto: str) -> None:
        print(f"\n--- {texto}")

    def salida(self) -> int:
        print(f"\n{self.titulo}: {self.pasadas} correctas, {len(self.fallos)} fallidas")
        for f in self.fallos:
            print(f"  - {f}")
        return 1 if self.fallos else 0
