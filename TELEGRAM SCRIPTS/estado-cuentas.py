#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
"Me han baneado?" — comprueba que las cuentas de las plataformas siguen vivas.

Lo imprime en HTML para que daily-digest.sh lo pegue en el resumen diario.

QUE COMPRUEBA, Y QUE NO. Esto es importante y conviene tenerlo claro antes de
confiar en el "No" de cada linea:

  - Hace UNA peticion autenticada por plataforma y mira si la credencial
    sigue siendo aceptada. Un 401 o un 403 significan que la clave ya no
    vale, y eso es lo que pasa cuando cierran una cuenta.
  - NO puede detectar una cuenta que sigue leyendo pero tiene la publicacion
    restringida. Eso no se ve desde fuera hasta que se intenta publicar, y
    cuando ocurre lo caza el cortacircuitos, que tambien sale aqui.

Por eso el apartado da dos senales por cuenta: si la clave responde, y si
nuestro propio cortacircuitos ha saltado. La segunda es la que avisa antes.

Las peticiones son de lectura y gastan una llamada al dia de cada cuota:
1 de 1000 en AbuseIPDB, 1 de 500 en VirusTotal. Es un precio razonable por
enterarse el mismo dia y no tres semanas despues.
"""

from __future__ import annotations

import configparser
import json
import sqlite3
import sys
import urllib.error
import urllib.parse
import urllib.request

CFG = "/opt/dirtyland/platform-reporter/config.ini"
STATE_DB = "/var/lib/dirtyland-reporter/state.sqlite3"
TIMEOUT = 20

# Hash de EICAR, el fichero de prueba estandar de la industria. Se usa solo
# como excusa para una consulta autenticada: existe siempre en VirusTotal, no
# es malware de verdad y no ensucia nada.
EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

OK, BANEADO, DUDA = "ok", "baneado", "duda"

_ICONO = {OK: "✅", BANEADO: "\U0001F6A8", DUDA: "❓"}
_TEXTO = {OK: "No me han baneado", BANEADO: "SI, LA CLAVE YA NO VALE",
          DUDA: "no se pudo comprobar"}


def _pedir(url: str, cabeceras: dict, datos: bytes | None = None):
    """Devuelve (codigo_http, cuerpo). Un fallo de red da (None, motivo)."""
    req = urllib.request.Request(url, data=datos, headers=cabeceras,
                                 method="POST" if datos else "GET")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, r.read(4000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(2000).decode("utf-8", "replace")
    except Exception as exc:                              # noqa: BLE001
        return None, str(exc)


def _por_codigo(codigo, cuerpo, detalle_ok: str = "") -> tuple[str, str]:
    if codigo is None:
        return DUDA, f"sin respuesta ({cuerpo[:60]})"
    if codigo in (401, 403):
        return BANEADO, f"HTTP {codigo}"
    if codigo == 429:
        # Que nos limiten el ritmo no es un baneo, pero tampoco confirma nada.
        return DUDA, "HTTP 429 (limite de ritmo)"
    if 200 <= codigo < 300:
        return OK, detalle_ok or f"HTTP {codigo}"
    return DUDA, f"HTTP {codigo}"


def abuseipdb(clave: str) -> tuple[str, str]:
    url = ("https://api.abuseipdb.com/api/v2/check?"
           + urllib.parse.urlencode({"ipAddress": "8.8.8.8", "maxAgeInDays": 1}))
    codigo, cuerpo = _pedir(url, {"Key": clave, "Accept": "application/json"})
    return _por_codigo(codigo, cuerpo)


def virustotal(clave: str) -> tuple[str, str]:
    codigo, cuerpo = _pedir(f"https://www.virustotal.com/api/v3/files/{EICAR}",
                            {"x-apikey": clave})
    return _por_codigo(codigo, cuerpo)


def abusech(clave: str) -> tuple[str, str]:
    """MalwareBazaar. Vale por las tres: comparten la misma cuenta.

    abuse.ch no siempre usa el codigo HTTP para decir que no: puede
    responder 200 con un query_status que lo explica. Por eso se mira
    tambien el cuerpo.
    """
    # El parametro de get_info se llama "hash", no "sha256_hash" --- ese es el
    # de add_comment. Con el nombre equivocado la API contestaba
    # "no_hash_provided", y eso no es inofensivo: una consulta mal formada
    # puede rechazarse ANTES de mirar la credencial, con lo que una clave
    # revocada habria pasado por buena. La comprobacion parecia funcionar
    # precisamente porque no llegaba a comprobar nada.
    datos = urllib.parse.urlencode({"query": "get_info",
                                    "hash": EICAR}).encode()
    codigo, cuerpo = _pedir("https://mb-api.abuse.ch/api/v1/",
                            {"Auth-Key": clave,
                             "Content-Type": "application/x-www-form-urlencoded"},
                            datos)
    bajo = (cuerpo or "").lower()
    if any(p in bajo for p in ("unauthorized", "illegal_auth_key",
                               "auth_key", "banned", "blacklisted")):
        try:
            estado = json.loads(cuerpo).get("query_status", "?")
        except Exception:                                 # noqa: BLE001
            estado = "?"
        return BANEADO, f"query_status={estado}"
    estado, detalle = _por_codigo(codigo, cuerpo)
    if estado is OK:
        try:
            detalle = "query_status=" + json.loads(cuerpo).get("query_status", "ok")
        except Exception:                                 # noqa: BLE001
            pass
    return estado, detalle


def cortacircuitos() -> str | None:
    """Nuestra propia senal: si salto, abuse.ch nos estaba rechazando."""
    try:
        db = sqlite3.connect(f"file:{STATE_DB}?mode=ro", uri=True, timeout=10)
        db.row_factory = sqlite3.Row
        fila = db.execute("SELECT account, tripped_at, reason FROM breaker"
                          " LIMIT 1").fetchone()
        db.close()
    except Exception:                                     # noqa: BLE001
        return None
    if not fila:
        return None
    return (f"cuenta <code>{fila['account']}</code> desde "
            f"<code>{fila['tripped_at']}</code>: {fila['reason'][:160]}")


def main() -> int:
    cp = configparser.ConfigParser(inline_comment_prefixes=("#", ";"))
    try:
        cp.read(CFG, encoding="utf-8")
    except Exception as exc:                              # noqa: BLE001
        print(f"  no se pudo leer la configuracion: {exc}")
        return 0

    claves = cp["api_keys"] if cp.has_section("api_keys") else {}

    def clave_de(nombre: str) -> str:
        v = (claves.get(nombre) or "").strip()
        return "" if v.startswith("<") or v.endswith(">") else v

    # SE ESCRIBE "abusech", SIN PUNTO, y es lo unico que funciona de verdad.
    # Telegram convierte en enlace cualquier cosa con pinta de dominio, asi
    # que "abuse.ch" salia subrayado y pinchable como si fuera una
    # recomendacion nuestra.
    #
    # Se probaron dos apanos antes y ninguno vale: meterlo en un <code> si lo
    # impide, pero lo pinta en letra de maquina de escribir ---como algo para
    # copiar y pegar--- y desentona con las otras dos; y un separador de ancho
    # cero entre el nombre y el dominio NO enganya al detector de Telegram,
    # comprobado en el movil.
    #
    # Sin punto no hay dominio que detectar. Y ademas es como se llama ya esa
    # clave en el config.ini, asi que no es un nombre inventado para la
    # ocasion.
    comprobaciones = (
        ("AbuseIPDB", clave_de("abuseipdb"), abuseipdb),
        ("VirusTotal", clave_de("virustotal"), virustotal),
        ("abusech", clave_de("abusech"), abusech),
    )

    # Este apartado responde UNA pregunta: siguen valiendo las cuentas. Si
    # una plataforma esta apagada o encendida es decision nuestra y se ve en
    # el apartado de los reporters, junto a sus numeros, que es donde importa
    # --- ahi una linea de ceros queda explicada por el punto rojo de al lado.
    # Meterlo tambien aqui solo enturbiaba la respuesta.
    lineas, hay_problema = [], False
    for etiqueta, clave, comprobar in comprobaciones:
        if not clave:
            estado, detalle = DUDA, "sin clave configurada"
        else:
            estado, detalle = comprobar(clave)
        if estado is not OK:
            hay_problema = True
        lineas.append(f"{_ICONO[estado]} <b>{etiqueta}:</b> {_TEXTO[estado]}"
                      f"  <i>({detalle})</i>")

    roto = cortacircuitos()
    if roto:
        hay_problema = True
        lineas.append(f"\U0001F6A8 <b>Cortacircuitos SALTADO</b> — {roto}")
        lineas.append("   Las tres de abuse.ch estan apagadas hasta rearmarlo "
                      "a mano con <code>--reset-breaker</code>.")

    cabecera = ("✅ <b>Todo en orden</b>" if not hay_problema
                else "⚠️ <b>Algo que mirar</b>")
    print(cabecera)
    for linea in lineas:
        print(linea)

    # Segundo parser SOLO para los enlaces. configparser normaliza los nombres
    # de clave a minusculas, y aqui el nombre es el texto del enlace: sin esto
    # "MalwareBazaar" se publicaba como "malwarebazaar". Se hace en un parser
    # aparte y no cambiando optionxform en el de arriba, porque eso volveria
    # sensibles a mayusculas todas las demas busquedas del fichero.
    cp2 = configparser.ConfigParser(inline_comment_prefixes=("#", ";"))
    cp2.optionxform = str
    try:
        cp2.read(CFG, encoding="utf-8")
    except Exception:                                     # noqa: BLE001
        cp2 = cp
    perfiles = cp2["perfiles"] if cp2.has_section("perfiles") else {}
    enlaces = [(n, u.strip()) for n, u in perfiles.items()
               if u.strip() and not u.strip().startswith("<")]
    if enlaces:
        print("\n<u>Mis perfiles</u>")
        for nombre, url in enlaces:
            print(f'<a href="{url}">{nombre}</a>')
    return 0


if __name__ == "__main__":
    sys.exit(main())
