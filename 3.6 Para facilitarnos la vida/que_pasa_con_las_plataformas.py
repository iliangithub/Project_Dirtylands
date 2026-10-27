#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
que_pasa_con_las_plataformas.py
Plataforma por plataforma: que se publico, que se descarto y POR QUE.

    sudo ~/que_pasa_con_las_plataformas.py            las ultimas 24 h
    sudo ~/que_pasa_con_las_plataformas.py --dias 7   una semana
    sudo ~/que_pasa_con_las_plataformas.py --todo     desde el principio
    sudo ~/que_pasa_con_las_plataformas.py --sha X    la historia de UNA muestra

Por que existe: el resumen diario da un numero por plataforma y ahi se acaba.
Cuando ese numero es un cero ---que en MalwareBazaar es lo habitual y no es un
fallo--- no dice cual fue la muestra ni que puerta la paro. Esto si.

NO decide nada ni envia nada. Solo lee la base de estado del reporter, asi que
se puede lanzar cuantas veces se quiera sin gastar cuota de ninguna API.

Las claves de `sent` no son iguales en todas las plataformas, y por eso cada
una se cuenta a su manera:

    abuseipdb      ip@fecha          una fila por IP y dia
    virustotal     upload: vote:     varias filas por muestra
    malwarebazaar  upload:           mas la de atribucion
    threatfox      tipo:indicador
    urlhaus        la URL entera
"""
from __future__ import annotations

import argparse
import collections
import os
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

BASE = "/var/lib/dirtyland-reporter/state.sqlite3"
CONFIG = "/opt/dirtyland/platform-reporter/config.ini"

# El orden es el que pidio quien lo usa, no el alfabetico.
PLATAFORMAS = ["abuseipdb", "virustotal", "threatfox", "malwarebazaar", "urlhaus"]
CUENTA_ABUSECH = {"malwarebazaar", "threatfox", "urlhaus"}

# Lo que cada puerta significa, en una linea. Sin esto hay que ir al codigo.
QUE_SIGNIFICA = {
    "antiguedad": "la muestra lleva mas de 10 dias en VirusTotal. Es la POLITICA "
                  "de MalwareBazaar, no un criterio nuestro, y ya costo la cuenta",
    "familia": "los motores no se ponen de acuerdo en como llamarla. Hacen falta "
               "3 diciendo el mismo nombre. NO significa que no sea malware: solo "
               "que no se le puede poner nombre, y por eso solo lo paran las dos "
               "plataformas que publican la muestra etiquetada",
    "deteccion": "no llega al minimo de motores que la marcan como maliciosa",
    "veredicto": "VirusTotal todavia no la conoce o no ha terminado de analizarla",
    "adware": "la senal dominante es adware o PUP, no malware",
    "sin-muestra": "se vio la URL pero no se capturo el binario, asi que no hay "
                   "nada que acreditar",
    "muestra-compartida": "SI se capturo, pero ese hash llego antes por otra URL "
                          "y es esa la que lleva la muestra",
    "enfriamiento": "esa IP ya se denuncio hace menos de 24 h",
    "duplicado": "ya se envio antes; la memoria por hash evita repetirlo",
    "tope-por-pasada": "no cabia en esta pasada. NO se pierde: sale en la siguiente",
    "cuota": "se llego al limite diario de esa API",
    "rechazo-plataforma": "LO RECHAZO LA PLATAFORMA. Es el unico que deberia "
                          "preocupar, y el que dispara el cortacircuitos",
    "barrera": "el texto o la IP tocaban infraestructura propia. Se aborto",
    "politica-wannacry": "familia vetada por indicacion expresa de abuse.ch",
    "esquema": "la URL no es http/https, asi que el puerto seria una suposicion",
    "acortador": "es un acortador o redirector, no el origen real",
    "ioc-no-derivable": "de esa URL no sale un indicador del que respondamos",
    "handshake": "no hubo sesion completa; podria ser una IP falsificada",
    "evidencia": "no hay bastante de lo que acusar",
}


def abrir():
    if not os.path.exists(BASE):
        sys.exit(f"no encuentro la base de estado en {BASE}")
    try:
        db = sqlite3.connect(f"file:{BASE}?mode=ro", uri=True)
    except sqlite3.OperationalError as exc:
        sys.exit(f"no se pudo abrir la base: {exc}")
    db.row_factory = sqlite3.Row
    return db


def tiene_tabla(db, nombre) -> bool:
    """Si la base tiene esa tabla.

    Se pregunta ANTES de consultarla, en vez de envolver el SELECT en un
    `except sqlite3.Error: continue`, que es lo que habia aqui: aquel except no
    distinguia "esta base es vieja y todavia no tiene la tabla" ---que hay que
    callar--- de "la consulta esta mal escrita" ---que no---, y se tragaba las
    dos por igual. Un error de esquema tiene que verse.
    """
    return db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (nombre,)).fetchone() is not None


def activadas() -> dict:
    """Que dice el config.ini de cada plataforma. Si no se puede leer, se calla."""
    import configparser
    cp = configparser.ConfigParser(inline_comment_prefixes=("#", ";"))
    try:
        cp.read(CONFIG, encoding="utf-8")
    except Exception:                                     # noqa: BLE001
        return {}
    return {p: cp.getboolean(p, "enabled", fallback=False)
            for p in PLATAFORMAS if cp.has_section(p)}


def corte(dias):
    if dias is None:
        return None
    return (datetime.now(timezone.utc) - timedelta(days=dias)).isoformat()


def historia_de(db, sha):
    """Todo lo que le ha pasado a UNA muestra, en orden."""
    fila = db.execute("SELECT * FROM samples WHERE sha256=?", (sha,)).fetchone()
    print(f"=== {sha} ===")
    if not fila:
        print("  no esta en la base: el colector no la ha recogido")
        return
    print(f"  estado          : {fila['state']}")
    print(f"  vista aqui      : {fila['first_local'][:19]}")
    print(f"  primera en VT   : {fila['vt_first_sub'][:19] if fila['vt_first_sub'] else 'nunca vista'}")
    print(f"  motores / familia: {fila['vt_malicious']} / {fila['family'] or '-'}")
    print(f"  intentos        : {fila['attempts']}")
    print(f"  proximo intento : {fila['next_check'][:19] if fila['next_check'] else '-'}")
    print()
    env = list(db.execute(
        "SELECT platform, status, sent_at, detail FROM sent WHERE key LIKE ?",
        (f"%{sha}%",)))
    print("  PUBLICADO:")
    if env:
        for r in env:
            print(f"    {r['sent_at'][:19]}  {r['platform']:<14} {r['status']:<9} {r['detail'] or ''}")
    else:
        print("    en ninguna plataforma")
    print()
    rz = list(db.execute(
        "SELECT ts, platform, gate, reason FROM rejections WHERE key LIKE ? "
        "ORDER BY ts DESC LIMIT 20", (f"%{sha}%",)))
    print("  DESCARTES (los 20 ultimos):")
    if not rz:
        print("    ninguno")
    for r in rz:
        print(f"    {r['ts'][:19]}  {r['platform']:<14} {r['gate']}")
        print(f"        {r['reason']}")


def bloque(db, plat, desde, activa, salto):
    print()
    print("=" * 72)
    estado = "activada" if activa else ("APAGADA" if activa is False else "?")
    print(f"  {plat.upper()}   [{estado}]")
    if salto and plat in CUENTA_ABUSECH:
        print(f"  CORTACIRCUITOS SALTADO el {salto['tripped_at'][:19]}")
        print(f"    {salto['reason']}")
        print("    Ninguna de las tres de abuse.ch publica hasta rearmarlo.")
    print("=" * 72)

    cond, args = "platform=?", [plat]
    if desde:
        cond += " AND sent_at>=?"
        args.append(desde)
    env = list(db.execute(
        f"SELECT status, sent_at, key, detail FROM sent WHERE {cond} "
        "ORDER BY sent_at DESC", args))
    reales = [r for r in env if r["status"] != "simulado"]
    print(f"  PUBLICADO: {len(reales)}")
    for r in reales[:8]:
        print(f"    {r['sent_at'][:19]}  {r['key'][:52]}  {r['detail'] or ''}")
    if len(reales) > 8:
        print(f"    ... y {len(reales) - 8} mas")

    cond, args = "platform=?", [plat]
    if desde:
        cond += " AND ts>=?"
        args.append(desde)
    rz = list(db.execute(
        f"SELECT ts, gate, key, reason FROM rejections WHERE {cond} "
        "ORDER BY ts DESC", args))
    grupos = collections.Counter(r["gate"] for r in rz)
    print()
    print(f"  DESCARTADO: {len(rz)}   (motivos distintos: {len(grupos)})")
    for gate, n in grupos.most_common():
        print()
        print(f"    [{gate}]  x{n}")
        explic = QUE_SIGNIFICA.get(gate)
        if explic:
            print(f"      que significa: {explic}")
        # Un ejemplar concreto, que es lo que hace falta para actuar.
        for r in rz:
            if r["gate"] == gate:
                print(f"      ejemplo: {r['key'][:60]}")
                print(f"        {r['reason'][:160]}")
                break

    hoy = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    # La columna NO se llama igual en las dos tablas, y quien lo fija es el
    # esquema de common/state.py: `quota` cuenta PUBLICACIONES en `used` y
    # `api_calls` cuenta LLAMADAS en `calls`. Pidiendo `used` a las dos, el
    # SELECT de api_calls lanzaba OperationalError, un `except sqlite3.Error`
    # se lo tragaba y la linea de las llamadas NO SE IMPRIMIA NUNCA: el bloque
    # de la plataforma salia entero y con pinta de correcto, solo que sin ese
    # dato. Y es el que mas importa, porque el tope de VirusTotal son 500
    # peticiones al dia e incluye las consultas de hash ---lo mas frecuente
    # con diferencia---, que es justo lo que cuenta api_calls y no quota.
    for tabla, columna, etiqueta in (("quota", "used", "publicaciones"),
                                     ("api_calls", "calls", "llamadas")):
        if not tiene_tabla(db, tabla):
            continue
        f = db.execute(
            f"SELECT {columna} AS n FROM {tabla} WHERE platform=? AND day=?",
            (plat, hoy)).fetchone()
        if f:
            print(f"\n  {etiqueta} hoy: {f['n']}")


def main() -> int:
    p = argparse.ArgumentParser(description="Que pasa con cada plataforma")
    p.add_argument("--dias", type=int, default=1)
    p.add_argument("--todo", action="store_true")
    p.add_argument("--sha", metavar="SHA256")
    a = p.parse_args()

    db = abrir()
    if a.sha:
        historia_de(db, a.sha.strip().lower())
        return 0

    desde = None if a.todo else corte(a.dias)
    ventana = "desde el principio" if a.todo else f"ultimos {a.dias} dia(s)"
    print(f"Estado de las plataformas  ---  {ventana}")
    print(f"base: {BASE}")

    salto = db.execute("SELECT * FROM breaker WHERE account='abuse.ch'").fetchone()
    act = activadas()
    for plat in PLATAFORMAS:
        bloque(db, plat, desde, act.get(plat), salto)

    print()
    print("=" * 72)
    print("  Recuerda: un cero en MalwareBazaar NO es un fallo. Solo acepta")
    print("  muestras de menos de 10 dias, y un senuelo captura sobre todo")
    print("  familias veteranas. El unico motivo que deberia preocupar es")
    print("  'rechazo-plataforma'.")
    print()
    print("  Y un PUBLICADO en ThreatFox casi nunca crea una fila a tu nombre:")
    print("  si el IOC ya existia, lo fusiona con el que hay y actualiza su")
    print("  'last_seen', dejando la autoria en quien lo vio primero. El envio")
    print("  ha servido ---confirma que esa infraestructura sigue viva, que es")
    print("  lo que solo puede decir quien la esta viendo--- aunque en el")
    print("  perfil no aparezca nada nuevo. Se comprueba con search_ioc de su")
    print("  API, no con el buscador de la web: mira si el 'last_seen' cuadra")
    print("  con la hora que sale aqui arriba.")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
