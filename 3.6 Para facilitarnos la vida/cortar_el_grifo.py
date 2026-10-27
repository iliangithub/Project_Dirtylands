#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
cortar_el_grifo.py

Apaga (o vuelve a encender) el reporte hacia cada plataforma, sin tener que
abrir el config.ini a mano ni acordarse de como se llama cada seccion.

    sudo ~/cortar_el_grifo.py             elegir que apagar o encender
    sudo ~/cortar_el_grifo.py --estado    solo mirar, no pregunta nada

No para el senuelo ni el reporter: se sigue capturando, recogiendo y
evaluando todo igual, y las muestras se quedan en la cola. Lo unico que se
apaga es la PUBLICACION en la plataforma elegida. Por eso volver a
encenderla no pierde nada de lo de en medio.

abuse.ch va como una sola opcion porque es una sola cuenta: MalwareBazaar,
ThreatFox y URLhaus comparten Auth-Key, y apagar una y dejar las otras dos no
protege de nada.

El fichero se edita LINEA A LINEA y no con configparser: reescribirlo entero
se llevaria por delante todos los comentarios, que en ese fichero son la
documentacion de por que cada umbral vale lo que vale.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
from datetime import datetime

CFG = "/opt/dirtyland/platform-reporter/config.ini"

# Numero -> (etiqueta, secciones del config.ini que hay que tocar)
PLATAFORMAS: dict[str, tuple[str, tuple[str, ...]]] = {
    "1": ("abuse.ch  (MalwareBazaar + ThreatFox + URLhaus)",
          ("malwarebazaar", "threatfox", "urlhaus")),
    "2": ("VirusTotal", ("virustotal",)),
    "3": ("AbuseIPDB", ("abuseipdb",)),
}


def cron_en_live(lineas: list[str] | None = None) -> bool | None:
    """True si el cron publica, False si simula, None si no hay fichero."""
    if lineas is None:
        if not os.path.isfile(CRON):
            return None
        with open(CRON, encoding="utf-8") as fh:
            lineas = fh.readlines()
    for linea in lineas:
        if linea.lstrip().startswith("#"):
            continue
        if _LINEA_LIVE.match(linea):
            return True
    return False


def cambiar_cron(a_live: bool) -> None:
    """Comenta una linea y descomenta la otra. Deja SIEMPRE una sola activa.

    Se edita linea a linea, como el config.ini y por lo mismo: el fichero trae
    comentarios que explican para que es cada cosa.
    """
    with open(CRON, encoding="utf-8") as fh:
        lineas = fh.readlines()
    salida = []
    for linea in lineas:
        cuerpo = linea.rstrip("\n")
        desnuda = cuerpo.lstrip("#").strip()
        if desnuda.startswith("*/15") and "malware-watch.sh" in desnuda:
            es_live = desnuda.endswith("--live")
            activa = (es_live == a_live)
            salida.append(("" if activa else "#") + desnuda + "\n")
        else:
            salida.append(linea)
    tmp = CRON + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.writelines(salida)
    os.chmod(tmp, 0o644)
    os.replace(tmp, CRON)

# El cron manda sobre todo lo demas: si no esta en --live, da igual lo que diga
# el config.ini porque NADA se publica. Por eso aparece arriba del todo y como
# opcion 0: apagar una plataforma con el cron ya en simulacion es no hacer
# nada, y hasta ahora la pantalla no lo decia.
CRON = "/etc/cron.d/dirtyland-reporter"

_LINEA_SIM = re.compile(
    r"^(\s*)(\*/15\s+.*malware-watch\.sh)\s*$")
_LINEA_LIVE = re.compile(
    r"^(\s*)#?\s*(\*/15\s+.*malware-watch\.sh\s+--live)\s*$")

_SECCION = re.compile(r"^\s*\[([^\]]+)\]\s*$")
_ENABLED = re.compile(r"^(\s*enabled\s*=\s*)(\S+)(.*)$", re.IGNORECASE)


def leer(ruta: str) -> list[str]:
    with open(ruta, encoding="utf-8") as fh:
        return fh.readlines()


def estado(lineas: list[str]) -> dict[str, bool]:
    """enabled de cada seccion, tal como esta escrito ahora."""
    actual, salida = None, {}
    for linea in lineas:
        m = _SECCION.match(linea)
        if m:
            actual = m.group(1).strip().lower()
            continue
        if actual:
            m = _ENABLED.match(linea)
            if m:
                salida[actual] = m.group(2).strip().lower() in (
                    "1", "true", "yes", "on")
    return salida


def poner(lineas: list[str], seccion: str, valor: bool) -> list[str]:
    """Reescribe SOLO la linea `enabled` de esa seccion. Nada mas.

    Si la seccion existe pero no tiene la clave, se anade justo debajo de la
    cabecera; asi el comentario que explica la seccion sigue encima.
    """
    salida, dentro, escrito = [], False, False
    for linea in lineas:
        m = _SECCION.match(linea)
        if m:
            if dentro and not escrito:
                # Se acaba la seccion sin haber encontrado la clave.
                salida.append(f"enabled = {'true' if valor else 'false'}\n")
                escrito = True
            dentro = m.group(1).strip().lower() == seccion
            salida.append(linea)
            continue
        if dentro:
            m = _ENABLED.match(linea)
            if m:
                salida.append(f"{m.group(1)}{'true' if valor else 'false'}{m.group(3)}\n")
                escrito = True
                continue
        salida.append(linea)
    if dentro and not escrito:
        salida.append(f"enabled = {'true' if valor else 'false'}\n")
    return salida


def destino(lineas: list[str], secciones: tuple[str, ...]) -> bool:
    """A que estado hay que llevar esta plataforma al conmutarla.

    La regla no es "invierte lo que haya", porque hay TRES estados posibles y
    no dos: encendida, apagada, y a medias. Es:

        alguna encendida  ->  se apagan TODAS
        ninguna encendida ->  se encienden todas

    O sea que un estado a medias se resuelve APAGANDO. Es el lado seguro: si
    alguien dejo una seccion de abuse.ch encendida por error, lo util es dejar
    las tres quietas, no completar el encendido sin que nadie lo haya pedido.

    Aqui hubo un fallo que conviene no repetir: esto devolvia
    `not todas_encendidas`, con lo que un estado a medias contaba como
    "apagado" y conmutarlo lo encendia TODO --- exactamente lo contrario de lo
    que el aviso en pantalla prometia. El texto y el codigo decian cosas
    distintas, y el que manda es el codigo.
    """
    est = estado(lineas)
    return not any(est.get(s, False) for s in secciones)


def pintar(lineas: list[str]) -> None:
    est = estado(lineas)
    hay_partial = False
    live = cron_en_live()

    print("\nCurrent status:")
    # El cron, ARRIBA DEL TODO. Si esta en simulacion, los tres puntos de abajo
    # dan igual: no se publica nada, y una pantalla que enseñara "REPORTING" en
    # verde estaria mintiendo.
    if live is None:
        marca_cron = "\U0001F534 NO CRON FILE  (nothing runs at all)"
    elif live:
        marca_cron = "\U0001F7E2 LIVE  (publishing)"
    else:
        marca_cron = "\U0001F534 SIMULATION  (nothing is published)"
    print(f"  0)  {'cron mode  (' + CRON + ')':<48} {marca_cron}")
    print()

    for num, (etiqueta, secciones) in PLATAFORMAS.items():
        activas = [s for s in secciones if est.get(s, False)]
        if len(activas) == len(secciones) and live:
            marca = "\U0001F7E2 REPORTING"
        elif len(activas) == len(secciones):
            # Encendida en el config, pero el cron no publica. Ni verde ni
            # "stopped": no esta parada, esta amordazada.
            marca = "\U0001F534 on, but muted by cron"
        elif not activas:
            # En minuscula a proposito: se distingue de un vistazo del
            # REPORTING en mayusculas, sin tener que leer la palabra.
            marca = "\U0001F534 stopped"
        else:
            # Solo puede pasar en abuse.ch, y solo si alguien edito el
            # config.ini a mano y se dejo una seccion.
            marca = "\U0001F7E1 PARTIAL (%s on)" % ", ".join(activas)
            hay_partial = True
        print(f"  {num})  {etiqueta:<48} {marca}")

    # El aviso va en pantalla y no solo en un comentario del codigo: quien ve
    # la linea amarilla necesita saber que hacer con ella, y sobre todo que
    # elegirla APAGA. Sin esto, lo natural seria suponer lo contrario --- que
    # completa lo que falta --- y encenderlo todo sin querer.
    # La misma linea de MOTIVO que el resumen diario de Telegram, y con la
    # misma logica, para que las dos pantallas no puedan contradecirse.
    todas = [s for _, secs in PLATAFORMAS.values() for s in secs]
    encendidas = sum(1 for s in todas if est.get(s, False))
    print()
    if live is None:
        print(f"  [REASON: there is no {CRON}: the reporter never runs]")
    elif not live:
        print("  [REASON: cron is in SIMULATION mode: nothing is published]")
    elif encendidas == 0:
        print("  [REASON: cron is fine, everything is simply switched off]")
    elif encendidas < len(todas):
        print("  [REASON: cron is fine, some services are simply off]")

    if hay_partial:
        print()
        print("  \U0001F7E1 PARTIAL means the three abuse.ch sections disagree,")
        print("     which protects nothing: they share one account and one key.")
        print("     Selecting it turns them ALL OFF, never all on.")
    print()


def main() -> int:
    # Los circulos de color necesitan UTF-8, y sudo puede entrar con un locale
    # C en el que Python escribe en ASCII: el print reventaria con
    # UnicodeEncodeError justo cuando mas quieres ver el estado. Ya paso una
    # vez con el vigilante de SSH.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:                                     # noqa: BLE001
        pass

    if os.geteuid() != 0:
        print(f"This edits {CFG}, which is root-only (mode 600).", file=sys.stderr)
        print(f"  sudo {sys.argv[0]}", file=sys.stderr)
        return 1
    if not os.path.isfile(CFG):
        print(f"Config not found: {CFG}", file=sys.stderr)
        return 1

    lineas = leer(CFG)
    pintar(lineas)

    # Mirar sin tocar. Existe como opcion propia y no solo como "entra y dale
    # a Enter": consultar el estado es lo que mas se hace, y no deberia
    # obligar a abrir un menu que puede cambiar cosas.
    if any(a in ("--estado", "--status") for a in sys.argv[1:]):
        return 0

    # Un solo procedimiento: se elige el numero y la plataforma pasa al estado
    # contrario. Antes habia que escribir "on 1" para reencender, o sea un
    # comando distinto para deshacer lo que se acababa de hacer --- y en algo
    # que se usa con prisas, dos formas de decir lo mismo es una de mas.
    print("Select what you want to switch.")
    print("  - 0 is the cron mode: with it in SIMULATION nothing publishes,")
    print("    no matter what the platforms below say")
    print("  - one or more numbers, e.g.  0 1")
    print("  - 🟢 becomes 🔴, and 🔴 becomes 🟢")
    print("  - Enter to quit without changes")
    try:
        respuesta = input("> ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\nNo changes.")
        return 0

    if not respuesta:
        print("No changes.")
        return 0

    numeros = [t for t in re.split(r"[,\s]+", respuesta) if t.isdigit()]
    if not numeros:
        print("Nothing selected. No changes.")
        return 0

    desconocidos = [n for n in numeros if n not in PLATAFORMAS and n != "0"]
    if desconocidos:
        print(f"Unknown option(s): {' '.join(desconocidos)}. No changes.",
              file=sys.stderr)
        return 2

    tocar_cron = "0" in numeros
    if tocar_cron and cron_en_live() is None:
        print(f"There is no {CRON}, so there is no cron mode to switch.",
              file=sys.stderr)
        print("Install it first: see section 3.5.5.3 of the README.",
              file=sys.stderr)
        return 2

    # El destino de cada una se calcula ANTES de tocar nada, y se ensena, para
    # que la confirmacion diga lo que va a pasar de verdad en vez de "vas a
    # cambiar tres cosas". La regla de los tres estados esta en destino().
    plan = [(n, destino(lineas, PLATAFORMAS[n][1]))
            for n in numeros if n in PLATAFORMAS]
    cron_a_live = (not cron_en_live()) if tocar_cron else None

    print()
    if tocar_cron:
        print("  %s the cron" % ("START publishing with" if cron_a_live
                                 else "STOP  publishing, back to SIMULATION for"))
    for n, encender in plan:
        print(f"  {'START' if encender else 'STOP '} reporting to  "
              f"{PLATAFORMAS[n][0]}")

    # Sin distinguir mayusculas, y basta con la inicial. Antes se comparaba
    # contra "YES" exacto y escribir "yes" cancelaba el cambio: quien lo
    # teclea ha entendido perfectamente lo que le piden, y castigarle por la
    # tecla de bloqueo no anade ni una pizca de deliberacion. Solo confunde,
    # porque el script contesta "Cancelled" a alguien que ha dicho que si.
    try:
        if input("\nConfirm? (y/yes): ").strip().lower() not in ("y", "yes"):
            print("Cancelled. Nothing was changed.")
            return 0
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled. Nothing was changed.")
        return 0

    # Copia de seguridad antes de tocar nada. Cuesta nada y este fichero
    # contiene las claves y la lista de bloqueo.
    sello = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    respaldo = f"{CFG}.bak-{sello}"
    shutil.copy2(CFG, respaldo)

    if tocar_cron:
        shutil.copy2(CRON, f"{CRON}.bak-{sello}")
        cambiar_cron(bool(cron_a_live))

    nuevas = lineas
    for n, encender in plan:
        for seccion in PLATAFORMAS[n][1]:
            nuevas = poner(nuevas, seccion, encender)

    tmp = CFG + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.writelines(nuevas)
    os.chmod(tmp, 0o600)
    os.replace(tmp, CFG)

    print(f"\nDone. Backup: {respaldo}")
    pintar(leer(CFG))
    if any(not encender for _, encender in plan):
        print("Nothing is lost: capture and collection carry on, and the")
        print("samples stay queued. Run this again to switch it back.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
