#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
estoy_dentro.py

Calla los avisos del anfitrion mientras TU estas trabajando en la maquina, y
los vuelve a encender cuando sales.

    sudo ~/estoy_dentro.py             encender o apagar la vigilancia
    sudo ~/estoy_dentro.py --estado    solo mirar, no pregunta nada

POR QUE HACE FALTA. La maquina principal no se toca nunca, asi que el canal de
Telegram esta callado durante semanas: ese silencio ES la prueba de que no hay
nadie dentro. Pero en cuanto entras tu, todo lo que haces dispara avisos ---el
login, cada orden que tecleas, cada contenedor que reinicias--- y el movil se
colapsa justo cuando quien lee los avisos eres tu mismo provocandolos.

QUE CALLA Y QUE NO:

  SI  todo lo que pasa por send-alert.sh: el vigilante de SSH, el de ordenes,
      el del cortafuegos y el de Dionaea. O sea la vigilancia del anfitrion.

  NO  el RESUMEN DIARIO, que se manda con "--siempre" a proposito. Si tambien
      se callara, no quedaria nada que te avisara de que la vigilancia sigue
      apagada, y este proyecto ya se llevo ese susto una vez con el cron del
      reporter en simulacion: el parte pintaba de verde lo que estaba muerto.

  NO  se pierde nada. Cada aviso callado se anota en un carrete y el resumen
      diario los cuenta y los ensena. Silenciar no es tirar.

  NO  el chat del SENUELO. Son dos bots y dos conversaciones distintas a
      proposito (apartado 3.4.2.7 del README): las del senuelo son constantes
      en cuanto se expone, y las del anfitrion deben ser rarisimas. Esto calla
      la del anfitrion, que es la que se llena cuando entras tu.

  NO  para el senuelo. Cowrie y Dionaea siguen capturando igual, y el reporter
      sigue publicando. Esto solo afecta a lo que te llega al movil. Para
      parar el senuelo esta ~/boton_del_panico.sh.

EL PLAZO. Por defecto se calla durante un rato y se enciende SOLA. No es
desconfianza: es que el fallo tipico no es olvidarse de apagarla, es
olvidarse de volver a encenderla, y una vigilancia apagada que nadie recuerda
es peor que no tenerla. Se puede pedir silencio sin plazo, pero hay que
escribirlo a mano.
"""

from __future__ import annotations

import os
import sys
import time

SILENCIO = "/opt/dirtyland/monitor/silencio"
CARRETE = "/opt/dirtyland/monitor/silenciadas.log"

# Horas que dura el silencio si no se dice otra cosa. Cuatro da para una
# sesion de trabajo larga sin dejar la maquina a oscuras toda la noche.
HORAS_POR_DEFECTO = 4


def leer() -> dict[str, str]:
    """El fichero de silencio, o {} si no hay."""
    if not os.path.isfile(SILENCIO):
        return {}
    datos = {}
    try:
        with open(SILENCIO, encoding="utf-8") as fh:
            for linea in fh:
                if "=" in linea:
                    clave, valor = linea.split("=", 1)
                    datos[clave.strip()] = valor.strip()
    except OSError:
        return {}
    return datos


def vigente(datos: dict[str, str]) -> bool:
    """True si AHORA MISMO se esta callando.

    La misma regla que aplica send-alert.sh, y a proposito: si las dos
    pantallas usaran criterios distintos, esta diria "apagada" mientras los
    avisos siguen llegando, o al reves. Un plazo vencido no calla nada.
    """
    if not datos:
        return False
    try:
        hasta = int(datos.get("hasta", ""))
    except ValueError:
        return False
    return hasta == 0 or time.time() < hasta


def restante(datos: dict[str, str]) -> str:
    try:
        hasta = int(datos.get("hasta", ""))
    except ValueError:
        return "?"
    if hasta == 0:
        return "sin plazo"
    quedan = int(hasta - time.time())
    if quedan <= 0:
        return "vencido"
    horas, minutos = divmod(quedan // 60, 60)
    return f"{horas}h {minutos:02d}m" if horas else f"{minutos}m"


def callados() -> int:
    """Cuantos avisos se han quedado en el carrete."""
    try:
        with open(CARRETE, encoding="utf-8", errors="replace") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0


def escribir(horas: float | None) -> None:
    """Crea el fichero de silencio. horas=None -> sin plazo."""
    ahora = int(time.time())
    hasta = 0 if horas is None else ahora + int(horas * 3600)
    tmp = SILENCIO + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("# Lo escribe estoy_dentro.py. Lo lee send-alert.sh.\n")
        fh.write("# hasta=0 significa 'hasta que se encienda a mano'.\n")
        fh.write(f"desde={ahora}\n")
        fh.write(f"hasta={hasta}\n")
    os.chmod(tmp, 0o644)
    os.replace(tmp, SILENCIO)


def borrar() -> None:
    try:
        os.remove(SILENCIO)
    except FileNotFoundError:
        pass


def pintar(datos: dict[str, str]) -> None:
    print("\nCurrent status:")
    if vigente(datos):
        marca = f"\U0001F534 SILENCED  ({restante(datos)} left)"
    elif datos:
        # El fichero esta, pero el plazo vencio: la vigilancia YA volvio sola.
        marca = "\U0001F7E2 WATCHING  (the silence expired on its own)"
    else:
        marca = "\U0001F7E2 WATCHING  (alerts reach your phone)"
    print(f"  1)  {'host alerts to Telegram':<44} {marca}")

    n = callados()
    print()
    if vigente(datos):
        print("  [REASON: you switched it off; nothing reaches your phone")
        print("           except the daily digest, which always goes out]")
    elif datos:
        print("  [REASON: it was off, but the deadline passed and it came back")
        print("           on by itself. Nothing to do.]")
    else:
        print("  [REASON: everything is normal. Silence in the channel means")
        print("           nobody is running commands on the machine.]")
    if n:
        print()
        print(f"  \U0001F7E1 {n} alert(s) held back while silenced.")
        print(f"     They are not lost: {CARRETE}")
        print("     The daily digest counts them too.")
    print()


def main() -> int:
    # Los circulos de color necesitan UTF-8, y sudo puede entrar con un locale
    # C en el que Python escribe en ASCII. Mismo motivo que en
    # cortar_el_grifo.py: el print reventaria justo al mirar el estado.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:                                     # noqa: BLE001
        pass

    if os.geteuid() != 0:
        print(f"This writes {SILENCIO}, which belongs to root.", file=sys.stderr)
        print(f"  sudo {sys.argv[0]}", file=sys.stderr)
        return 1

    carpeta = os.path.dirname(SILENCIO)
    if not os.path.isdir(carpeta):
        print(f"{carpeta} does not exist: the host monitoring is not installed.",
              file=sys.stderr)
        print("See section 3.4.2.7 of the README.", file=sys.stderr)
        return 1

    datos = leer()
    pintar(datos)

    if any(a in ("--estado", "--status") for a in sys.argv[1:]):
        return 0

    if vigente(datos):
        print("Turn the alerts back ON? (y/yes): ", end="")
        try:
            if input().strip().lower() not in ("y", "yes"):
                print("Cancelled. Still silenced.")
                return 0
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled. Still silenced.")
            return 0
        borrar()
        print("\n\U0001F7E2 Alerts are back on.")
        n = callados()
        if n:
            print(f"   {n} alert(s) were held back. Read them with:")
            print(f"     sudo cat {CARRETE}")
        return 0

    # No esta silenciado: se ofrece callarlo.
    print("Silence the host alerts while you work?")
    print(f"  - Enter          for {HORAS_POR_DEFECTO} hours (recommended)")
    print("  - a number       that many hours, e.g.  8")
    print("  - forever        no deadline; you MUST turn it back on yourself")
    print("  - n              leave it alone")
    try:
        respuesta = input("> ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\nNo changes.")
        return 0

    if respuesta in ("n", "no"):
        print("No changes.")
        return 0

    if respuesta == "forever":
        horas = None
    elif not respuesta:
        horas = float(HORAS_POR_DEFECTO)
    else:
        try:
            horas = float(respuesta)
        except ValueError:
            print(f"'{respuesta}' is not a number of hours. No changes.",
                  file=sys.stderr)
            return 2
        if horas <= 0:
            print("A silence of zero hours is not a silence. No changes.",
                  file=sys.stderr)
            return 2

    escribir(horas)
    if horas is None:
        print("\n\U0001F534 Silenced with NO deadline.")
        print("   Nothing will turn it back on but you:")
        print(f"     sudo {sys.argv[0]}")
    else:
        print(f"\n\U0001F534 Silenced for {restante(leer())}.")
        print("   It comes back on by itself when the time is up.")
    print("   The daily digest still goes out, and it will say it is off.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
