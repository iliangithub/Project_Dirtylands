#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
test_botones_cowrie.py — el teclado del plugin de Cowrie.

    python3 "TELEGRAM SCRIPTS/tests/test_botones_cowrie.py"

No importa el plugin entero: depende de Twisted, de treq y de los modulos de
Cowrie, que solo existen dentro del contenedor. Lo que se prueba es la logica
del teclado, extraida del fichero real con exec sobre las funciones sueltas,
para que no sea una copia que algun dia diga otra cosa.

Lo que se comprueba es lo unico que puede salir mal aqui de forma silenciosa:

  - que haya un boton por cada IP de la lista, no solo por la primera;
  - que pulsar uno NO borre los demas, que es lo que hacia antes;
  - que las IP propias no lleven boton, pase lo que pase;
  - y que callback_data quepa en los 64 bytes de Telegram tambien con IPv6.
"""

from __future__ import annotations

import ipaddress
import re
import sys
from collections import OrderedDict
from pathlib import Path

FUENTE = Path(__file__).resolve().parent.parent / "COWRIE" / "telegram_alert_cowrie.py"

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


# --------------------------------------------------------------------------
# Se sacan los metodos del fichero de verdad y se cuelgan de un objeto minimo.
# Asi la prueba corre contra el codigo que se despliega, no contra una copia.
FUENTES = FUENTE.read_text(encoding="utf-8")


def extraer(nombre: str) -> str:
    patron = re.compile(r"^    def %s\(.*?(?=^    def |\Z)" % re.escape(nombre),
                        re.S | re.M)
    m = patron.search(FUENTES)
    if not m:
        sys.exit("no se encontro el metodo %s en %s" % (nombre, FUENTE))
    return m.group(0)


PROPIAS = {"10.0.0.5", "127.0.0.1", "198.51.100.146"}

ns: dict = {
    "ipaddress": ipaddress,
    "OrderedDict": OrderedDict,
    "BAN_BUTTON": True,
    "is_whitelisted": lambda ip: ip in PROPIAS,
}

cuerpo = "class Falso:\n"
cuerpo += '    ETIQUETA_BLOQUEAR = "\\U0001f6ab Block IP %s"\n'
cuerpo += "    MAX_MENSAJES_CON_BOTON = 200\n"
# Las peticiones de baneo en vuelo. El filtro de botones las mira: un aviso
# sobre una IP que se esta baneando ahora mismo no debe ofrecer un boton para
# banearla.
cuerpo += "    _pending_bans: dict = {}\n"
for nombre in ("_ips_con_boton", "_pintar_teclado", "_estado_inicial",
               "_keyboard", "_registrar_botones"):
    cuerpo += "\n" + extraer(nombre)
exec(compile(cuerpo, str(FUENTE), "exec"), ns)


class Memoria:
    banned: set = set()


bot = ns["Falso"]()
bot.memory = Memoria()
bot._botones = OrderedDict()


def etiquetas(teclado):
    return [fila[0]["text"] for fila in (teclado or {}).get("inline_keyboard", [])]


def datos(teclado):
    return [fila[0]["callback_data"] for fila in (teclado or {}).get("inline_keyboard", [])]


# --------------------------------------------------------------------------
print("\nUn boton por IP")
IPS = ["195.178.110.227", "176.53.159.196"]
teclado = bot._keyboard(IPS)
comprueba("dos IP dan dos botones", 2, len(etiquetas(teclado)))
comprueba("cada fila lleva su IP",
          ["\U0001f6ab Block IP 195.178.110.227",
           "\U0001f6ab Block IP 176.53.159.196"], etiquetas(teclado))
comprueba("y cada callback apunta a la suya",
          ["ban:195.178.110.227", "ban:176.53.159.196"], datos(teclado))
comprueba("una sola IP sigue funcionando igual", 1,
          len(etiquetas(bot._keyboard("195.178.110.227"))))
comprueba("una cadena suelta vale, no solo una lista",
          ["ban:195.178.110.227"], datos(bot._keyboard("195.178.110.227")))

print("\nLo que NO lleva boton")
comprueba("una IP nuestra no lleva boton", None, bot._keyboard("198.51.100.146"))
comprueba("ni el loopback", None, bot._keyboard("127.0.0.1"))
comprueba("una IP invalida se ignora", None, bot._keyboard("no-soy-una-ip"))
comprueba("de una lista mixta solo salen las baneables",
          ["ban:195.178.110.227"],
          datos(bot._keyboard(["198.51.100.146", "195.178.110.227", "10.0.0.5"])))
comprueba("las repetidas no duplican boton", 1,
          len(etiquetas(bot._keyboard(["1.2.3.4", "1.2.3.4"]))))
bot.memory.banned = {"195.178.110.227"}
comprueba("una ya baneada tampoco",
          ["ban:176.53.159.196"], datos(bot._keyboard(IPS)))
bot.memory.banned = set()

# NI UNA QUE SE ESTA BANEANDO AHORA MISMO. El aviso del BANEO AUTOMATICO
# llegaba con un boton de "Block IP" debajo, para la IP que acababa de
# banearse sola: el filtro miraba las baneadas, pero el aviso se encolaba
# ANTES de pedir el baneo, asi que en ese momento la IP no constaba en
# ninguna parte. Invita a pulsar algo que no hace falta, y quien lo pulsara
# se llevaba un error porque la regla ya estaba puesta.
bot._pending_bans = {"195.178.110.227": ({}, 0)}
comprueba("ni una que se esta baneando en este momento",
          ["ban:176.53.159.196"], datos(bot._keyboard(IPS)))
bot._pending_bans = {}

print("\nPulsar uno NO borra los demas")
# El fallo que arregla todo esto: _update_button mandaba un teclado nuevo con
# UN solo boton, asi que al pulsar el de la primera IP desaparecia el de la
# segunda sin haberla baneado nadie. Un boton que se va da a entender que ya
# esta hecho, que es peor que no tenerlo.
bot._registrar_botones(4242, IPS)
estado = bot._botones[4242]
comprueba("el mensaje queda registrado con sus dos IP", 2, len(estado))

estado["195.178.110.227"] = ("⏳ Baneando 195.178.110.227...", False)
tras = bot._pintar_teclado(estado)
comprueba("siguen siendo dos filas", 2, len(etiquetas(tras)))
comprueba("la pulsada cambia de texto",
          "⏳ Baneando 195.178.110.227...", etiquetas(tras)[0])
comprueba("y deja de ser pulsable", "noop", datos(tras)[0])
comprueba("la otra sigue intacta y pulsable",
          "ban:176.53.159.196", datos(tras)[1])
comprueba("con su etiqueta original",
          "\U0001f6ab Block IP 176.53.159.196", etiquetas(tras)[1])

print("\nLimites de Telegram")
IPV6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
comprueba("la IPv6 mas larga cabe en callback_data (64 bytes)", True,
          len(("ban:" + IPV6).encode("utf-8")) <= 64)
print("        (ban:IPv6 = %d bytes)" % len(("ban:" + IPV6).encode("utf-8")))
comprueba("y produce su boton", 1, len(etiquetas(bot._keyboard(IPV6))))
comprueba("una fila por boton, nunca dos por fila", True,
          all(len(f) == 1 for f in bot._keyboard(IPS)["inline_keyboard"]))

print("\nLa memoria de mensajes no crece sin fin")
for n in range(300):
    bot._registrar_botones(10000 + n, ["203.0.113.%d" % (n % 250 + 1)])
comprueba("se guardan como mucho MAX_MENSAJES_CON_BOTON",
          True, len(bot._botones) <= ns["Falso"].MAX_MENSAJES_CON_BOTON)
comprueba("y se tiran los mas viejos, no los recientes",
          True, 10299 in bot._botones and 10000 not in bot._botones)

# --------------------------------------------------------------- transporte
# Ahora que el 23 esta abierto, un aviso tiene que decir por donde entraron.
# Cowrie marca "protocol" en TODOS los eventos de una sesion (lo fija EventLog
# al crearla), asi que no hay que deducirlo del puerto.
print("\nPor donde entro: SSH o Telnet")
# Las dos tablas se leen del fichero que se despliega, no de una copia.
_tablas: dict = {}
for _nombre in ("VIA_PROTOCOLO", "NOMBRE_PROTOCOLO"):
    _m = re.search(r"^%s = \{.*?^\}" % _nombre, FUENTES, re.S | re.M)
    if not _m:
        sys.exit("no se encontro %s en %s" % (_nombre, FUENTE))
    exec(compile(_m.group(0), str(FUENTE), "exec"), _tablas)

comprueba("telnet se nombra en la cabecera del aviso",
          "vía Telnet", _tablas["VIA_PROTOCOLO"]["telnet"])
comprueba("y ssh tambien",
          "vía SSH", _tablas["VIA_PROTOCOLO"]["ssh"])

# LA CABECERA NO LLEVA EL "sensor" DE COWRIE. Por defecto es el hostname del
# CONTENEDOR ---su id de Docker--- asi que cambiaba en cada --force-recreate y,
# habiendo un solo senuelo, no distinguia entre nada. Salia como
# "[Cowrie 9ee5ca58e312] vía Telnet", con aspecto de dato y sin serlo.
_cabecera = re.search(r"def _header\(self, event\).*?return msgtxt",
                      FUENTES, re.S)
comprueba("se encuentra la cabecera", True, _cabecera is not None)
if _cabecera:
    _src = _cabecera.group(0)
    # Se busca la LECTURA del campo, no la palabra: el comentario que explica
    # por que se quito la menciona, y comprobar prosa en vez de codigo es como
    # se escriben pruebas que fallan solas.
    comprueba("la cabecera ya no lee el sensor", False,
              'event.get("sensor")' in _src)
    comprueba("y el transporte va DENTRO del corchete", True,
              '"<strong>[Cowrie" + (" " + via if via else "") + "]</strong>"'
              in _src)
    comprueba("con una linea en blanco antes de los datos", True,
              '"\\n\\nEvent: "' in _src)
comprueba("un transporte desconocido no inventa etiqueta",
          None, _tablas["VIA_PROTOCOLO"].get("gopher"))
comprueba("en el resumen va el nombre a secas, que ahi 'via X: 3' se lee mal",
          "Telnet", _tablas["NOMBRE_PROTOCOLO"]["telnet"])
comprueba("las dos tablas cubren los mismos transportes",
          set(_tablas["VIA_PROTOCOLO"]), set(_tablas["NOMBRE_PROTOCOLO"]))

print("\n== el baneo automatico solo dispara donde debe ==")
# No se importa el plugin (arrastra Twisted y treq): se LEE la condicion tal
# como esta escrita en el fichero y se evalua. Asi la prueba se rompe si
# alguien la cambia, en vez de comprobar una copia que ya no se parece.
_fuente = (Path(__file__).resolve().parent.parent
           / "COWRIE" / "telegram_alert_cowrie.py").read_text(encoding="utf-8")
_m = re.search(r"if \(AUTOBAN_REPETICIONES\n(.*?)\):", _fuente, re.S)
comprueba("la condicion del autoban sigue en el plugin", True, _m is not None)

if _m:
    _cond = " ".join(l.strip() for l in
                     ("AUTOBAN_REPETICIONES " + _m.group(1)).split("\n"))
    _PROPIAS = {"192.0.2.190", "192.0.2.217", "198.51.100.146"}

    def _dispara(times, ip, baneadas=frozenset(), vuelo=frozenset(), tope=200):
        entorno = {
            "AUTOBAN_REPETICIONES": tope, "times": times, "src_ip": ip,
            "is_whitelisted": lambda x: x in _PROPIAS,
            "self": type("S", (), {
                "memory": type("M", (), {"banned": baneadas})(),
                "_pending_bans": vuelo})(),
        }
        return bool(eval(_cond, {}, entorno))

    comprueba("banea a la que repite 250 veces sin traer nada nuevo",
              True, _dispara(250, "45.9.1.7"))
    comprueba("no banea todavia a las 199", False, _dispara(199, "45.9.1.7"))
    comprueba("NUNCA banea una IP nuestra, por muchas que lleve",
              False, _dispara(9999, "192.0.2.190"))
    comprueba("no vuelve a banear una que ya lo esta",
              False, _dispara(9999, "45.9.1.7", baneadas={"45.9.1.7"}))
    comprueba("ni pide otro si ya hay uno suyo en vuelo",
              False, _dispara(9999, "45.9.1.7", vuelo={"45.9.1.7"}))
    comprueba("un tope de 0 lo desactiva entero",
              False, _dispara(9999, "45.9.1.7", tope=0))

print("\n-------------------------------------")
print("ok: %d   fallos: %d" % (OK, MAL))
sys.exit(1 if MAL else 0)
