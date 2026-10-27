#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
auditd-watch.py --- avisa por Telegram de CADA programa que se ejecuta.

    /opt/dirtyland/monitor/auditd-watch.py                  sigue el log y avisa
    /opt/dirtyland/monitor/auditd-watch.py --test 50        ensaya con lo ultimo
    /opt/dirtyland/monitor/auditd-watch.py --test 50 --seco  ...sin mandar nada

POR QUE EXISTE, si ya esta registro-comandos.sh. Porque aquel solo ve lo que
se teclea en un bash: no ve un `sh`, ni un `python -c`, ni lo que lance un
script, ni un binario que alguien suba y ejecute. Se apoya en PROMPT_COMMAND,
y quien tenga shell puede quitarlo con `unset PROMPT_COMMAND`.

Esto mira el nivel de abajo: la llamada al sistema `execve`. Ahi no hay forma
de esconderse, porque para ejecutar algo hay que pasar por ella.

LOS DOS SE QUEDAN, y no es redundancia: cada uno ve lo que el otro no.

    registro-comandos.sh   la LINEA tal como se escribio, con sus comillas y
                           su tuberia entera, y los builtins ---"cd",
                           "export", "history -c"--- que no ejecutan nada y
                           por tanto no generan ningun execve.
    esto                   TODO lo que se ejecuta, venga de donde venga, en
                           cualquier interprete y por cualquier via.

Una tuberia se ve aqui como tres programas distintos y alli como una sola
linea. Las dos lecturas hacen falta.

QUIEN SE FILTRA Y COMO. La regla de auditd lleva "auid>=1000". El `auid` es
el usuario que se AUTENTICO, se fija al hacer login y NO SE PUEDE CAMBIAR
DESPUES: ni con sudo, ni con su, ni entrando en otro interprete. Se hereda por
todos los procesos hijos. Eso hace dos cosas a la vez:

  - captura todo lo que hace una persona, incluido lo que hace despues de
    "sudo su" o "su root", que es justo el punto ciego que tenia el otro
    registro;
  - y deja fuera lo que no es una persona: cron, systemd, y ---esto importa
    mucho--- TODO lo que ocurre dentro de los contenedores, porque esos
    procesos no vienen de un login y no tienen auid. Sin ese filtro llegaria
    por duplicado cada orden de cada atacante de Cowrie.

EL FORMATO NO SE ADIVINO: esta escrito contra una salida real de auditd 4.0.2
de esta misma maquina, guardada en tests/muestras/audit-real.log. Tres cosas
que no se habrian acertado leyendo la documentacion:

  - Los campos interpretados se pegan al anterior SIN ESPACIO:
    `key="dirtyland-exec"ARCH=x86_64`. Partir por espacios da tokens rotos.
  - Los argumentos vienen en HEXADECIMAL cuando llevan caracteres especiales:
    `a2=696D706F7274...` es `import os; os.system('whoami')`.
  - Un argumento muy largo se parte en varios campos `aN[0]`, `aN[1]`...
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time

AUDIT_LOG = os.environ.get("AUDIT_LOG", "/var/log/audit/audit.log")
ALERTA = os.environ.get("ALERTA", "/opt/dirtyland/monitor/send-alert.sh")

# QUIEN AVISA Y DE QUE MAQUINA, en la primera linea. Por este mismo chat
# llegan los avisos de los dos senuelos, y un aviso de ordenes ejecutadas se
# lee MUY distinto segun de donde venga: dentro de Cowrie es lo normal ---para
# eso esta---, y en el anfitrion es que hay alguien dentro de la maquina de
# verdad. Confundirlos es confundir "todo va bien" con "esto es grave".
SERVICIO = os.environ.get("AUDIT_SERVICIO", "dirtyland-auditwatch")
MAQUINA = os.environ.get("MAQUINA", "Maquina VPS principal")

# Cuanto se espera a que se calme la cosa antes de mandar. Una orden tuya
# genera varios execve en decimas de segundo; mandarlos de uno en uno seria
# una notificacion por cada trozo de una tuberia.
VENTANA = float(os.environ.get("AUDIT_VENTANA", "20"))

# Tope por mensaje. Un "apt install" son cientos de execve, y un aviso de
# cientos de lineas no se lee: se ignora. Se recorta diciendo cuantos faltan.
MAX_LINEAS = int(os.environ.get("AUDIT_MAX_LINEAS", "40"))

# Y un tope de espera. Con solo la ventana de silencio, mientras alguien siga
# tecleando no sale nada: el aviso llega cuando para, que puede ser mucho
# despues. Y el caso que importa ---alguien trabajando dentro de la maquina---
# es justo el que no para. Pasado esto se manda lo acumulado aunque siga
# habiendo actividad.
ESPERA_MAX = float(os.environ.get("AUDIT_ESPERA_MAX", "120"))

# Por donde iba la ultima vez. Sin esto, al arrancar se saltaba al final del
# fichero y se perdia TODO lo ocurrido mientras el servicio estuvo parado,
# para siempre y sin dejar rastro. Es el mismo fallo que tenia el vigilante
# de ordenes con su "-n 0", y se vio el 2026-08-29: al reiniciarlo, las dos
# ordenes siguientes no llegaron nunca ---estaban en el registro, pero nadie
# las leyo---. Un vigilante que pierde lo que vigila justo cuando se le
# reinicia es peor que no tenerlo, porque uno cree que lo tiene.
POSICION = os.environ.get("AUDIT_POSICION",
                          "/opt/dirtyland/monitor/auditwatch.pos")

# Ruido conocido que no aporta nada. NO se filtra por comodidad: son cosas que
# NO ha pedido nadie ---las lanza el sistema por su cuenta al autenticar o al
# abrir un shell--- o son nuestras propias tuberias vistas desde fuera.
# Cualquier otra cosa pasa.
RUIDO = {
    "/usr/sbin/unix_chkpwd",    # PAM comprobando la contrasena en cada sudo
    "/usr/bin/locale",          # bash al arrancar
    "/usr/bin/dircolors",       # bash al arrancar
}

# Lo NUESTRO no se avisa a si mismo. Sin esto pasaban dos cosas, las dos
# malas:
#
#   - Un bucle: el vigilante manda el aviso con send-alert.sh, eso ejecuta
#     curl, curl queda auditado con el TEXTO DEL AVISO entero como argumento,
#     y el aviso siguiente lo citaba dentro. Cada vuelta mas grande.
#   - Y peor: el 2026-08-29 el TOKEN DEL BOT acabo dentro de un aviso, porque
#     iba en la linea de ordenes de curl. Hubo que revocarlo.
#
# Lo de curl ya esta arreglado en su origen ---el token va por la entrada
# estandar---, pero esto se queda: avisar de nuestro propio envio no aporta
# nada y es justo lo que arrastra secretos.
NUESTRO = ("send-alert.sh", "api.telegram.org", "dirtyland-cmd")

# CENSURA, como segunda linea de defensa. Lo de arriba tapa lo que sabemos que
# lleva secretos; esto tapa lo que no sabemos. Un registro de ejecuciones
# recoge lo que alguien teclea, y ahi acaban claves tarde o temprano ---un
# curl con su cabecera de autorizacion, un mysql -p, un token pegado a mano---
# y de aqui sale derecho a un chat.
CENSURA = [
    (re.compile(r"bot\d{6,}:[A-Za-z0-9_-]{20,}"), "bot<CENSURADO>"),
    (re.compile(r"(?i)\b(authorization|bearer)\s*:?\s*\S+"), r"\1 <CENSURADO>"),
    (re.compile(r"(?i)\b(api[_-]?key|token|passwd|password|secret)"
                r"\s*[=:]\s*\S+"), r"\1=<CENSURADO>"),
    # El -p pegado a la contrasena, PERO SOLO en los clientes de base de
    # datos, que es donde ese patron significa eso. La primera version tapaba
    # cualquier "-p" seguido de algo y se comia el "arts" de "run-parts":
    # salia "run-p<CENSURADO> --list ...". Censurar de mas oculta justo lo que
    # se venia a ver, asi que se prefiere quedarse corto y explicarlo.
    (re.compile(r"(?i)\b(mysql|mysqldump|mariadb|psql)\b([^\n]*?)\s-p\S+"),
     r"\1\2 -p<CENSURADO>"),
]


def censurar(texto: str) -> str:
    for patron, con in CENSURA:
        texto = patron.sub(con, texto)
    return texto


# Cuanto tiene que tardar un programa en aparecer para que cuente como una
# ACCION NUEVA y no como parte de la anterior. Ver plegar().
DENTRO_DE = float(os.environ.get("AUDIT_DENTRO_DE", "2"))


def plegar(evs: list[dict]) -> list[dict]:
    """Deja las ordenes que tecleo una persona y pliega sus tripas.

    EL PROBLEMA. auditd ensena CADA execve, y eso incluye lo que un programa
    lanza por dentro. Un solo "augenrules --load" son trece: el sh, un mktemp,
    un awk de doce lineas, un ls, un grep, cuatro cat, un cmp, un rm... Con la
    salida real del 2026-08-29, SEIS ordenes tecleadas salian como 32 lineas y
    el aviso era ilegible.

    COMO SE DISTINGUE. Cada registro trae pid y ppid, asi que se sabe quien
    lanzo a quien. Pero el arbol por si solo no basta, y este es el matiz que
    importa: si se plegara todo descendiente, un "sudo su" se llevaria por
    delante TODO lo que se teclee luego dentro del shell de root ---que es
    justo lo que mas interesa ver---.

    Asi que se mira tambien el TIEMPO. Las tripas de un programa se lanzan en
    el mismo instante que el; una persona tarda segundos en escribir la
    siguiente orden. Un hijo que aparece dentro de DENTRO_DE segundos de su
    padre es parte de aquella orden; uno que aparece despues es una accion
    nueva y se ensena.

    Es una heuristica, no una certeza, y por eso el umbral se puede mover con
    AUDIT_DENTRO_DE. Lo que NO hace es esconder nada sin decirlo: cada orden
    lleva cuantos programas se plegaron dentro.
    """
    por_pid = {e["pid"]: e for e in evs if e.get("pid")}
    raiz_de: dict[str, str] = {}
    salida = []
    for ev in evs:
        padre = por_pid.get(ev.get("ppid") or "")

        # EL ARBOL TIENE UN HUECO, y hay que taparlo: sudo bifurca un proceso
        # intermedio que NO ejecuta nada, y como aqui solo se ven los execve,
        # ese proceso es invisible. El hijo aparece con un ppid que no hemos
        # visto nunca. En la salida real del 2026-08-29, "sudo tail" tenia
        # pid 432314 y el "tail" de dentro ppid 432316.
        #
        # Se reconoce por el texto: si lo anterior fue "sudo X" y esto es
        # exactamente X, es lo mismo visto desde dentro.
        if padre is None and salida:
            anterior = salida[-1]
            if (anterior["orden"].startswith("sudo ")
                    and ev["orden"] == anterior["orden"][5:]
                    and (ev["marca"] - anterior["marca"]) <= DENTRO_DE):
                padre = anterior

        if padre is not None and (ev["marca"] - padre["marca"]) <= DENTRO_DE:
            # Cuelga de la misma orden que su padre.
            raiz = raiz_de.get(padre.get("pid", ""), padre.get("pid", ""))
            if ev.get("pid"):
                raiz_de[ev["pid"]] = raiz
            cabeza = por_pid.get(raiz, padre)
            cabeza["dentro"] = cabeza.get("dentro", 0) + 1
            continue
        ev["dentro"] = ev.get("dentro", 0)
        salida.append(ev)
    return salida


def _una_linea(texto: str, tope: int = 160) -> str:
    """Todo en una linea y sin espacios de sobra.

    Un argumento puede traer un guion de awk de doce lineas ---paso--- y eso
    revienta la lectura del aviso: el mensaje se vuelve un muro y no se
    distingue una orden de la siguiente.
    """
    texto = " ".join(texto.split())
    return texto if len(texto) <= tope else texto[:tope] + "…"

_EVENTO = re.compile(r"^type=(\w+) msg=audit\(([\d.]+):(\d+)\):\s*(.*)$")


def _campo(texto: str, nombre: str) -> str:
    """El valor de `nombre=...`, con o sin comillas.

    Se ancla el principio con (?:^|\\s) para no cazar "euid" al buscar "uid",
    y el final con (?=\\s|$|") por lo de los campos pegados sin espacio.
    """
    m = re.search(r'(?:^|\s)%s="([^"]*)"' % nombre, texto)
    if m:
        return m.group(1)
    m = re.search(r'(?:^|\s)%s=([^\s"]+)' % nombre, texto)
    return m.group(1) if m else ""


def _dehex(valor: str) -> str:
    """Un argumento de auditd: entre comillas, o en hexadecimal."""
    if valor.startswith('"') and valor.endswith('"'):
        return valor[1:-1]
    try:
        return bytes.fromhex(valor).decode("utf-8", "replace")
    except ValueError:
        return valor


def argumentos(texto: str) -> str:
    """La orden reconstruida a partir de a0, a1, ... del registro EXECVE.

    Los argumentos muy largos vienen partidos en aN[0], aN[1]..., asi que se
    juntan por su numero antes de unirlos. Sin esto, una orden larga saldria
    troceada y en desorden.
    """
    partes: dict[int, dict[int, str]] = {}
    for indice, trozo, valor in re.findall(
            r'\ba(\d+)(?:\[(\d+)\])?=("(?:[^"]*)"|\S+)', texto):
        n = int(indice)
        partes.setdefault(n, {})[int(trozo) if trozo else 0] = valor

    salida = []
    for n in sorted(partes):
        trozos = partes[n]
        if len(trozos) == 1 and 0 in trozos:
            salida.append(_dehex(trozos[0]))
        else:
            # Partido: se concatena EN CRUDO y se descifra al final, porque
            # cada trozo puede cortar un caracter por la mitad.
            crudo = "".join(trozos[i] for i in sorted(trozos))
            salida.append(_dehex(crudo))
    return " ".join(salida)


def eventos(lineas) -> list[dict]:
    """Agrupa las lineas por evento y devuelve solo los execve que interesan.

    auditd escribe un evento en varias lineas ---SYSCALL, EXECVE, CWD, PATH,
    PROCTITLE--- unidas por el "(marca:serie)" de su cabecera, y NO siempre
    seguidas: entre medias puede haber lineas de otro evento.
    """
    por_serie: dict[str, dict] = {}
    orden: list[str] = []
    for linea in lineas:
        m = _EVENTO.match(linea.strip())
        if not m:
            continue
        tipo, marca, serie, resto = m.groups()
        if serie not in por_serie:
            por_serie[serie] = {"marca": float(marca)}
            orden.append(serie)
        ev = por_serie[serie]
        if tipo == "SYSCALL":
            ev["quien"] = _campo(resto, "AUID") or _campo(resto, "auid")
            ev["como"] = _campo(resto, "UID") or _campo(resto, "uid")
            ev["tty"] = _campo(resto, "tty")
            ev["ses"] = _campo(resto, "ses")
            ev["exe"] = _campo(resto, "exe")
            ev["pid"] = _campo(resto, "pid")
            ev["ppid"] = _campo(resto, "ppid")
            ev["clave"] = _campo(resto, "key")
            ev["exito"] = _campo(resto, "success")
        elif tipo == "EXECVE":
            ev["orden"] = argumentos(resto)
        elif tipo == "CWD":
            ev["cwd"] = _campo(resto, "cwd")

    salida = []
    for serie in orden:
        ev = por_serie[serie]
        # Sin SYSCALL no se sabe quien ni desde donde, y sin EXECVE no hay
        # orden que ensenar: en los dos casos no es un evento nuestro.
        if "exe" not in ev or "orden" not in ev:
            continue
        if ev.get("exe") in RUIDO:
            continue
        if any(x in ev["orden"] for x in NUESTRO):
            continue
        ev["serie"] = serie
        salida.append(ev)
    return salida


# --------------------------------------------------------------------------
def _esc(t: str) -> str:
    return (t or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def formatear(evs: list[dict]) -> str:
    """El mensaje de Telegram.

    LA FORMA IMPORTA AQUI MAS DE LO NORMAL, porque esto se lee en un movil y
    de un vistazo. La primera version agrupaba con una cabecera por cada
    cambio de usuario o terminal, y salia ilegible: un `sudo X` genera DOS
    eventos ---el sudo en tu terminal y la orden ya como root en otra--- asi
    que la cabecera cambiaba en cada linea y el aviso era mas cabeceras que
    ordenes.

    Ahora se usa la convencion de toda la vida, que se entiende sin explicar:

        $  lo ejecuto tu usuario
        #  acabo corriendo como root

    Y el `sudo X` seguido de su propio `X` como root se cuenta UNA vez: son la
    misma accion vista dos veces, no dos cosas que hayan pasado.
    """
    lineas = []
    usuarios, ttys = [], []
    for ev in plegar(evs):
        orden = _una_linea(censurar(ev["orden"]))

        if ev.get("quien") and ev["quien"] not in usuarios:
            usuarios.append(ev["quien"])
        if ev.get("tty") and ev["tty"] not in ttys:
            ttys.append(ev["tty"])

        # LA MARCA VA FUERA DEL <code>, y no es un detalle de estilo: ese
        # bloque esta para copiar y pegar la orden, y con la marca dentro se
        # copia tambien la marca. Fuera, el bloque lleva la orden y nada mas.
        #
        # Se ponen las DOS, "$" y "#", y en negrita: con solo el "#" hay que
        # deducir que lo que no lo lleva es del usuario, y una lista donde
        # unas lineas empiezan con marca y otras no se lee peor que una donde
        # todas empiezan igual.
        marca = "<b>$</b> "
        if ev.get("como") == "root" and ev.get("quien") != "root":
            marca = "<b>#</b> "
        # Cuantos programas lanzo por dentro. No se esconde nada en silencio:
        # si una orden movio doce cosas, ahi lo dice.
        dentro = ""
        if ev.get("dentro"):
            dentro = "  <i>(+%d)</i>" % ev["dentro"]
        lineas.append("%s<code>%s</code>%s" % (marca, _esc(orden), dentro))

    if not lineas:
        return ""

    # Todo el encabezado en negrita y separado del cuerpo: es lo unico que se
    # lee en la notificacion del movil sin abrirla.
    cab = "<b>[%s] %s</b>\n<b>\U0001F6A8 Esto NO son los senuelos \U0001F6A8</b>" % (
        _esc(SERVICIO), _esc(MAQUINA))
    cab += "\n<b>%d %s ---  %s desde %s</b>" % (
        len(lineas), "orden" if len(lineas) == 1 else "ordenes",
        _esc(", ".join(usuarios) or "?"), _esc(", ".join(ttys) or "?"))
    pistas = []
    if any(l.startswith("<b>#</b>") for l in lineas):
        pistas.append("<b>$</b> tu usuario   <b>#</b> como root")
    # "programas que lanzo por dentro" no se entendio a la primera, y si hay
    # que preguntar que significa una leyenda es que la leyenda esta mal.
    if any("(+" in l for l in lineas):
        pistas.append("<b>(+n)</b> = esa orden lanzo n programas mas por dentro")
    if pistas:
        cab += "\n<i>%s</i>" % "   ---   ".join(pistas)

    cuerpo = lineas[:MAX_LINEAS]
    if len(lineas) > MAX_LINEAS:
        cuerpo.append("\n… y %d mas. Estan todas en el registro de auditoria; "
                      "el aviso se corta aqui para no perder mensajes por "
                      "exceso de envios." % (len(lineas) - MAX_LINEAS))
    return cab + "\n\n" + "\n".join(cuerpo)


def avisar(texto: str) -> None:
    if not os.path.exists(ALERTA):
        print(texto)
        return
    subprocess.run([ALERTA, texto], timeout=60, check=False)


# --------------------------------------------------------------------------
def _leer_posicion() -> tuple[int, int] | None:
    """(inodo, byte) donde se quedo la vez anterior, o None."""
    try:
        with open(POSICION) as fh:
            ino, pos = fh.read().split()
        return int(ino), int(pos)
    except (OSError, ValueError):
        return None


def _guardar_posicion(inodo: int, byte: int) -> None:
    try:
        tmp = POSICION + ".tmp"
        with open(tmp, "w") as fh:
            fh.write("%d %d\n" % (inodo, byte))
        os.replace(tmp, POSICION)      # de una pieza: nunca a medias
    except OSError as exc:
        _AVISADO.setdefault("pos", 0)
        if not _AVISADO["pos"]:
            _AVISADO["pos"] = 1
            print("no se pudo guardar la posicion en %s: %s" % (POSICION, exc),
                  file=sys.stderr)


_AVISADO: dict[str, int] = {}


def seguir(ruta: str):
    """Como "tail -F": sigue el fichero y lo reabre si lo rotan.

    auditd rota su log al llegar al tope, asi que un descriptor abierto se
    queda apuntando al fichero viejo y el vigilante se calla para siempre
    sin dar ningun error. Se comprueba el inodo.

    Y RETOMA DONDE SE QUEDO. Antes saltaba al final al arrancar, asi que todo
    lo ocurrido mientras el servicio estuvo parado se perdia. Si el fichero es
    el mismo de la ultima vez y no ha menguado, se sigue desde ahi; si es otro
    ---lo rotaron--- se empieza por el principio del nuevo, que es lo que
    todavia no se ha leido.
    """
    fh = None
    inodo = None
    while True:
        try:
            if fh is None:
                fh = open(ruta, "r", errors="replace")
                inodo = os.fstat(fh.fileno()).st_ino
                anterior = _leer_posicion()
                if anterior and anterior[0] == inodo:
                    tam = os.fstat(fh.fileno()).st_size
                    # SI HA MENGUADO, lo han vaciado, y entonces todo lo que
                    # hay dentro es nuevo: se empieza por el principio. La
                    # primera version ponia aqui un min() ---o sea, saltaba al
                    # final del fichero recien vaciado--- y se perdia todo lo
                    # escrito despues. El comentario decia una cosa y el
                    # codigo hacia la contraria; lo caza la prueba del vaciado.
                    fh.seek(0 if anterior[1] > tam else anterior[1])
                elif anterior:
                    fh.seek(0)          # es otro fichero: se lee entero
                else:
                    fh.seek(0, os.SEEK_END)   # primera vez
                # SE APUNTA YA, sin esperar a leer una linea. Si no, un
                # arranque en frio seguido de un reinicio vuelve a saltar al
                # final y se pierde todo lo de en medio: o sea, el arreglo no
                # arreglaba el primer reinicio, que es justo cuando paso.
                _guardar_posicion(inodo, fh.tell())
            linea = fh.readline()
            if linea:
                yield linea
                _guardar_posicion(inodo, fh.tell())
                continue
            try:
                if os.stat(ruta).st_ino != inodo:
                    fh.close()
                    fh = None
                    continue
            except OSError:
                pass
        except OSError:
            if fh:
                fh.close()
            fh = None
        yield None


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--test", type=int, metavar="N",
                   help="no sigue el log: mira las ultimas N lineas y sale")
    # Sin esto, la unica forma de ver como queda un aviso era mandandoselo al
    # movil. Medir el volumen ---que es justo para lo que sirve --test--- no
    # deberia costar una notificacion.
    p.add_argument("--seco", action="store_true",
                   help="lo escribe por pantalla en vez de enviarlo")
    a = p.parse_args()

    if a.test:
        with open(AUDIT_LOG, errors="replace") as fh:
            lineas = fh.readlines()[-a.test:]
        evs = eventos(lineas)
        if not evs:
            print("sin ejecuciones que avisar en esas %d lineas" % a.test)
            return 0
        if a.seco:
            print(formatear(evs))
        else:
            avisar(formatear(evs))
            print("enviado: %d programas (con --seco se ve aqui sin mandarlo)"
                  % len(evs))
        return 0

    pendientes: list[str] = []
    ultimo = 0.0
    primero = 0.0
    for linea in seguir(AUDIT_LOG):
        if linea is not None:
            if not pendientes:
                primero = time.time()
            pendientes.append(linea)
            ultimo = time.time()
        ahora = time.time()
        # Se manda cuando la cosa se ha calmado, O cuando lo acumulado lleva
        # demasiado esperando aunque no se haya calmado.
        if pendientes and ((ahora - ultimo) >= VENTANA
                           or (ahora - primero) >= ESPERA_MAX):
            evs = eventos(pendientes)
            pendientes = []
            if evs:
                avisar(formatear(evs))
        if linea is None:
            time.sleep(1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
