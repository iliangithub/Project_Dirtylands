# SPDX-FileCopyrightText: 2022 Louren van Garderen <mail@lourenvangarderen.nl>
# SPDX-FileCopyrightText: 2023-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# Simple Telegram Bot logger
#
# ==== EXCLUSIVO DE COWRIE (dirtyland). Dionaea usa el suyo ====
# Cambios respecto al original:
#   1. Timestamp ISO en cada alerta.
#   2. Descargas/subidas: SHA-256, fichero destino y origen.
#   3. Enlace a AbuseIPDB (la consulta la hace el operador, no el senuelo).
#   4. Reporta tambien file_upload (SCP), no solo descargas.
#   5. Escapa el HTML del input del atacante.
#   6. ANTI-SPAM POR IP + HUELLA DE PLAYBOOK. La regla es:
#        - una IP ejecuta un guion de comandos -> AVISA
#        - esa MISMA IP repite ese guion       -> avisa hasta ALERTS_PER_IP
#                                                 veces; a partir de ahi, mudo
#        - OTRA IP ejecuta el mismo guion      -> AVISA (es otro actor)
#        - la IP mete un comando que nunca le habiamos visto -> AVISA, y
#          muestra solo lo nuevo
#      El guion se identifica normalizado, asi que rotar IP, URL o el nombre
#      del dropper no sirve para volver a sonar.
#      Ademas hay una cola de salida que respeta el limite de Telegram
#      (~20 msg/min por chat) y su 429/retry_after: nunca mas se queda mudo.
#   7. Lee bot_token / chat_id del telegram.cfg externo (ruta abajo).
#      Todo lo demas se ajusta con las constantes de este fichero.
#   8. Boton "Block IP" que aplica una regla REAL de nftables.
#   9. LISTA BLANCA: las IPs privadas (tu propio SSH desde dentro de la VPS)
#      se notifican SIEMPRE y enteras, sin filtro alguno, y no se pueden
#      banear desde el boton.
# ==============================================================
#
# ===================== LAS PIEZAS DEL SISTEMA =====================
#
#   CONTENEDOR (dirtyland_cowrie)          HOST (la VPS)
#   ------------------------------         ---------------------------
#   telegram_alert_cowrie.py   <-- ESTE    telegram-ban-watcher
#     detecta, filtra y avisa                servicio systemd que vigila
#     escribe  state/ban_queue  ---------->  la cola y llama a...
#     lee      state/ban_results <--------  telegram-notification-ban
#                                             valida la IP y aplica nft
#                                           telegram-ban-watcher.service
#                                             arranca el watcher al boot
#
#   El contenedor NO puede tocar el cortafuegos (no hay nft, no hay sudo,
#   el compose lleva no-new-privileges). Solo deja la peticion por escrito.
#
# ===================== COMO SE INSTALA ESTE FICHERO ===============
#
#   Vive en el host, en /opt/dirtyland/Telegram Reports/, y entra al
#   contenedor por bind-mount. En docker-compose.yml, dentro de
#   services.cowrie.volumes (las comillas hacen falta: la ruta lleva un
#   espacio):
#
#     - "/opt/dirtyland/Telegram Reports/telegram_alert_cowrie.py:/cowrie/cowrie-git/src/cowrie/output/telegram.py:ro"
#     - "/opt/dirtyland/Telegram Reports/telegram.cfg:/opt/dirtyland/Telegram Reports/telegram.cfg:ro"
#     - "/opt/dirtyland/Telegram Reports/state:/opt/dirtyland/Telegram Reports/state:rw"
#
#   El directorio de escritura, con el uid que usa Cowrie dentro:
#
#     sudo mkdir -p "/opt/dirtyland/Telegram Reports/state"
#     sudo chown $(sudo docker exec dirtyland_cowrie id -u) "/opt/dirtyland/Telegram Reports/state"
#     sudo chmod 770 "/opt/dirtyland/Telegram Reports/state"   # 770, no 700: ver abajo
#
#   Activarlo en /opt/dirtyland/cowrie/etc/cowrie.cfg:
#
#     [output_telegram]
#     enabled = true
#
#   El nombre de la seccion NO es libre, y no funciona como uno esperaria. El
#   cargador (src/twisted/plugins/cowrie_plugin.py) hace:
#
#     engine = x.split("_")[1]
#     output = import_module(f"cowrie.output.{engine}").Output()
#
#   Se queda con el PRIMER trozo del nombre. Una seccion
#   [output_telegram_alert_cowrie] daria engine="telegram" e importaria el
#   plugin DE FABRICA, no este, y sin dar ningun error: el log diria
#   "Loaded output engine: telegram" y las alertas no llegarian jamas.
#   Por eso este fichero se monta ENCIMA de output/telegram.py (ver arriba) y
#   la seccion es [output_telegram] a secas. Para confirmar que se ha cargado
#   ESTE plugin y no el original, buscar en el log la linea:
#     [telegram] tokens cargados de /opt/dirtyland/Telegram Reports/telegram.cfg
#
#   Y levantar:
#
#     cd /opt/dirtyland && sudo docker compose up -d
#     sudo docker logs dirtyland_cowrie 2>&1 | grep -i telegram | tail
#
#   Si editas este fichero, basta con reiniciar el contenedor. Si lo
#   REEMPLAZAS por otro (algunos editores escriben un fichero nuevo en vez
#   de modificarlo), el bind-mount sigue apuntando al inodo viejo:
#
#     sudo docker compose up -d --force-recreate cowrie
#
# ==================================================================

from __future__ import annotations

import configparser
import hashlib
import html
import ipaddress
import json
import os
import re
import shlex
import sys
import time
from collections import OrderedDict, deque

import treq
from twisted.internet import reactor, task
from twisted.internet.utils import getProcessOutputAndValue
from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CowrieConfig


# #############################################################################
# ##                                                                         ##
# ##   FICHERO DE CONFIGURACION CON LOS TOKENS   ->   EDITAR SOLO ESTA LINEA ##
# ##                                                                         ##
TELEGRAM_CFG_PATH = "/opt/dirtyland/Telegram Reports/telegram.cfg"
# ##                                                                         ##
# ##   De ahi se leen UNICAMENTE: enabled, bot_token, chat_id                ##
# ##   (seccion [output_telegram]). Nada mas; el resto son las constantes    ##
# ##   de abajo. Se puede apuntar a otra ruta sin tocar el codigo con la     ##
# ##   variable de entorno DIRTYLAND_TELEGRAM_CFG.                           ##
# ##                                                                         ##
# #############################################################################


# #############################################################################
# ##                          AJUSTES DEL PLUGIN                             ##
# #############################################################################

# --- Rutas. OJO: son rutas DENTRO DEL CONTENEDOR. El compose monta
#     /opt/dirtyland/Telegram Reports del host en la misma ruta, asi que
#     coinciden y no hay que traducir nada mentalmente.
#     El subdirectorio state/ es el unico montado con escritura.
STATE_DIR = "/opt/dirtyland/Telegram Reports/state"
STATE_FILE = STATE_DIR + "/cowrie_telegram_state.json"
BAN_LOG_FILE = STATE_DIR + "/banned.txt"

# --- LISTA BLANCA -----------------------------------------------------------
# Tus propias conexiones. Se notifican SIEMPRE y COMPLETAS, sin dedup ni
# contadores, y el boton de ban se niega a tocarlas (no te vas a echar de tu
# propia VPS por un dedazo).
#
# Redes explicitas a proposito: NO se usa ipaddress.is_private, que ademas de
# las privadas de verdad marca como tales el CGNAT (100.64/10) y los rangos
# de documentacion (192.0.2/24, 198.51.100/24, 203.0.113/24). Por ahi si
# puede venir trafico real, y no queremos regalarle una exencion.
WHITELIST_PRIVATE_IPS = True
WHITELIST_NETWORKS = (
    "10.0.0.0/8",        # RFC1918
    "172.16.0.0/12",     # RFC1918
    "192.168.0.0/16",    # RFC1918
    "127.0.0.0/8",       # loopback: tu ssh desde dentro de la propia VPS
    "169.254.0.0/16",    # link-local
    "::1/128",
    "fc00::/7",          # ULA
    "fe80::/10",         # link-local v6
)
# IPs o redes publicas propias (tu casa, tu movil, tu salto). Mismo trato.
# Acepta "203.0.113.9" o "203.0.113.0/24".
WHITELIST_EXTRA: tuple[str, ...] = ()
# Con lista blanca se espera menos y se enseñan mas comandos: es tu sesion.
WHITELIST_FLUSH_WAIT = 10
WHITELIST_COMMANDS_SHOWN = 60

# --- Agrupado de sesion -----------------------------------------------------
# Los comandos de una sesion NO se mandan sueltos: se acumulan y se juzgan
# juntos. Se envia tras este silencio del atacante, o al cerrar la sesion.
SESSION_FLUSH_WAIT = 30      # segundos
COMMANDS_SHOWN = 15          # comandos mostrados en el mensaje (resto: contados)

# --- LA REGLA DE REPETICION -------------------------------------------------
# Cuantas veces se avisa de que UNA MISMA IP hace LO MISMO.
# Con 2: se avisa de la 1a y la 2a vez; a partir de la 3a, silencio.
# (Sube a 3 si quieres que la tercera tambien suene.)
ALERTS_PER_IP = 2

# RAFAGA DE LOGINS. Numero de logins SEGUIDOS que una IP puede hacer ---sin
# ejecutar nada de por medio--- antes de que se callen sus avisos de login. En
# cuanto teclea un comando, el contador vuelve a 0 (lo reinicia _flush_session)
# y su siguiente login vuelve a sonar; si retoma el aporreo, se vuelve a callar
# pasadas estas veces. Un 0 lo desactiva.
#
# Existe porque la regla de mas abajo solo calla credenciales REPETIDAS, y un
# bot que solo aporrea el login cambia de usuario/clave en cada intento: cada
# uno cuenta como "credencial nueva" y sonaba siempre. Esto mira el volumen de
# logins de la IP, no la credencial, que es lo que de verdad satura el movil.
# Los comandos y las muestras NO se tocan: esos son justo lo que se quiere ver.
LOGIN_RACHA_MAX = int(os.environ.get("LOGIN_RACHA_MAX", "5"))

# BANEO AUTOMATICO. Numero de veces que una IP puede repetir EL MISMO guion
# **sin traer nada nuevo** antes de que se la banee sola. Un 0 lo desactiva.
#
# El disparador no es el volumen bruto, y es a proposito. Contar peticiones
# banearia tambien a quien esta entregando payloads distintos muy deprisa, que
# es justo a quien queremos dejar entrar. La condicion que se usa aqui es mas
# estrecha y significa otra cosa: esta IP repite un guion que ya conocemos y
# **no ha ejecutado ni un comando que no le hubieramos visto**. Cuando eso pasa
# cientos de veces, ha dejado de ensenarnos nada y solo aporta ruido y disco.
#
# Si en algun momento cambia de guion o teclea algo nuevo, la rama de "comandos
# NUEVOS" salta ANTES que esta y no se banea: el contador de repeticiones va
# por (IP, guion), asi que un guion distinto empieza de cero.
#
# El caso que lo motivo: una sola IP con 10.038 eventos identicos en dos horas.
# Por entorno, para poder bajarlo los primeros dias y ver el aviso sin
# esperar a que una IP repita su guion doscientas veces.
#
# OJO, no sirve para ensayarlo desde el anfitrion: una sesion lanzada contra
# el senuelo sale de 172.20.0.x, que esta en WHITELIST_NETWORKS, y a una IP
# de la lista blanca no se le banea nunca (is_whitelisted, mas abajo). Este
# aviso solo lo trae trafico de fuera.
AUTOBAN_REPETICIONES = int(os.environ.get("AUTOBAN_REPETICIONES", "200"))
# Se olvida a una IP que lleva este tiempo sin aparecer: si vuelve dentro de
# un mes, se le considera actor nuevo y vuelve a sonar. 0 = no olvidar nunca.
IP_MEMORY_TTL = 30 * 86400
# Cuantas IPs se recuerdan como maximo (se olvidan las mas antiguas), y cuanto
# se guarda de cada una. De los comandos solo se guarda un hash de 8 caracteres
# (basta para saber si ya se los habiamos visto), asi el fichero de estado se
# queda en pocos MB en vez de crecer sin freno con el texto completo.
MAX_IPS_TRACKED = 5000
# 400 y no 80. Con 80 un bot con un guion largo ---catorce arquitecturas por
# wget, tftp, chmod, rm, mas los busybox sueltos--- no cabia entero en su
# propia memoria, asi que en CADA sesion habia comandos "que no le habiamos
# visto nunca" y la alerta sonaba siempre. Se llego a leer "Vez 341 con este
# guion (solo se avisan las 2 primeras)". El tope casi nunca se toca: un
# escaneo normal deja entre cinco y treinta comandos distintos.
MAX_CMDS_PER_IP = 400
MAX_COUNTERS_PER_IP = 40

# --- Reconocimiento de playbook ---------------------------------------------
# Dos sesiones son "el mismo guion" si comparten este porcentaje de comandos
# normalizados. 0.85 tolera que el bot cambie una linea o dos.
PLAYBOOK_SIMILARITY = 0.85
PLAYBOOK_MIN_COMMANDS = 2    # por debajo, se compara por texto exacto
PLAYBOOK_MAX = 400           # huellas recordadas
# Si una IP conocida mete comandos que nunca le habiamos visto, avisa
# aunque haya agotado su cupo, mostrando unicamente lo nuevo.
ALERT_ON_NOVEL_COMMANDS = True

# --- Logins -----------------------------------------------------------------
# Misma regla: cada IP avisa sus primeras ALERTS_PER_IP entradas. Una
# credencial que no se habia visto NUNCA (de nadie) avisa siempre.

# --- Muestras ---------------------------------------------------------------
# Un SHA-256 nuevo avisa siempre. Uno ya conocido cae bajo la regla por IP.

# --- Cola de salida (limite real de la API de Telegram) ---------------------
# Telegram acepta ~20 mensajes por minuto en un mismo chat; pasarse devuelve
# 429 y acaba silenciando el bot durante horas. Esto NO tira alertas por
# criterio: las encola, las ritma y obedece el retry_after de Telegram.
SEND_MIN_INTERVAL = 1.2      # segundos entre mensajes
SEND_MAX_PER_MINUTE = 18
SEND_QUEUE_MAX = 200         # si se desborda, cae lo menos prioritario
# Igual que el anterior, por entorno; 0 lo desactiva. Y con la misma letra
# pequena: lo que resume son avisos SILENCIADOS, y a una IP de la lista
# blanca no se le silencia nada, asi que tampoco sale con sesiones propias.
DIGEST_INTERVAL = int(os.environ.get("DIGEST_INTERVAL", "1800"))

# --- Boton de ban ------------------------------------------------------------
BAN_BUTTON = True
POLL_UPDATES = True          # escuchar las pulsaciones (getUpdates)

# COMO se aplica el ban:
#
#   "queue"   (el que usas): Cowrie corre en un contenedor. Ahi dentro no hay
#             nft, no hay sudo, y el compose lleva no-new-privileges, asi que
#             el contenedor NO PUEDE ni debe tocar el cortafuegos del host.
#             El plugin solo escribe la IP en BAN_QUEUE_FILE; un servicio del
#             host (telegram-ban-watcher) la lee, aplica la regla de nftables
#             con su comentario, y responde en BAN_RESULT_FILE. El plugin lee
#             esa respuesta y actualiza el boton. El contenedor nunca tiene
#             permisos sobre el cortafuegos: solo puede pedir.
#
#   "command" Cowrie instalado directamente en el host. Ejecuta BAN_COMMAND
#             por sudo. {ip} se sustituye por la IP ya validada.
BAN_MODE = "queue"
BAN_QUEUE_FILE = STATE_DIR + "/ban_queue"
BAN_RESULT_FILE = STATE_DIR + "/ban_results"
BAN_RESULT_TIMEOUT = 90      # seg. sin respuesta del host -> se avisa
BAN_COMMAND = "/usr/bin/sudo -n /usr/local/sbin/telegram-notification-ban {ip}"

ALLOWED_USER_IDS: set[str] = set()   # vacio = cualquiera del chat
SILENCE_BANNED_IPS = True            # tras banear, dejar de alertar de esa IP

# #############################################################################


# Como se nombra cada transporte en los avisos. Cowrie marca "protocol" en
# TODOS los eventos de una sesion ---lo fija EventLog al crearla--- asi que no
# hay que deducirlo del puerto ni del tipo de evento. Si algun dia apareciera
# un transporte nuevo, sale sin etiqueta en vez de mentir.
VIA_PROTOCOLO = {
    "ssh": "vía SSH",
    "telnet": "vía Telnet",
}

# El mismo transporte, para el reparto del resumen. Ahi "via Telnet: 91" se lee
# mal; el nombre a secas, bien.
NOMBRE_PROTOCOLO = {
    "ssh": "SSH",
    "telnet": "Telnet",
}

PRIORITY_EVENTS = (
    "cowrie.login.success",
    "cowrie.session.file_download",
    "cowrie.session.file_upload",
)

BATCH_EVENTS = (
    "cowrie.command.input",
    "cowrie.command.failed",
)

# Normalizacion: lo que cambia entre ejecuciones del MISMO guion.
# El orden importa; se aplican en secuencia sobre cada linea.
_NORM_RULES = (
    (re.compile(r"https?://\S+", re.I), "<URL>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<IP>"),
    (re.compile(r"\b[0-9a-f]{8,}\b", re.I), "<HEX>"),
    (re.compile(r"\b[A-Za-z0-9+/]{20,}={0,2}\b"), "<B64>"),
    # Nombre aleatorio del dropper dentro de una ruta: /tmp/a7f3, /var/run/x9k2.
    # Solo tras una barra, para no tocar palabras normales como eth0 o sha1.
    (
        re.compile(
            r"(?<=/)(?=[A-Za-z0-9_.-]*\d)(?=[A-Za-z0-9_.-]*[A-Za-z])[A-Za-z0-9_.-]{4,}\b"
        ),
        "<RND>",
    ),
    # Y cualquier token largo que mezcle letras y digitos: kworker83sd, .x9k2j1.
    (
        re.compile(
            r"\b(?=[A-Za-z0-9_.-]*\d)(?=[A-Za-z0-9_.-]*[A-Za-z])[A-Za-z0-9_.-]{6,}\b"
        ),
        "<RND>",
    ),
    (re.compile(r"\b\d{3,}\b"), "<N>"),
)
def _trocear(raw: str) -> list[str]:
    """Parte por ; y por salto de linea, PERO no dentro de parentesis.

    Antes era un `re.split(r"[\n;]+")` a secas y por eso los avisos ensenaban
    trozos huerfanos. El guion mas repetido de Mirai lleva un subshell:

        chmod 777 i ||(cp /bin/ls ii;cat i>ii &&rm i;cp ii i;rm ii);./i

    y salia partido en cuatro, con el ultimo pedazo quedandose el parentesis
    de cierre:

        chmod <N> i ||(cp /bin/ls ii
        cat i>ii &&rm i
        cp ii i
        rm ii)          <-- esto no lo escribio nadie, lo partimos nosotros

    Leido en el movil parece un error de sintaxis del atacante, o que el
    mensaje se ha cortado. Ni una cosa ni la otra: el subshell es UNA unidad y
    se cuenta como una.

    Las comillas tambien se respetan: un `echo "a;b"` es un comando, no dos.
    """
    partes: list[str] = []
    actual: list[str] = []
    hondura = 0
    comilla = ""
    for car in raw or "":
        if comilla:
            actual.append(car)
            if car == comilla:
                comilla = ""
            continue
        if car in "'\"":
            comilla = car
            actual.append(car)
            continue
        if car == "(":
            hondura += 1
        elif car == ")" and hondura:
            hondura -= 1
        # El salto de linea parte SIEMPRE, este dentro de un parentesis o no.
        # Solo el ";" respeta la hondura. Es a proposito: con un parentesis
        # sin cerrar ---y el atacante escribe lo que le da la gana--- un
        # salto que no partiera dejaria el resto del guion pegado en un solo
        # pedazo gigante. Fallar hacia trocear de mas es inofensivo; fallar
        # hacia no trocear se come el guion entero.
        if car == "\n" or (car == ";" and not hondura):
            partes.append("".join(actual))
            actual = []
            hondura = 0 if car == "\n" else hondura
            continue
        actual.append(car)
    partes.append("".join(actual))
    return partes



# Telegram corta en 4096 caracteres. Si te pasas devuelve 400 y el mensaje
# NO llega: no es un aviso, es una alerta perdida. Se deja margen para la
# cabecera y el pie.
TELEGRAM_MAX_CHARS = 4096
MESSAGE_BUDGET = 3600
# Tope por comando dentro del bloque. Con 400 caracteres se reconoce
# perfectamente que hace un comando, y ninguno puede acaparar el
# presupuesto y dejar fuera a los demas.
MAX_LINEA = 400


def _esc(value) -> str:
    """Escapa para parse_mode=HTML: el input del atacante es hostil."""
    return html.escape(str(value if value is not None else ""))


def _strip_html(text: str) -> str:
    """Version en texto plano, para reintentar si el HTML no le gusta."""
    return html.unescape(re.sub(r"<[^>]+>", "", text))


def _pre_block(lines, budget=MESSAGE_BUDGET) -> tuple[str, int]:
    """
    Construye un <pre> que quepa de verdad, escapando linea a linea y
    contando el tamano YA escapado (un comando lleno de < y & ocupa el
    triple). Devuelve (bloque, lineas_omitidas).

    Cada comando se recorta a MAX_LINEA. Sin ese recorte, un solo comando
    enorme --un blob en base64, tipico de los droppers-- se comia el
    presupuesto entero: si era el PRIMERO, la funcion salia con la lista
    vacia y el aviso quedaba en "Comandos: 10 (+10 comandos mas)" sin
    ensenar ni uno. Diez comandos anunciados y ninguno visible es peor que
    no avisar, porque parece que el aviso funciona.

    El recorte se hace ANTES de escapar, a proposito: cortar sobre el texto
    ya escapado puede partir una entidad como &quot; por la mitad, y
    entonces Telegram rechaza el mensaje entero con un 400.
    """
    kept, used = [], 0
    for index, line in enumerate(lines):
        line = str(line)
        if len(line) > MAX_LINEA:
            line = line[:MAX_LINEA] + " [...]"
        piece = _esc(line)
        if used + len(piece) + 1 > budget:
            return "<pre>" + "\n".join(kept) + "</pre>", len(lines) - index
        kept.append(piece)
        used += len(piece) + 1
    return "<pre>" + "\n".join(kept) + "</pre>", 0


def _build_whitelist() -> tuple:
    nets = []
    for cidr in (WHITELIST_NETWORKS if WHITELIST_PRIVATE_IPS else ()) + tuple(
        WHITELIST_EXTRA
    ):
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            log.msg("[telegram] lista blanca: %r no es una red valida" % cidr)
    return tuple(nets)


_WHITELIST = _build_whitelist()

# --- Las IP propias que NO son privadas -------------------------------------
#
# Los nodos de salida del VPN son direcciones publicas normales, asi que las
# redes de arriba no las cubren. Y sin ellas pasaban dos cosas feas: la alerta
# de una comprobacion propia llegaba como si fuera un ataque, y el boton rojo
# ofrecia banear nuestro propio nodo --- pulsarlo te echa de tu maquina.
#
# La lista NO se escribe aqui. Sale de la [blocklist] del config.ini, que es
# la unica que dice "esto somos nosotros" y ya se mantiene. Pero ese fichero
# NO se monta en el contenedor, y no debe montarse: lleva las claves de API y
# no pintan nada dentro del honeypot. Asi que el reporter publica solo la
# lista, sin secretos, en el directorio que ya esta montado, y aqui se lee.
#
# Se relee cuando cambia la fecha del fichero: este plugin vive mientras viva
# el contenedor, y anadir un nodo nuevo no deberia obligar a reiniciarlo.
IPS_PROPIAS_FILE = "/opt/dirtyland/Telegram Reports/ips-propias.txt"

_propias_cache: dict = {"mtime": None, "nets": ()}


def _propias_del_fichero() -> tuple:
    try:
        mtime = os.path.getmtime(IPS_PROPIAS_FILE)
    except OSError:
        return ()
    if _propias_cache["mtime"] == mtime:
        return _propias_cache["nets"]

    nets = []
    try:
        with open(IPS_PROPIAS_FILE, encoding="utf-8") as handle:
            for linea in handle:
                linea = linea.split("#", 1)[0].strip()
                if not linea:
                    continue
                try:
                    nets.append(ipaddress.ip_network(linea, strict=False))
                except ValueError:
                    log.msg("[telegram] ips-propias: %r no es una IP ni una red"
                            % linea)
    except OSError as err:
        log.msg("[telegram] no se pudo leer %s: %s" % (IPS_PROPIAS_FILE, err))
        return _propias_cache["nets"]

    _propias_cache["mtime"] = mtime
    _propias_cache["nets"] = tuple(nets)
    log.msg("[telegram] %d IP propias cargadas de %s"
            % (len(nets), IPS_PROPIAS_FILE))
    return _propias_cache["nets"]


def is_whitelisted(ip: str) -> bool:
    """Tus propias IPs: nunca se filtran y nunca se banean."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    redes = _WHITELIST + _propias_del_fichero()
    return any(addr in net for net in redes if net.version == addr.version)


def normalize_command(raw: str) -> list[str]:
    """
    Convierte un comando en su forma canonica para comparar guiones.

    'wget http://5.9.1.2/bins/x86 -O /tmp/a7f3' y
    'wget http://91.3.4.5/bins/mips -O /tmp/b19c'  ->  la misma linea.
    Asi el bot que rota IP/URL/nombre de binario no cuenta como guion nuevo.
    """
    out = []
    for part in _trocear(raw):
        part = part.strip().strip("&|")
        if not part:
            continue
        for pattern, repl in _NORM_RULES:
            part = pattern.sub(repl, part)
        part = re.sub(r"\s+", " ", part).strip()
        if part:
            out.append(part[:200])
    return out


def fingerprint(commands: set[str]) -> str:
    """Huella estable del conjunto de comandos normalizados."""
    joined = "\n".join(sorted(commands))
    return hashlib.sha1(joined.encode("utf-8", "replace")).hexdigest()[:16]


def _eventos(n: int) -> str:
    """"1 evento" / "7 eventos". Un "(1 eventos)" en el resumen canta."""
    return "1 evento" if n == 1 else "%d eventos" % n


# ---------------------------------------------------------------------------
# La bandera del pais de cada IP.
#
# La carpeta va montada en el contenedor EN LA MISMA RUTA que en el anfitrion,
# igual que "Telegram Reports", asi que este import vale dentro y fuera.
#
# Se envuelve entero porque esto es un adorno: si la carpeta no esta montada,
# si la tabla falta o si el modulo cambia de nombre, lo que tiene que pasar es
# que las alertas salgan SIN bandera, no que dejen de salir.
#
# Todo el bloque va envuelto, el sys.path.insert incluido. Aqui se colo un
# NameError ---se uso `sys` sin importarlo--- y eso NO es un adorno que falla:
# revienta al IMPORTAR el modulo, asi que Cowrie arranca sin plugin de salida
# y el senuelo deja de avisar por Telegram entero. Un fallo de una linea
# cosmetica no puede llevarse por delante todo el canal.
# EL IMPORT ES PEREZOSO, y no por elegancia: en una instalacion desde cero el
# contenedor se crea en el apartado 3.4.2.9 y la carpeta geoip no se llena
# hasta el 3.4.4. Importando al cargar el modulo, el plugin arrancaria con la
# carpeta vacia, se quedaria sin tabla PARA SIEMPRE ---un import solo ocurre
# una vez--- y las alertas saldrian sin bandera sin que nada lo dijera, hasta
# que alguien recreara el contenedor sin saber por que.
#
# Al primer aviso ya esta todo copiado, asi que preguntando entonces se
# acierta siempre y el orden del README deja de importar.
_paises = None
_paises_intentado = False


def _cargar_paises():
    global _paises, _paises_intentado
    if not _paises_intentado:
        _paises_intentado = True
        try:
            if "/opt/dirtyland/geoip" not in sys.path:
                sys.path.insert(0, "/opt/dirtyland/geoip")
            import paises as modulo
            _paises = modulo
        except Exception:                                  # noqa: BLE001
            _paises = None
    return _paises


def pais_de(ip: str) -> str:
    """" \U0001f1f9\U0001f1f7 Turquia" para pegar detras de una IP, o "" si no se sabe."""
    if not ip:
        return ""
    modulo = _cargar_paises()
    if modulo is None:
        return ""
    try:
        etiqueta = modulo.etiqueta(ip)
    except Exception:                                      # noqa: BLE001
        return ""
    return "  " + etiqueta if etiqueta else ""


def cmd_hash(command: str) -> str:
    """Hash corto de un comando: lo que se guarda por IP, en vez del texto."""
    return hashlib.sha1(command.encode("utf-8", "replace")).hexdigest()[:8]


class Memory:
    """
    Estado persistente en STATE_FILE.

    - playbooks: catalogo GLOBAL de guiones, solo para reconocerlos y darles
      un identificador estable. No silencia a nadie por si mismo.
    - ips: lo que sabemos de CADA IP. Aqui es donde se decide callar:
      contadores de "esta IP ya hizo esto N veces" y hashes de sus comandos.

    samples y creds son dict y no set a proposito: en un dict el orden de
    insercion se conserva, asi que al recortar por tamano se tiran los mas
    ANTIGUOS. Con un set habria que ordenarlos y se acabarian conservando
    los hashes que empiezan por f, que no es lo que interesa.
    """

    def __init__(self, path: str):
        self.path = path
        self.playbooks: dict[str, dict] = {}
        self.ips: dict[str, dict] = {}
        self.samples: dict[str, None] = {}   # SHA-256 vistos alguna vez
        self.creds: dict[str, None] = {}     # "usuario:clave" vistos alguna vez
        self.banned: set[str] = set()
        self._dirty = False
        self.load()

    # ------------------------------------------------------------ persistencia
    def load(self) -> None:
        try:
            with open(self.path, encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            return
        self.playbooks = data.get("playbooks", {})
        for entry in self.playbooks.values():
            entry["cmds"] = set(entry.get("cmds", []))
            entry["ips"] = set(entry.get("ips", []))
        self.ips = data.get("ips", {})
        for entry in self.ips.values():
            # dict.fromkeys y no set: hay que conservar el orden con el que se
            # guardaron, que es el de insercion. Con un set, al recortar se
            # tiraba al azar.
            entry["cmds"] = dict.fromkeys(entry.get("cmds", []))
            entry["trunc"] = bool(entry.get("trunc"))
        self.samples = dict.fromkeys(data.get("samples", []))
        self.creds = dict.fromkeys(data.get("creds", []))
        self.banned = set(data.get("banned", []))
        self._expire()
        log.msg(
            "[telegram] memoria: %d guiones, %d IPs, %d muestras, %d baneos"
            % (len(self.playbooks), len(self.ips), len(self.samples), len(self.banned))
        )

    def save(self) -> None:
        if not self._dirty:
            return
        data = {
            "playbooks": {
                fp: {
                    "cmds": sorted(e["cmds"]),
                    "ips": sorted(e["ips"])[-200:],
                    "count": e["count"],
                    "first": e["first"],
                    "last": e["last"],
                }
                for fp, e in self.playbooks.items()
            },
            "ips": {
                ip: {
                    "n": e["n"],
                    # list() y no sorted(): ordenarlos aqui destruia en cada
                    # guardado el orden de insercion del que depende el
                    # recorte, y dejaba fuera siempre a los mismos.
                    "cmds": list(e["cmds"]),
                    "trunc": e.get("trunc", False),
                    "last": e["last"],
                }
                for ip, e in self.ips.items()
            },
            "samples": list(self.samples)[-20000:],
            "creds": list(self.creds)[-20000:],
            "banned": sorted(self.banned),
        }
        tmp = self.path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as handle:
                json.dump(data, handle, separators=(",", ":"))
            os.replace(tmp, self.path)
            self._dirty = False
        except OSError as err:
            log.msg(f"[telegram] no se pudo guardar {self.path}: {err}")

    def touch(self) -> None:
        self._dirty = True

    # -------------------------------------------------------- catalogo global
    def match(self, commands: set[str]) -> tuple[str | None, float]:
        """Guion conocido mas parecido (Jaccard), o (None, 0.0)."""
        best_fp, best_score = None, 0.0
        for fp, entry in self.playbooks.items():
            union = len(commands | entry["cmds"])
            if not union:
                continue
            score = len(commands & entry["cmds"]) / union
            if score > best_score:
                best_fp, best_score = fp, score
        if best_score >= PLAYBOOK_SIMILARITY:
            return best_fp, best_score
        return None, best_score

    def register_playbook(self, fp: str, commands: set[str], src_ip: str) -> dict:
        now = time.time()
        entry = self.playbooks.get(fp)
        if entry is None:
            entry = {"cmds": set(commands), "ips": set(), "count": 0,
                     "first": now, "last": now}
            self.playbooks[fp] = entry
        entry["count"] += 1
        entry["last"] = now
        # OJO: el conjunto canonico NO se amplia con cada sesion parecida.
        # Si se ampliara, la huella iria absorbiendo variantes, la similitud
        # de las sesiones normales bajaria del umbral y se catalogarian como
        # guiones nuevos -> cupo nuevo por IP -> volveria el spam.
        if src_ip:
            entry["ips"].add(src_ip)
        self._dirty = True

        if len(self.playbooks) > PLAYBOOK_MAX:
            ordered = sorted(self.playbooks.items(), key=lambda kv: kv[1]["last"])
            for old, _ in ordered[: len(self.playbooks) - PLAYBOOK_MAX]:
                del self.playbooks[old]
        return entry

    # ------------------------------------------------------- contadores por IP
    def ip_entry(self, ip: str) -> dict:
        entry = self.ips.get(ip)
        if entry is None:
            # "cmds" es un dict y no un set por la misma razon que samples
            # y creds, explicada arriba: en un dict se conserva el orden de
            # insercion, asi que al recortar por tamano se tiran los MAS
            # ANTIGUOS. Con un set se tiraban al azar ---en la practica se
            # quedaban los hashes que ordenan mas alto--- y podia perderse lo
            # que se acababa de aprender.
            entry = {"n": {}, "cmds": {}, "last": time.time(), "trunc": False}
            self.ips[ip] = entry
            self._expire()
        return entry

    def times_seen(self, ip: str, key: str) -> int:
        """Veces que ESTA IP ya hizo ESTO (sin contar la actual)."""
        return self.ip_entry(ip)["n"].get(key, 0)

    def bump(self, ip: str, key: str) -> int:
        """Apunta una repeticion mas. Devuelve el numero de esta vez (1 = 1a)."""
        entry = self.ip_entry(ip)
        count = entry["n"].get(key, 0) + 1
        entry["n"][key] = count
        entry["last"] = time.time()
        # Una IP no acumula fichas infinitas: se tiran las mas antiguas.
        if len(entry["n"]) > MAX_COUNTERS_PER_IP:
            for old in list(entry["n"])[: MAX_COUNTERS_PER_IP // 2]:
                del entry["n"][old]
        self._dirty = True
        return count

    def novel_commands(self, ip: str, commands: set[str]) -> set[str]:
        """Comandos (texto) que esta IP no habia ejecutado nunca.

        Si de esa IP ya se ha tenido que olvidar algo, se devuelve el conjunto
        vacio: sobre una memoria incompleta no se puede distinguir "nunca lo
        habia hecho" de "se me olvido", y confundirlos es lo que convertia la
        alerta en un aviso permanente. Callar es aqui el lado seguro ---la IP
        ya esta caracterizada, y si cambia de guion de verdad el contador va
        por (IP, guion) y vuelve a sonar desde cero---.
        """
        entry = self.ip_entry(ip)
        if entry.get("trunc"):
            return set()
        known = entry["cmds"]
        return {c for c in commands if cmd_hash(c) not in known}

    def learn_commands(self, ip: str, commands: set[str]) -> None:
        entry = self.ip_entry(ip)
        for c in commands:
            entry["cmds"][cmd_hash(c)] = None
        if len(entry["cmds"]) > MAX_CMDS_PER_IP:
            sobran = len(entry["cmds"]) - MAX_CMDS_PER_IP
            for viejo in list(entry["cmds"])[:sobran]:
                del entry["cmds"][viejo]
            # Queda constancia de que a esta IP le falta memoria. Sin esta
            # marca, lo olvidado volvia a parecer nuevo en la sesion siguiente
            # y la alerta sonaba una y otra vez con el mismo guion.
            entry["trunc"] = True
        entry["last"] = time.time()
        self._dirty = True

    def forget(self, ip: str) -> None:
        if self.ips.pop(ip, None) is not None:
            self._dirty = True

    def _expire(self) -> None:
        now = time.time()
        if IP_MEMORY_TTL > 0:
            stale = [ip for ip, e in self.ips.items() if now - e["last"] > IP_MEMORY_TTL]
            for ip in stale:
                del self.ips[ip]
            if stale:
                self._dirty = True
        if len(self.ips) > MAX_IPS_TRACKED:
            ordered = sorted(self.ips.items(), key=lambda kv: kv[1]["last"])
            for ip, _ in ordered[: len(self.ips) - MAX_IPS_TRACKED]:
                del self.ips[ip]
            self._dirty = True


class Output(cowrie.core.output.Output):
    """
    telegram output
    """

    # ------------------------------------------------------------------ setup
    def start(self):
        cfg = _load_tokens()
        self.bot_token = cfg.get("bot_token", "")
        self.chat_id = cfg.get("chat_id", "")
        self.enabled = cfg.get("enabled", "true").lower() in ("1", "true", "yes", "on")

        self.memory = Memory(STATE_FILE)

        self._batches: dict[str, dict] = {}
        self._queue: deque = deque()
        self._sent_times: deque = deque()
        self._draining = False
        self._drain_scheduled = False
        self._paused_until = 0.0
        self._poll_errors = 0
        # motivo -> [avisos callados, eventos que representaban]. Son dos
        # cosas distintas y el resumen daba solo la segunda llamandola
        # "eventos silenciados": una sola sesion callada de 300 comandos se
        # leia como 300 avisos escondidos, cuando fue uno.
        self._suppressed: dict[str, list[int]] = {}
        self._suppressed_ips: dict[str, int] = {}
        # Sesiones por transporte, para el reparto del resumen.
        self._sesiones_por_via: dict[str, int] = {}
        # Desde cuando cuentan los numeros del resumen. NO es "hace media
        # hora": si en un intervalo no hubo nada que callar no se manda
        # resumen, y entonces los contadores siguen corriendo. Antes eso no se
        # decia y las sesiones de un rato tranquilo aparecian sumadas al
        # resumen siguiente como si fueran de su media hora.
        self._ventana_desde = time.time()
        self._dropped = 0
        self._update_offset = 0
        self._polling = False
        self._loops: list = []
        self._pending_bans: dict[str, tuple] = {}
        self._result_offset = 0
        # message_id -> {ip: etiqueta_de_estado}. El teclado de un mensaje SE
        # DERIVA de aqui y se vuelve a dibujar entero cada vez que algo cambia.
        #
        # Antes no hacia falta porque solo habia un boton por mensaje, y
        # "cambiar el boton" era reemplazar el teclado entero por uno nuevo de
        # un solo elemento. Con varias IP eso borraria los demas botones: al
        # pulsar "Block A" desapareceria el de B sin haberlo tocado.
        #
        # Un diccionario por mensaje y un unico sitio que dibuja evita esa
        # clase de fallo entera. Es la misma idea que ya aplicamos en otros
        # sitios: no hay dos mitades que puedan discrepar, hay un estado y una
        # funcion que lo pinta.
        self._botones: "OrderedDict[int, OrderedDict[str, str]]" = OrderedDict()

        if not self.enabled:
            log.msg("[telegram] desactivado en telegram.cfg")
            return
        if not self.bot_token or not self.chat_id:
            log.msg("[telegram] falta bot_token o chat_id: salida desactivada")
            self.enabled = False
            return

        if DIGEST_INTERVAL > 0:
            loop = task.LoopingCall(self._send_digest)
            loop.start(DIGEST_INTERVAL, now=False)
            self._loops.append(loop)

        save_loop = task.LoopingCall(self.memory.save)
        save_loop.start(300, now=False)
        self._loops.append(save_loop)

        if BAN_BUTTON and POLL_UPDATES:
            self._polling = True
            reactor.callLater(1, self._poll_updates)

        if BAN_BUTTON and BAN_MODE == "queue":
            results = task.LoopingCall(self._check_ban_results)
            results.start(3, now=False)
            self._loops.append(results)

        log.msg("[telegram] activo (anti-spam por IP + huella de guion)")

    def stop(self):
        self._polling = False
        for loop in self._loops:
            if loop.running:
                loop.stop()
        for session in list(self._batches):
            self._flush_session(session)
        self.memory.save()

    # ------------------------------------------------------------------ write
    def write(self, event):
        for i in list(event):
            # remove twisted 15 legacy keys
            if i.startswith("log_"):
                del event[i]

        if not getattr(self, "enabled", False):
            return

        eventid = event.get("eventid", "")
        src_ip = event.get("src_ip", "")
        session = event.get("session", "")

        # Se cuenta AQUI, antes de cualquier filtro, porque este es el unico
        # punto por el que pasan todos los eventos. El resumen es el unico
        # sitio donde se ve el reparto entre los dos senuelos, y si se contara
        # despues de los filtros solo reflejaria lo que ya se ha avisado.
        protocolo = (event.get("protocol") or "").lower()
        if protocolo and eventid == "cowrie.session.connect":
            self._sesiones_por_via[protocolo] = (
                self._sesiones_por_via.get(protocolo, 0) + 1)

        if SILENCE_BANNED_IPS and src_ip and src_ip in self.memory.banned:
            return

        if eventid in BATCH_EVENTS:
            self._add_to_batch(event)
            return

        if eventid == "cowrie.session.closed":
            if session in self._batches:
                self._flush_session(session)
            return

        if eventid not in PRIORITY_EVENTS:
            return

        if eventid == "cowrie.login.success":
            self._handle_login(event)
        else:
            self._handle_file(event)

    # ------------------------------------------------------------------ logins
    def _handle_login(self, event) -> None:
        src_ip = event.get("src_ip", "")
        username = str(event.get("username", ""))
        password = str(event.get("password", ""))
        cred = f"{username}:{password}"
        white = is_whitelisted(src_ip)

        # Tus propias entradas no ensucian la memoria: si tu usas una clave,
        # el atacante que la pruebe despues tiene que seguir saliendo como
        # "credencial nunca vista".
        new_cred = cred not in self.memory.creds
        if not white:
            self.memory.creds[cred] = None
            self.memory.touch()

        if not white:
            # Rafaga de logins sin nada de por medio. Se cuentan los logins
            # SEGUIDOS de esta IP; _flush_session lo pone a 0 en cuanto teclea
            # un comando. Va ANTES de la regla por credencial porque un userdb
            # que acepta cualquier clave hace que cada intento traiga una
            # credencial nueva, y esa regla ---que solo calla las repetidas---
            # no frenaba el aporreo. Aqui se mira el volumen, no la credencial.
            entry = self.memory.ip_entry(src_ip)
            racha = entry.get("racha", 0) + 1
            entry["racha"] = racha
            if LOGIN_RACHA_MAX and racha > LOGIN_RACHA_MAX:
                self._suppress("rafaga de logins de la misma IP", src_ip)
                return

            times = self.memory.bump(src_ip, "login:" + cred)
            # Credencial jamas vista de nadie: interesa aunque la IP repita.
            if times > ALERTS_PER_IP and not new_cred:
                self._suppress("login repetido de la misma IP", src_ip)
                return
        else:
            times = 0

        msgtxt = self._header(event)
        msgtxt += "\nUsername: <code>" + _esc(username) + "</code>"
        msgtxt += "\nPassword: <code>" + _esc(password) + "</code>"
        if new_cred:
            msgtxt += "\n<i>Credencial nunca vista antes</i>"
        if times > 1:
            # NO se escribe "de %d": un "repeticion 14 de 2" parece un
            # contador roto. El segundo numero es el TOPE de avisos, no un
            # total, asi que se dice como lo que es.
            #
            # Y pasado el cupo la frase cambia, por lo mismo que en los
            # guiones: aqui solo se llega porque la credencial no se habia
            # visto NUNCA de nadie, asi que decir "solo se avisan las 2
            # primeras" en la vez 14 es desmentirse en la misma pantalla.
            if times > ALERTS_PER_IP:
                msgtxt += ("\n<i>Vez %d con esta credencial --- callada desde "
                           "la %d, suena porque la credencial es nueva</i>" % (
                               times, ALERTS_PER_IP + 1))
            else:
                msgtxt += ("\n<i>Vez %d con esta credencial (se avisan las %d "
                           "primeras)</i>" % (times, ALERTS_PER_IP))
        self._enqueue(msgtxt, src_ip, priority=0 if white else 1)

    # --------------------------------------------------------------- descargas
    def _handle_file(self, event) -> None:
        src_ip = event.get("src_ip", "")
        shasum = str(event.get("shasum", ""))
        white = is_whitelisted(src_ip)

        new_sample = bool(shasum) and shasum not in self.memory.samples
        if shasum and not white:
            self.memory.samples[shasum] = None
            self.memory.touch()

        if not white and not new_sample:
            # Binario ya conocido: cae bajo la regla por IP.
            times = self.memory.bump(src_ip, "sample:" + (shasum or "?"))
            if times > ALERTS_PER_IP:
                self._suppress("muestra repetida por la misma IP", src_ip)
                return

        msgtxt = self._header(event)
        outfile = event.get("outfile", "")
        origin = (
            event.get("url", "")
            or event.get("destfile", "")
            or event.get("filename", "")
        )
        if origin:
            msgtxt += "\nOrigin: <code>" + _esc(origin) + "</code>"
        if outfile:
            msgtxt += "\nSaved to: <code>" + _esc(outfile) + "</code>"
        if shasum:
            msgtxt += "\n<strong>%s</strong>" % (
                "MUESTRA NUEVA" if new_sample else "Muestra ya conocida"
            )
            msgtxt += "\nSHA256: <code>" + _esc(shasum) + "</code>"
            # Las dos plataformas, y las dos por SHA-256. Contestan preguntas
            # distintas y por eso van juntas: VirusTotal dice QUE ES (motores,
            # familia) y MalwareBazaar dice SI YA ESTA PUBLICADO --- que es lo
            # que uno quiere saber antes de plantearse subir nada.
            #
            # Un 404 en el enlace de MalwareBazaar tambien es una respuesta:
            # significa que esa muestra no la tienen.
            msgtxt += (
                '\n<a href="https://www.virustotal.com/gui/file/'
                + _esc(shasum)
                + '">Ver en VirusTotal</a>'
                + '  |  <a href="https://bazaar.abuse.ch/sample/'
                + _esc(shasum)
                + '/">Ver en MalwareBazaar</a>'
            )
        self._enqueue(msgtxt, src_ip, priority=0)

    # ------------------------------------------------- acumulado de la sesion
    def _add_to_batch(self, event) -> None:
        session = event.get("session", "") or event.get("src_ip", "")
        src_ip = event.get("src_ip", "")
        white = is_whitelisted(src_ip)

        batch = self._batches.get(session)
        if batch is None:
            batch = {"event": event, "raw": [], "norm": set(), "total": 0,
                     "timer": None, "white": white}
            self._batches[session] = batch

        limit = WHITELIST_COMMANDS_SHOWN if white else COMMANDS_SHOWN
        raw = str(event.get("input", ""))
        batch["total"] += 1
        if len(batch["raw"]) < limit:
            batch["raw"].append(raw)
        batch["norm"].update(normalize_command(raw))

        if batch["timer"] is not None and batch["timer"].active():
            batch["timer"].cancel()
        batch["timer"] = reactor.callLater(
            WHITELIST_FLUSH_WAIT if white else SESSION_FLUSH_WAIT,
            self._flush_session,
            session,
        )

    # ------------------------------- EL NUCLEO: decidir si esta sesion suena
    def _flush_session(self, session) -> None:
        batch = self._batches.pop(session, None)
        if not batch:
            return
        if batch["timer"] is not None and batch["timer"].active():
            batch["timer"].cancel()

        event = batch["event"]
        src_ip = event.get("src_ip", "")
        commands: set[str] = batch["norm"]
        if not commands:
            return

        # La IP hizo algo mas que loguearse: se reinicia su racha de logins,
        # asi su proximo login vuelve a sonar (y si retoma el aporreo, se
        # vuelve a callar tras LOGIN_RACHA_MAX). Es el "hasta que ejecute algo"
        # de la regla de rafaga.
        _ent = self.memory.ips.get(src_ip)
        if _ent is not None and _ent.get("racha"):
            _ent["racha"] = 0

        # ---- Lista blanca: tu propia sesion. Todo, sin filtrar, sin aprender.
        if batch["white"]:
            msgtxt = self._header(event)
            msgtxt += "\nComandos: <strong>%d</strong>" % batch["total"]
            block, cut = _pre_block(batch["raw"])
            msgtxt += "\n" + block
            omitted = batch["total"] - len(batch["raw"]) + cut
            if omitted > 0:
                msgtxt += "\n(+%d comandos mas, ver el JSON log)" % omitted
            self._enqueue(msgtxt, src_ip, priority=0)
            return

        if SILENCE_BANNED_IPS and src_ip in self.memory.banned:
            return

        # ---- 1. Que guion es esto (identidad global, no silencia por si sola)
        if len(commands) < PLAYBOOK_MIN_COMMANDS:
            fp = fingerprint(commands)
            score = 1.0
        else:
            match_fp, score = self.memory.match(commands)
            fp = match_fp or fingerprint(commands)
        entry = self.memory.playbooks.get(fp)
        known_playbook = entry is not None
        other_ips = len(entry["ips"] - {src_ip}) if entry else 0

        # ---- 2. Que le hemos visto ya a ESTA IP
        novel = self.memory.novel_commands(src_ip, commands)
        times = self.memory.bump(src_ip, "pb:" + fp)

        self.memory.register_playbook(fp, commands, src_ip)
        self.memory.learn_commands(src_ip, commands)

        # ---- 3. La regla
        if times > ALERTS_PER_IP:
            if ALERT_ON_NOVEL_COMMANDS and novel:
                pass          # trae algo que nunca le vimos: suena igual
            else:
                # Llegar aqui es la definicion exacta de "no aporta nada":
                # repite guion conocido y no trae ni un comando nuevo.
                if (AUTOBAN_REPETICIONES
                        and times >= AUTOBAN_REPETICIONES
                        and src_ip
                        and not is_whitelisted(src_ip)
                        and src_ip not in self.memory.banned
                        and src_ip not in self._pending_bans):
                    self._autoban(src_ip, times, fp)
                self._suppress("misma IP repitiendo su guion", src_ip, batch["total"])
                return

        # ---- 4. El mensaje
        msgtxt = self._header(event)
        if times == 1 and not known_playbook:
            msgtxt += "\n<strong>ACTOR NUEVO / GUION NUEVO</strong>"
        elif times == 1:
            msgtxt += "\n<strong>IP NUEVA con un guion ya conocido</strong>"
            msgtxt += "\n<code>%s</code> (%d%%, ya usado por %d IP(s))" % (
                fp, int(score * 100), other_ips)
        else:
            # "de esta IP" seria impreciso: el contador va por IP **y guion**
            # ---bump(src_ip, "pb:" + fp)---, asi que la misma IP con otro
            # guion vuelve a avisar desde cero.
            # Llegar aqui pasado el cupo solo ocurre por la rama de comandos
            # nuevos: el resto se ha suprimido mas arriba. Asi que la frase
            # tiene que ser distinta segun el caso. Poner siempre "solo se
            # avisan las N primeras" era desmentirse en la misma pantalla ---se
            # llego a leer "Vez 341 con este guion (solo se avisan las 2
            # primeras)"--- y hacia dudar de todo lo demas del mensaje.
            if times > ALERTS_PER_IP:
                msgtxt += ("\n<strong>Vez %d con este guion</strong>"
                           " --- callada desde la %d, suena por lo de abajo" % (
                               times, ALERTS_PER_IP + 1))
            else:
                msgtxt += ("\n<strong>Vez %d con este guion</strong>"
                           " (se avisan las %d primeras)" % (times, ALERTS_PER_IP))
            msgtxt += "\nGuion <code>%s</code>" % fp

        if times > ALERTS_PER_IP and novel:
            # La cuenta y el "estaba callada" ya los da la linea de arriba;
            # aqui solo queda decir QUE es lo nuevo. Antes esta linea repetia
            # lo del silencio y contradecia a la anterior.
            msgtxt += "\n<strong>Comandos que no le habiamos visto nunca:</strong>"
            shown = sorted(novel)[:COMMANDS_SHOWN]
            block, cut = _pre_block(shown)
            msgtxt += "\n" + block
            rest = len(novel) - len(shown) + cut
            if rest > 0:
                msgtxt += "\n(+%d mas)" % rest
        else:
            msgtxt += "\nComandos: <strong>%d</strong>" % batch["total"]
            block, cut = _pre_block(batch["raw"])
            msgtxt += "\n" + block
            omitted = batch["total"] - len(batch["raw"]) + cut
            if omitted > 0:
                msgtxt += "\n(+%d comandos mas, ver el JSON log)" % omitted

        self._enqueue(msgtxt, src_ip, priority=0 if times == 1 else 1)

    # ------------------------------------------------------- cabecera y texto
    def _header(self, event) -> str:
        src_ip = event.get("src_ip", "")
        white = is_whitelisted(src_ip)
        # AQUI IBA EL "sensor" DE COWRIE, y se quito porque no identificaba
        # nada: por defecto es el hostname del CONTENEDOR, o sea su id de
        # Docker, asi que cambiaba en cada `--force-recreate` ---se vio pasar
        # de 9709a663e247 a 9ee5ca58e312 en un despliegue--- y ademas solo hay
        # un senuelo, con lo que no distinguia entre nada. Un identificador
        # que cambia solo y no separa nada es ruido con aspecto de dato.
        #
        # Lo que SI dice algo va en su sitio: por donde entro. Es lo unico que
        # se lee en la notificacion del movil sin abrirla.
        via = VIA_PROTOCOLO.get((event.get("protocol") or "").lower())
        msgtxt = "<strong>[Cowrie" + (" " + via if via else "") + "]</strong>"
        if white:
            msgtxt += " <strong>[IP PROPIA]</strong>"
        # Linea en blanco: la cabecera es lo que se mira de un vistazo y
        # pegada al Event no se separaba de los datos.
        msgtxt += "\n\nEvent: " + _esc(event.get("eventid"))
        msgtxt += "\nTime: <code>" + _esc(event.get("timestamp")) + "</code>"
        # La marca va pegada a la IP, no solo en la cabecera: al mirar el
        # movil de reojo lo que se lee es la linea del Source.
        msgtxt += "\nSource: <code>" + _esc(src_ip) + "</code>"
        if white:
            msgtxt += " (nuestro \U0001F607)"
        else:
            # El pais del REGISTRO del rango, no el de quien teclea. Va aqui,
            # pegado a la IP, y no como un "desde X" que prometeria saber
            # donde esta sentado alguien.
            # No pasa por _esc: no es texto del atacante, es nuestro, y
            # nombres.txt se genera sin tildes ni signos que HTML mire.
            msgtxt += pais_de(src_ip)
        if src_ip and not white:
            # La consulta la hace el operador desde su movil, no el honeypot,
            # asi que no genera trafico saliente desde la red del senuelo.
            msgtxt += (
                '\n<a href="https://www.abuseipdb.com/check/'
                + _esc(src_ip)
                + '">Ver IP en AbuseIPDB</a>'
            )
        msgtxt += "\nSession: <code>" + _esc(event.get("session")) + "</code>"
        return msgtxt

    # --------------------------------------------------- contadores y resumen
    def _reparto_por_via(self) -> str:
        """Una linea con las sesiones de cada transporte, o vacia si no hay.

        Va en el resumen y no en cada aviso: el resumen es UNO para los dos
        senuelos ---no hay un resumen de SSH y otro de telnet--- asi que es el
        sitio donde el reparto significa algo.
        """
        if not self._sesiones_por_via:
            return ""
        partes = []
        for proto, n in sorted(self._sesiones_por_via.items(),
                               key=lambda kv: (-kv[1], kv[0])):
            partes.append("%s: %d" % (NOMBRE_PROTOCOLO.get(proto, proto), n))
        return "\nSesiones: " + ", ".join(partes)

    def _autoban(self, ip, times, fp) -> None:
        """Banea una IP que lleva `times` repeticiones sin aportar nada.

        Avisa SIEMPRE, aunque la IP estuviera silenciada. Un baneo que ocurre
        solo y no se cuenta en ningun sitio es indistinguible de un baneo que
        no ocurrio, y ademas seria la unica accion del sistema que actua sobre
        un tercero sin dejar rastro visible.
        """
        log.msg("[telegram] autoban de %s tras %d repeticiones del guion %s"
                % (ip, times, fp))
        # SE APUNTA ANTES DE AVISAR, y ese orden es el arreglo. El filtro de
        # botones ya excluia lo que estuviera baneado o en vuelo, pero aqui el
        # aviso se encolaba PRIMERO y la peticion de baneo despues: al pintar
        # el teclado la IP todavia no constaba en ningun sitio, y salia con su
        # boton de "Block IP" debajo del "BANEO AUTOMATICO".
        self._pending_bans.setdefault(ip, ({}, time.time()))
        self._enqueue(
            "<strong>[Cowrie]</strong>\n\U0001f6ab <strong>BANEO AUTOMATICO</strong>"
            "\n<code>%s</code>\nLleva <strong>%d</strong> repeticiones del guion "
            "<code>%s</code> sin ejecutar un solo comando nuevo.\nSe deja de "
            "aprender de ella; el resto sigue igual." % (_esc(ip), times, _esc(fp)),
            ip,
            priority=1,
        )
        # "auto": es el baneo que decide el propio plugin, no el boton. Va
        # hasta el comentario de la regla de nftables para poder contarlos por
        # separado en el resumen diario.
        self._ban_ip(ip, 4, {}, origen="auto")

    def _suppress(self, reason, src_ip, count=1) -> None:
        """Un aviso que no se manda, y cuantos eventos representaba.

        `count` son EVENTOS (comandos de la sesion, normalmente), no avisos:
        por muchos que sean, el aviso que se ha callado es uno.
        """
        par = self._suppressed.setdefault(reason, [0, 0])
        par[0] += 1
        par[1] += count
        if src_ip:
            self._suppressed_ips[src_ip] = self._suppressed_ips.get(src_ip, 0) + count

    def _send_digest(self) -> None:
        if not self._suppressed and not self._dropped:
            # No se manda, y tampoco se reinicia nada: lo contado hasta ahora
            # sigue vivo y saldra en el proximo, con su ventana ya alargada.
            # Reiniciar aqui perderia esas sesiones; no decir la ventana era
            # lo que las convertia en mentira.
            return
        avisos = sum(p[0] for p in self._suppressed.values())
        eventos = sum(p[1] for p in self._suppressed.values())
        descartados = self._dropped
        top = sorted(self._suppressed_ips.items(), key=lambda kv: kv[1], reverse=True)[:5]

        minutos = max(1, int((time.time() - self._ventana_desde) / 60))
        msgtxt = "<strong>[Cowrie] Resumen</strong> --- ultimos %d min" % minutos
        msgtxt += self._reparto_por_via()
        msgtxt += "\nAvisos callados: <strong>%d</strong>" % avisos
        if eventos != avisos:
            # Los eventos solo se nombran cuando aportan algo. "3 avisos (3
            # eventos)" es ruido.
            msgtxt += " (%s)" % _eventos(eventos)
        for reason, (n_av, n_ev) in sorted(self._suppressed.items(),
                                           key=lambda kv: -kv[1][0]):
            msgtxt += "\n  %s: %d" % (_esc(reason), n_av)
            if n_ev != n_av:
                msgtxt += " (%s)" % _eventos(n_ev)
        if descartados:
            msgtxt += "\n  descartados por cola llena: %d" % descartados
        if top:
            msgtxt += "\nIPs mas insistentes:"
            for ip, num in top:
                # La IP ES el enlace a AbuseIPDB, en vez de un <code> que
                # hay que copiar y pegar a mano en el navegador:
                # consultarla es lo unico que se hace con ella al leer el
                # resumen.
                #
                # Sigue siendo seguro aunque se pierda el <code>. Lo que
                # ese <code> protegia era que Telegram no convirtiera la
                # IP suelta en un enlace hacia http://esa-ip; dentro de un
                # <a> nuestro ya no puede, porque el destino lo ponemos
                # nosotros.
                #
                # La consulta la hace el movil del operador: desde la red
                # del senuelo no sale ni una peticion.
                msgtxt += (
                    '\n  <a href="https://www.abuseipdb.com/check/%s">'
                    '%s</a>%s (%s)') % (_esc(ip), _esc(ip), pais_de(ip),
                                        _eventos(num))

        # "acumulada", y con el tope cuando se ha llegado a el. Son totales de
        # la memoria del plugin, no de esta ventana, y estaban puestos justo
        # debajo de los numeros del intervalo sin decirlo. Ademas saturan: una
        # vez en el tope no vuelven a moverse, asi que un numero que ya no
        # cambia se leia como si midiera actividad.
        guiones, ips = len(self.memory.playbooks), len(self.memory.ips)
        msgtxt += "\nMemoria acumulada: %d guiones%s, %d IPs%s" % (
            guiones, " (tope)" if guiones >= PLAYBOOK_MAX else "",
            ips, " (tope)" if ips >= MAX_IPS_TRACKED else "")

        self._suppressed.clear()
        self._suppressed_ips.clear()
        self._sesiones_por_via.clear()
        # Restar y no poner a cero: el _enqueue de aqui abajo puede descartar
        # este mismo resumen y sumar uno mas, y ese no se puede perder ---es
        # justo el momento en el que hace falta saberlo---.
        self._dropped -= descartados
        self._ventana_desde = time.time()
        # UN BOTON POR CADA IP DE LA LISTA, no solo por la primera.
        #
        # Antes iba solo la mas insistente. Con dos IP en el mensaje y un
        # solo boton, la segunda habia que banearla a mano --- y lo que se
        # lee de un vistazo es que solo una es accionable, que es justo lo
        # contrario de lo que el resumen esta contando.
        #
        # No se desmadra: la lista ya esta acotada a cinco unas lineas mas
        # arriba, y los botones siguen a la lista.
        self._enqueue(msgtxt, [ip for ip, _ in top], priority=2)

    # ---------------------------------------------- cola de salida con ritmo
    def _enqueue(self, message, src_ip, priority=1) -> None:
        """
        Encola respetando el limite real de Telegram. No es una cuota de
        informacion: es el ritmo de entrega. Si la cola se desborda se tira
        lo menos prioritario (los resumenes antes que las muestras nuevas).
        """
        if len(self._queue) >= SEND_QUEUE_MAX:
            worst = max(range(len(self._queue)), key=lambda i: self._queue[i][0])
            if self._queue[worst][0] >= priority:
                del self._queue[worst]
                self._dropped += 1
            else:
                self._dropped += 1
                return
        self._queue.append((priority, message, src_ip))
        self._drain()

    def _drain(self) -> None:
        if self._draining or not self._queue:
            return
        now = time.time()

        if now < self._paused_until:
            self._schedule_drain(self._paused_until - now)
            return

        while self._sent_times and now - self._sent_times[0] > 60:
            self._sent_times.popleft()
        if len(self._sent_times) >= SEND_MAX_PER_MINUTE:
            self._schedule_drain(60 - (now - self._sent_times[0]) + 0.5)
            return

        best = min(range(len(self._queue)), key=lambda i: self._queue[i][0])
        priority, message, src_ip = self._queue[best]
        del self._queue[best]

        self._draining = True
        self._sent_times.append(now)
        d = self._send(message, src_ip)
        d.addBoth(self._after_send)

    def _schedule_drain(self, delay) -> None:
        # Un unico temporizador pendiente. Sin esta guarda, 300 alertas de
        # golpe dejaban 300 callLater en cola, justo en la avalancha en la
        # que menos falta hacen.
        if self._drain_scheduled:
            return
        self._drain_scheduled = True
        reactor.callLater(max(delay, SEND_MIN_INTERVAL), self._drain_timer)

    def _drain_timer(self) -> None:
        self._drain_scheduled = False
        self._drain()

    def _after_send(self, _result) -> None:
        self._draining = False
        if self._queue:
            self._schedule_drain(SEND_MIN_INTERVAL)

    # ------------------------------------------------------------- transporte
    def send_message(self, message):
        """Compatibilidad con el plugin original."""
        self._enqueue(message, None, priority=1)

    def _send(self, message, src_ip):
        log.msg("Telegram plugin will try to call TelegramBot")
        if len(message) > TELEGRAM_MAX_CHARS:
            # Red de seguridad: cortar HTML a ciegas partiria una etiqueta y
            # Telegram devolveria 400. En texto plano no hay nada que romper.
            message = _strip_html(message)[: TELEGRAM_MAX_CHARS - 20] + "\n[...]"
        payload = {
            "chat_id": self.chat_id,
            "parse_mode": "HTML",
            "text": message,
            "disable_web_page_preview": True,
        }
        keyboard = self._keyboard(src_ip)
        if keyboard:
            payload["reply_markup"] = keyboard

        d = treq.post(
            "https://api.telegram.org/bot%s/sendMessage" % self.bot_token,
            json=payload,
            timeout=20,
        )
        d.addCallback(treq.json_content)
        d.addCallback(self._check_response, message, src_ip)
        d.addErrback(lambda f: log.msg("[telegram] sendMessage: %s" % f.getErrorMessage()))
        return d

    def _check_response(self, body, message, src_ip) -> None:
        """
        429 = nos hemos pasado de ritmo. Telegram dice cuantos segundos hay
        que callarse; se respeta y se reencola el mensaje en vez de perderlo.
        400 por HTML mal formado = se reintenta en texto plano, que es mejor
        que perder la alerta por un caracter raro del atacante.

        Y se deja constancia SIEMPRE, tambien cuando sale bien. Antes, un
        envio correcto y un envio perdido dejaban en el log exactamente el
        mismo rastro: la unica linea "will try to call" que escribe _send.
        Con eso, "no me llegan las alertas" no se puede diagnosticar sin
        instrumentar el plugin a mano. El message_id que devuelve Telegram es
        el acuse de recibo, y es lo que convierte esa duda en un dato.

        El cuerpo que no es un diccionario tampoco se descarta en silencio.
        Ocurre cuando delante hay un proxy o un portal cautivo que responde
        una pagina HTML con HTTP 200: la peticion "funciona", el mensaje no
        existe, y sin esta linea no queda ni rastro.
        """
        if not isinstance(body, dict):
            log.msg("[telegram] respuesta inesperada (%s): %.200r"
                    % (type(body).__name__, body))
            return
        if body.get("ok"):
            result = body.get("result")
            log.msg("[telegram] enviado, message_id=%s" % (
                result.get("message_id") if isinstance(result, dict) else "?"))
            return
        code = body.get("error_code")
        description = str(body.get("description", ""))

        if code == 429:
            retry = int(body.get("parameters", {}).get("retry_after", 30))
            self._paused_until = time.time() + retry + 1
            log.msg("[telegram] 429: pausa de %ds" % retry)
            self._queue.appendleft((0, message, src_ip))
        elif code == 400 and "parse" in description.lower() and "<" in message:
            log.msg("[telegram] HTML rechazado, reintento en texto plano")
            self._queue.appendleft((0, _strip_html(message), src_ip))
        else:
            log.msg("[telegram] API error %s: %s" % (code, description))

    # ------------------------------------------------ botones de ban (nftables)
    #
    # UN BOTON POR IP, y por que eso no se desmadra cuando hay muchas:
    #
    #   - Los botones siguen a la LISTA QUE SE VE, y esa lista ya esta acotada
    #     (el resumen ensena las 5 IP mas insistentes). Nunca hay mas botones
    #     que lineas. El tope no es de los botones: es del mensaje, y ya
    #     existia.
    #   - Uno por fila. La etiqueta de una IPv4 son ~26 caracteres y la de una
    #     IPv6 hasta 45; dos por fila se cortan en un movil, y un boton que
    #     dice "Block 2001:db8:..." es un boton que no te atreves a pulsar.
    #   - callback_data admite 64 bytes. "ban:" + IPv6 larga = 49. Cabe, y hay
    #     una prueba que lo comprueba en vez de confiar en que quepa.
    #   - Si algun dia la lista pasara de ~8, lo que tocaria NO es apilar mas
    #     filas sino una sola de "bloquear todas las listadas". Con 5 no hace
    #     falta y no se anade: un boton que borra cinco cosas de golpe es un
    #     dedazo esperando a ocurrir.
    ETIQUETA_BLOQUEAR = "🚫 Block IP %s"
    MAX_MENSAJES_CON_BOTON = 200

    def _ips_con_boton(self, ips):
        """Filtra las IP que pueden llevar boton, sin repetir y en orden."""
        if not BAN_BUTTON or not ips:
            return []
        if isinstance(ips, str):
            ips = [ips]
        salida = []
        for ip in ips:
            if not ip or ip in salida:
                continue
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            # Nunca un boton que te pueda echar de tu propia VPS.
            #
            # Ni uno para banear lo que ya se esta baneando: _pending_bans son
            # las peticiones en vuelo, y sin mirarlas el aviso del BANEO
            # AUTOMATICO llegaba con un boton de "Block IP" para la IP que
            # acababa de banearse sola. No es solo raro de leer ---invita a
            # pulsar algo que no hace falta--- y quien lo pulsara se llevaria
            # un error, porque la regla ya esta puesta.
            if (is_whitelisted(ip) or ip in self.memory.banned
                    or ip in self._pending_bans):
                continue
            salida.append(ip)
        return salida

    def _pintar_teclado(self, estado):
        """Dibuja el teclado ENTERO a partir del estado. Unico sitio que pinta.

        Que sea el unico es justo lo que arregla el fallo de los varios
        botones: antes "cambiar un boton" era mandar un teclado nuevo de un
        solo elemento, asi que pulsar el de una IP borraba los de las demas
        sin haberlas tocado.
        """
        filas = []
        for ip, (texto, activo) in estado.items():
            filas.append([{"text": texto,
                           "callback_data": ("ban:%s" % ip) if activo else "noop"}])
        return {"inline_keyboard": filas} if filas else None

    def _estado_inicial(self, ips):
        return OrderedDict(
            (ip, (self.ETIQUETA_BLOQUEAR % ip, True))
            for ip in self._ips_con_boton(ips))

    def _keyboard(self, ips):
        """Teclado inicial. Acepta una IP suelta o una lista."""
        estado = self._estado_inicial(ips)
        return self._pintar_teclado(estado) if estado else None

    def _registrar_botones(self, message_id, ips) -> None:
        """Recuerda que botones lleva un mensaje ya enviado.

        Hace falta porque el message_id no existe hasta que Telegram contesta,
        y sin el no se puede volver a dibujar el teclado mas tarde.
        """
        estado = self._estado_inicial(ips)
        if not message_id or not estado:
            return
        self._botones[message_id] = estado
        # Sin tope esto crece para siempre en un proceso que no para nunca.
        # Los mensajes viejos ya nadie los va a pulsar.
        while len(self._botones) > self.MAX_MENSAJES_CON_BOTON:
            self._botones.popitem(last=False)

    def _poll_updates(self) -> None:
        """Long-polling de getUpdates: es como llega la pulsacion del boton."""
        if not self._polling:
            return

        d = treq.post(
            "https://api.telegram.org/bot%s/getUpdates" % self.bot_token,
            json={
                "offset": self._update_offset,
                "timeout": 25,
                "allowed_updates": ["callback_query"],
            },
            timeout=40,
        )
        d.addCallback(treq.json_content)
        d.addCallback(self._handle_updates)
        d.addErrback(self._poll_failed)
        # Espera creciente si algo va mal (token invalido, otro proceso
        # haciendo getUpdates con el mismo token, la red caida): de 2s a 60s,
        # en vez de martillear la API cada 2 segundos para siempre.
        d.addBoth(lambda _: reactor.callLater(
            min(2 * (2 ** min(self._poll_errors, 5)), 60) if self._poll_errors else 2,
            self._poll_updates,
        ))

    def _poll_failed(self, failure) -> None:
        self._poll_errors += 1
        if self._poll_errors <= 3 or self._poll_errors % 20 == 0:
            log.msg("[telegram] getUpdates (%d fallos): %s"
                    % (self._poll_errors, failure.getErrorMessage()))

    def _handle_updates(self, payload) -> None:
        self._poll_errors = 0
        for update in (payload or {}).get("result", []):
            self._update_offset = max(self._update_offset, update.get("update_id", 0) + 1)
            query = update.get("callback_query")
            if not query:
                continue

            data = str(query.get("data", ""))
            if not data.startswith("ban:"):
                continue

            # El chat tiene que ser el nuestro y, si se ha configurado
            # ALLOWED_USER_IDS, tambien el usuario.
            chat = str(query.get("message", {}).get("chat", {}).get("id", ""))
            user = str(query.get("from", {}).get("id", ""))
            if chat != str(self.chat_id):
                continue
            if ALLOWED_USER_IDS and user not in ALLOWED_USER_IDS:
                self._answer_callback(query.get("id"), "No autorizado")
                continue

            ip = data[4:]
            try:
                parsed = ipaddress.ip_address(ip)
            except ValueError:
                self._answer_callback(query.get("id"), "IP invalida")
                continue
            if is_whitelisted(ip):
                # Cinturon y tirantes: aunque llegase el callback, no.
                self._answer_callback(query.get("id"), "IP propia: no se banea")
                continue

            self._answer_callback(query.get("id"), "Aplicando regla para %s..." % ip)
            self._ban_ip(ip, parsed.version, query.get("message", {}))

    def _ban_ip(self, ip, version, message, origen="manual") -> None:
        """Pide el ban. En modo cola lo pide; en modo comando lo ejecuta.

        `origen` dice si lo pidio el boton o el baneo automatico. Sin eso los
        dos quedaban con el mismo comentario en la tabla de nftables y no
        habia forma de contarlos por separado.
        """
        if BAN_MODE == "queue":
            self._queue_ban(ip, message, origen)
            return

        argv = [part.replace("{ip}", ip) for part in shlex.split(BAN_COMMAND)]
        argv.append(origen)
        if not argv:
            return

        d = getProcessOutputAndValue(argv[0], argv[1:], env=os.environ)
        d.addCallback(self._ban_result, ip, message)
        d.addErrback(self._ban_failed, ip, message)

    # ---------------------------------------------- modo cola (contenedor)
    def _queue_ban(self, ip, message, origen="manual") -> None:
        """
        Escribe la peticion en la cola compartida. Una sola linea, en modo
        append, que en POSIX es atomico para escrituras cortas: aunque
        lleguen dos pulsaciones a la vez no se mezclan.
        """
        # EN UTC Y CON EL HUSO PUESTO. time.strftime() a secas da la hora
        # LOCAL DEL CONTENEDOR, que va en Europe/Kyiv, y la escribia sin
        # ninguna marca: un baneo pedido a las 14:16 UTC quedaba anotado como
        # "17:16:42". Eso va a parar a ban_results y al journal, que son el
        # registro de auditoria de quien baneo que y cuando; dentro de un mes
        # esa fecha miente por tres horas. Es la misma familia que el problema
        # de cowrie_log_tz.
        #
        # Sigue siendo UN solo token sin espacios, que es lo que espera el
        # `while read -r stamp ip rest` del vigilante.
        line = "%s %s %s\n" % (
            time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()), ip,
            "auto" if origen == "auto" else "manual")
        try:
            with open(BAN_QUEUE_FILE, "a", encoding="utf-8") as handle:
                handle.write(line)
        except OSError as err:
            log.msg("[telegram] no se pudo encolar el ban de %s: %s" % (ip, err))
            self._update_button(message, "⚠ No se pudo encolar %s" % ip, ip)
            self._enqueue(
                "<strong>[Cowrie]</strong>\n⚠ No se pudo escribir en la cola "
                "de baneos.\n<pre>%s</pre>\nRevisa el volumen de escritura y "
                "los permisos de <code>%s</code>." % (_esc(err), _esc(STATE_DIR)),
                None,
                priority=0,
            )
            return

        self._pending_bans[ip] = (message, time.time())
        self._update_button(message, "⏳ Baneando %s..." % ip, ip)
        log.msg("[telegram] ban de %s encolado, esperando al host" % ip)

    def _check_ban_results(self) -> None:
        """Lee las respuestas del servicio del host y cierra el circulo."""
        if not self._pending_bans:
            return

        try:
            size = os.path.getsize(BAN_RESULT_FILE)
        except OSError:
            size = 0
        if size < self._result_offset:      # el fichero se ha rotado
            self._result_offset = 0

        if size > self._result_offset:
            try:
                with open(BAN_RESULT_FILE, encoding="utf-8", errors="replace") as fh:
                    fh.seek(self._result_offset)
                    lines = fh.readlines()
                    self._result_offset = fh.tell()
            except OSError as err:
                log.msg("[telegram] no se pudo leer %s: %s" % (BAN_RESULT_FILE, err))
                lines = []

            for line in lines:
                parts = line.split(None, 3)
                if len(parts) < 3:
                    continue
                _stamp, ip, status = parts[0], parts[1], parts[2]
                detail = parts[3].strip() if len(parts) > 3 else ""
                if ip not in self._pending_bans:
                    continue
                message, _ = self._pending_bans.pop(ip)
                if status == "OK":
                    self.memory.banned.add(ip)
                    self.memory.touch()
                    self.memory.save()
                    self._update_button(
                        message, "\U0001f6ab BLOCKED %s en nftables" % ip, ip)
                    self._enqueue(
                        "<strong>[Cowrie]</strong>\n\U0001f6ab BLOCKED "
                        "<code>%s</code> en nftables" % _esc(ip),
                        None,
                        priority=0,
                    )
                else:
                    self._update_button(message, "⚠ Fallo al banear %s" % ip, ip)
                    self._enqueue(
                        "<strong>[Cowrie]</strong>\n⚠ El host no pudo banear "
                        "<code>%s</code>\n<pre>%s</pre>"
                        % (_esc(ip), _esc(detail[:300])),
                        None,
                        priority=0,
                    )

        # Peticiones sin respuesta: casi siempre el watcher parado.
        now = time.time()
        for ip in [i for i, (_, ts) in self._pending_bans.items()
                   if now - ts > BAN_RESULT_TIMEOUT]:
            message, _ = self._pending_bans.pop(ip)
            self._update_button(message, "⚠ Sin respuesta del host: %s" % ip, ip)
            self._enqueue(
                "<strong>[Cowrie]</strong>\n⚠ <code>%s</code> lleva %ds en la "
                "cola sin respuesta.\nComprueba el servicio del host:\n"
                "<code>systemctl status telegram-ban-watcher</code>"
                % (_esc(ip), BAN_RESULT_TIMEOUT),
                None,
                priority=0,
            )

    def _ban_result(self, result, ip, message) -> None:
        out, err, code = result
        detail = (err or out or b"").decode("utf-8", "replace").strip()
        if code == 0:
            self.memory.banned.add(ip)
            self.memory.touch()
            self.memory.save()
            self._audit(ip, "OK")
            self._update_button(message, "\U0001f6ab BLOCKED %s en nftables" % ip, ip)
            self._enqueue(
                "<strong>[Cowrie]</strong>\n\U0001f6ab BLOCKED <code>%s</code> "
                "en nftables" % _esc(ip),
                None,
                priority=0,
            )
        else:
            self._audit(ip, "FALLO rc=%s %s" % (code, detail))
            self._update_button(message, "⚠ Fallo al banear %s" % ip, ip)
            self._enqueue(
                "<strong>[Cowrie]</strong>\n⚠ No se pudo banear "
                "<code>%s</code>\nrc=%s\n<pre>%s</pre>"
                % (_esc(ip), code, _esc(detail[:300])),
                None,
                priority=0,
            )

    def _ban_failed(self, failure, ip, message) -> None:
        log.msg("[telegram] ban %s fallo: %s" % (ip, failure.getErrorMessage()))
        self._audit(ip, "ERROR %s" % failure.getErrorMessage())
        self._update_button(message, "⚠ Fallo al banear %s" % ip, ip)

    def _audit(self, ip, status) -> None:
        try:
            with open(BAN_LOG_FILE, "a", encoding="utf-8") as handle:
                handle.write(
                    "%s %s %s\n" % (time.strftime("%Y-%m-%dT%H:%M:%S"), ip, status)
                )
        except OSError as err:
            log.msg("[telegram] no se pudo escribir %s: %s" % (BAN_LOG_FILE, err))

    def _answer_callback(self, callback_id, text) -> None:
        if not callback_id:
            return
        d = treq.post(
            "https://api.telegram.org/bot%s/answerCallbackQuery" % self.bot_token,
            json={"callback_query_id": callback_id, "text": text},
            timeout=10,
        )
        d.addCallback(treq.content)
        d.addErrback(lambda f: log.msg("[telegram] answerCallback: %s" % f.getErrorMessage()))

    def _update_button(self, message, label, ip=None) -> None:
        """Marca el resultado EN LA FILA DE ESA IP, sin tocar las demas.

        Antes esto mandaba un teclado nuevo con un unico boton, y con eso
        bastaba porque solo habia uno. Con varias IP en el mismo mensaje, eso
        borraba los botones de las demas: pulsabas "Block A" y B desaparecia
        sin que nadie lo hubiera tocado ni baneado. Peor que un boton de menos
        es un boton que desaparece dando a entender que ya esta hecho.

        Ahora se actualiza el estado de esa IP y se vuelve a dibujar el
        teclado entero desde el estado. Si el mensaje no esta registrado ---
        por ejemplo si el plugin se reinicio despues de enviarlo --- se cae al
        comportamiento de antes, que para un solo boton es correcto.
        """
        # Un baneo automatico no viene de ningun boton, asi que llega aqui sin
        # mensaje. Antes eso reventaba con AttributeError sobre None.
        if not message:
            return
        message_id = message.get("message_id")
        if not message_id:
            return

        estado = self._botones.get(message_id)
        if estado is not None and ip in estado:
            estado[ip] = (label, False)
            markup = self._pintar_teclado(estado)
        else:
            markup = {"inline_keyboard": [[{"text": label,
                                            "callback_data": "noop"}]]}

        d = treq.post(
            "https://api.telegram.org/bot%s/editMessageReplyMarkup" % self.bot_token,
            json={
                "chat_id": self.chat_id,
                "message_id": message_id,
                "reply_markup": markup,
            },
            timeout=10,
        )
        d.addCallback(treq.content)
        d.addErrback(lambda f: log.msg("[telegram] editMarkup: %s" % f.getErrorMessage()))


def _load_tokens() -> dict:
    """
    Lee SOLO enabled / bot_token / chat_id de TELEGRAM_CFG_PATH.
    Si falta algo, cae a la seccion [output_telegram] de cowrie.cfg.
    """
    path = os.environ.get("DIRTYLAND_TELEGRAM_CFG", TELEGRAM_CFG_PATH)
    values: dict[str, str] = {}

    try:
        with open(path, encoding="utf-8") as handle:
            raw = handle.read()
    except OSError as err:
        log.msg(f"[telegram] no se pudo leer {path}: {err}")
        raw = None

    if raw is not None:
        parser = configparser.ConfigParser(interpolation=None)
        # Si el fichero no trae ninguna cabecera [seccion], le ponemos una.
        if re.search(r"^\s*\[", raw, re.MULTILINE) is None:
            raw = "[output_telegram]\n" + raw
        try:
            parser.read_string(raw)
        except configparser.Error as err:
            log.msg(f"[telegram] {path} mal formado: {err}")
            parser = configparser.ConfigParser(interpolation=None)

        values.update(parser.defaults())
        for section in ("output_telegram", "telegram"):
            if parser.has_section(section):
                values.update(dict(parser.items(section)))
        log.msg(f"[telegram] tokens cargados de {path}")

    for key in ("bot_token", "chat_id"):
        if not values.get(key, "").strip():
            try:
                values[key] = CowrieConfig.get("output_telegram", key)
            except Exception:
                pass

    return {k: str(v).strip() for k, v in values.items()}