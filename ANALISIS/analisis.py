#!/usr/bin/env python3
"""analisis.py --- saca inteligencia del respaldo, sin tocar la VPS.

    python3 ANALISIS/analisis.py --respaldo ./dirtyland-respaldo-2026-09-11/

Lee lo que el senuelo lleva recogido ---sesiones de Cowrie, base de Dionaea,
memoria del bot, base del reporter--- y escribe un informe en Markdown con
los actores, las IPs, el malware y las TTPs.

QUE HACE Y QUE NO HACE, que es lo que decide si el informe vale algo.

Esto AGREGA EVIDENCIA. No atribuye, no nombra familias y no concluye. Todo
lo que escribe es OBSERVADO: sale de contar lo que hay en los registros y se
puede volver a comprobar mirando el mismo fichero. La unica columna inferida
es la de ATT&CK, va marcada como tal y sale de `ttp.tsv`, que es una tabla
que se edita a mano.

La interpretacion ---quien es este actor, de que familia es esta muestra, si
dos guiones son el mismo grupo--- se escribe a mano leyendo esto. Es la
misma disciplina de el 3.5.2 del README, y es lo que hace
que el documento se sostenga: un informe generado que ademas adivina es un
informe en el que ya no se sabe que parte comprobar.

NO EJECUTA NI UNA MUESTRA. De los binarios solo mira tamano y hash.

EL INFORME NO VA AL REPOSITORIO. La herramienta si; su salida no. Va al
documento principal, y ademas lleva IPs y hashes de capturas reales.
Por eso el nombre por defecto casa con una regla del .gitignore.
"""
from __future__ import annotations

import argparse
import collections
import glob
import hashlib
import importlib
import ipaddress
import json
import math
import os
import re
import sqlite3
import sys
import unicodedata
from datetime import datetime, timedelta, timezone, tzinfo

AQUI = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(AQUI)

# --------------------------------------------------------------- el huso
#
# COWRIE FIRMA SUS MARCAS CON UNA "Z" Y ESCRIBE LA HORA LOCAL DEL
# CONTENEDOR. Con el senuelo en Europe/Kyiv eso son tres horas de mas, y no
# se nota en ningun sitio: la cadena es ISO valida y se interpreta sin error.
# Ya mordio una vez ---AbuseIPDB recibia denuncias fechadas en el futuro--- y
# esta escrito entero en REPORTING PLATFORM SCRIPTS/collectors/cowrie.py.
#
# Aqui se repite la correccion en lugar de importar aquel modulo, que arrastra
# el paquete del reporter entero. Para que las dos no se separen con el
# tiempo, la suite comprueba que dan el MISMO resultado sobre las mismas
# marcas: si alguien toca una y no la otra, se pone roja.
_CON_HUSO = re.compile(r"[+-]\d{2}:?\d{2}$")


def parse_timestamp(raw: str | None, tz: tzinfo = timezone.utc):
    if not raw:
        return None
    explicito = _CON_HUSO.search(raw) is not None
    try:
        ts = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if explicito:
        return ts.astimezone(timezone.utc)
    return ts.replace(tzinfo=None).replace(tzinfo=tz).astimezone(timezone.utc)


def resolver_huso(nombre: str) -> tzinfo:
    """El huso que se pide, o se para. NO CAE A UTC EN SILENCIO.

    Devolver UTC cuando no se puede resolver el nombre es lo que hacia
    antes, y es la peor de las opciones: el informe sale ENTERO y con pinta
    de correcto, con todas las marcas tres horas corridas. Es exactamente
    el fallo que cuenta la cabecera de este fichero ---AbuseIPDB recibiendo
    denuncias fechadas en el futuro--- y que costo encontrar precisamente
    porque nada se quejaba.

    Se cae en dos sitios: un --tz mal escrito, y una maquina sin base de
    husos (Windows no trae ninguna; ahi hace falta el paquete tzdata). Las
    dos se arreglan en diez segundos SI alguien te las cuenta.
    """
    if not nombre or nombre.upper() == "UTC":
        return timezone.utc
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(nombre)
    except Exception as exc:                           # noqa: BLE001
        raise SystemExit(
            "no se pudo resolver el huso %r: %s\n"
            "\n"
            "El informe habría salido en UTC y SIN AVISAR, y todas las"
            " marcas de Cowrie se habrían desplazado tantas horas como la"
            " diferencia entre ese huso y UTC.\n"
            "\n"
            "  - Si el nombre está mal, usa uno de la base IANA,\n"
            "    como Europe/Kyiv o UTC.\n"
            "  - Si es correcto, a esta máquina le falta la base de"
            " husos: Windows no trae ninguna. Se instala con\n"
            "    pip install tzdata." % (nombre, exc))


# ------------------------------------------------- normalizar una orden
#
# Dos ejecuciones del MISMO guion nunca son identicas: cambia la URL, la IP,
# el nombre aleatorio del fichero. Sin normalizar, cada atacante parece un
# actor distinto y no se agrupa nada. Las reglas son las mismas que usa el
# bot de Cowrie para su huella (_NORM_RULES), por el mismo motivo y con el
# mismo orden: se aplican en secuencia.
_NORM = (
    (re.compile(r"https?://\S+", re.I), "<URL>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<IP>"),
    (re.compile(r"\b[0-9a-f]{16,}\b", re.I), "<HEX>"),
    (re.compile(r"\b\d{4,}\b"), "<N>"),
    (re.compile(r"\s+"), " "),
)


# LAS TIRAS \xNN SON TEXTO, Y ESCRITO ASI NO SE LEE. Las botnets mandan
# ordenes del tipo `echo -e "\x4f\x56\x46\x55\x47\x5a"`: escriben una
# palabra byte a byte y esperan leerla de vuelta para comprobar que hay un
# shell de verdad al otro lado. En hexadecimal son ruido; en claro son
# OVFUGZ, kami, GAYFGT --- el nombre que la herramienta se da a si misma o
# la senal que usa para reconocerse.
#
# Se descifra APARTE y no dentro de la orden: la orden es la prueba y se
# ensena tal cual llego. Esto es una lectura de esa prueba, en su tabla.
_RX_TIRA = re.compile(r"(?:\\x[0-9a-fA-F]{2}){3,}")
_RX_BYTE = re.compile(r"\\x([0-9a-fA-F]{2})")


def en_claro(tira: str) -> str:
    r"""El texto de una tira \xNN, o vacio si no es texto legible."""
    try:
        crudo = bytes(int(b, 16) for b in _RX_BYTE.findall(tira))
    except ValueError:
        return ""
    txt = crudo.decode("utf-8", "replace").strip("\r\n")
    if not txt.strip():
        return ""
    # SOLO SI ES IMPRIMIBLE ENTERO. Media palabra legible y media basura no
    # es una lectura, es una suposicion: eso se queda sin descifrar.
    if not all(32 <= ord(c) < 127 for c in txt):
        return ""
    return txt


def normaliza(orden: str) -> str:
    t = orden.strip()
    for patron, con in _NORM:
        t = patron.sub(con, t)
    return t


def huella(ordenes) -> str:
    """Huella estable de un conjunto de ordenes normalizadas.

    Va sobre el CONJUNTO ordenado y no sobre la secuencia: el mismo guion
    lanzado con dos ordenes intercambiadas sigue siendo el mismo guion, y
    tratarlo como otro partiria en dos un actor que es uno.
    """
    base = "\n".join(sorted(set(ordenes)))
    return hashlib.sha256(base.encode("utf-8", "replace")).hexdigest()[:12]


# ---------------------------------------------- nuestro propio trafico
#
# EL SENUELO SE HABLA A SI MISMO Y ESO NO ES UN ATAQUE. Al probar Cowrie
# desde la propia VPS, la conexion entra por la puerta de enlace del puente
# de Docker ---172.20.0.1--- y Cowrie la anota como una sesion mas, con sus
# logins y sus ordenes. En el respaldo del 2026-09-11 eran 67 sesiones, 260
# ordenes y LAS 32 entradas con la credencial alyosha: el 100% de esa
# credencial era nuestro, no de nadie de fuera.
#
# El reporter ya lo sabia ---ipguard.py tiene una capa entera para esto y
# por eso nunca ha denunciado a 172.20.0.1--- pero el informe no, y contaba
# nuestras pruebas como actividad de atacantes.
#
# NO SE FILTRA POR LISTA DE IPs sino por rango: una lista se queda vieja en
# cuanto Docker renumera la red, y esto sigue valiendo.
#
# Y NO SE USA is_global, QUE ES LA TRAMPA. Parece lo obvio ---es lo que usa
# ipguard--- pero aqui destroza las pruebas: Python cuenta como privados los
# rangos de DOCUMENTACION (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), y
# el respaldo sintetico de la suite esta hecho con ellos precisamente porque
# es lo correcto en un fichero de pruebas. Con is_global se descartaba el
# fixture entero: 16 pruebas en rojo de golpe.
#
# Lo que se quiere excluir no es "lo no enrutable", es NUESTRA PROPIA RED: el
# senuelo hablando consigo mismo. Eso es RFC1918, loopback y enlace local, y
# nada mas. Un 203.0.113.7 no es nuestro: es un ejemplo, y si alguna vez
# apareciera de verdad seria un dato, no ruido.
_NUESTRAS_REDES = tuple(ipaddress.ip_network(r) for r in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # RFC1918
    "127.0.0.0/8", "::1/128",                          # loopback
    "169.254.0.0/16", "fe80::/10",                     # enlace local
    "fc00::/7",                                        # unicast local IPv6
))


def es_nuestra(ip: str) -> bool:
    """True si la IP es de nuestra propia red, no de internet."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False         # no es una IP: no es cosa nuestra, se deja pasar
    return any(a in r for r in _NUESTRAS_REDES if a.version == r.version)


# ------------------------------------------------------------- el pais
def sin_tildes(t: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFD", t)
                   if unicodedata.category(c) != "Mn")


# LOS NOMBRES DE PAIS, ESCRITOS BIEN Y DE UNA VEZ.
#
# nombres.txt va SIN tildes a proposito (lo comparten los scripts de
# Telegram, que no quieren depender del locale), y antes se le devolvian
# leyendolas de iso-codes. Eso tenia dos pegas: en una maquina sin el
# paquete el informe salia con "Espana" y "Japon", y el propio iso-codes
# trae erratas ("Costa de Marfil" con tilde en la i) y nombres que no son
# los que se usan en castellano ("Algeria", "Burquina Faso"). Un informe
# no puede llevar faltas de ortografia segun donde se genere.
#
# Asi que aqui va la lista entera, revisada a mano. Los codigos son los
# de nombres.txt; la suite comprueba que no falta ninguno.
NOMBRES_PAISES = {
    "AD": "Andorra", "AE": "Emiratos Árabes Unidos", "AF": "Afganistán",
    "AG": "Antigua y Barbuda", "AI": "Anguila", "AL": "Albania",
    "AM": "Armenia", "AO": "Angola", "AP": "Asia-Pacífico",
    "AQ": "Antártida", "AR": "Argentina", "AS": "Samoa Estadounidense",
    "AT": "Austria", "AU": "Australia", "AW": "Aruba",
    "AX": "Islas Åland", "AZ": "Azerbaiyán", "BA": "Bosnia y Herzegovina",
    "BB": "Barbados", "BD": "Bangladés", "BE": "Bélgica",
    "BF": "Burkina Faso", "BG": "Bulgaria", "BH": "Baréin",
    "BI": "Burundi", "BJ": "Benín", "BL": "San Bartolomé",
    "BM": "Bermudas", "BN": "Brunéi", "BO": "Bolivia",
    "BQ": "Caribe Neerlandés", "BR": "Brasil", "BS": "Bahamas",
    "BT": "Bután", "BV": "Isla Bouvet", "BW": "Botsuana",
    "BY": "Bielorrusia", "BZ": "Belice", "CA": "Canadá",
    "CC": "Islas Cocos", "CD": "Rep. Dem. del Congo",
    "CF": "Rep. Centroafricana", "CG": "Congo", "CH": "Suiza",
    "CI": "Costa de Marfil", "CK": "Islas Cook", "CL": "Chile",
    "CM": "Camerún", "CN": "China", "CO": "Colombia", "CR": "Costa Rica",
    "CU": "Cuba", "CV": "Cabo Verde", "CW": "Curazao",
    "CX": "Isla de Navidad", "CY": "Chipre", "CZ": "Chequia",
    "DE": "Alemania", "DJ": "Yibuti", "DK": "Dinamarca", "DM": "Dominica",
    "DO": "República Dominicana", "DZ": "Argelia", "EC": "Ecuador",
    "EE": "Estonia", "EG": "Egipto", "EH": "Sahara Occidental",
    "ER": "Eritrea", "ES": "España", "ET": "Etiopía",
    "EU": "Unión Europea", "FI": "Finlandia", "FJ": "Fiyi",
    "FK": "Islas Malvinas", "FM": "Micronesia", "FO": "Islas Feroe",
    "FR": "Francia", "GA": "Gabón", "GB": "Reino Unido", "GD": "Granada",
    "GE": "Georgia", "GF": "Guayana Francesa", "GG": "Guernsey",
    "GH": "Ghana", "GI": "Gibraltar", "GL": "Groenlandia", "GM": "Gambia",
    "GN": "Guinea", "GP": "Guadalupe", "GQ": "Guinea Ecuatorial",
    "GR": "Grecia", "GS": "Georgias del Sur", "GT": "Guatemala",
    "GU": "Guam", "GW": "Guinea-Bisáu", "GY": "Guyana",
    "HK": "Hong Kong", "HM": "Islas Heard y McDonald", "HN": "Honduras",
    "HR": "Croacia", "HT": "Haití", "HU": "Hungría", "ID": "Indonesia",
    "IE": "Irlanda", "IL": "Israel", "IM": "Isla de Man", "IN": "India",
    "IO": "Terr. Británico del Índico", "IQ": "Irak", "IR": "Irán",
    "IS": "Islandia", "IT": "Italia", "JE": "Jersey", "JM": "Jamaica",
    "JO": "Jordania", "JP": "Japón", "KE": "Kenia", "KG": "Kirguistán",
    "KH": "Camboya", "KI": "Kiribati", "KM": "Comoras",
    "KN": "San Cristóbal y Nieves", "KP": "Corea del Norte",
    "KR": "Corea del Sur", "KW": "Kuwait", "KY": "Islas Caimán",
    "KZ": "Kazajistán", "LA": "Laos", "LB": "Líbano", "LC": "Santa Lucía",
    "LI": "Liechtenstein", "LK": "Sri Lanka", "LR": "Liberia",
    "LS": "Lesoto", "LT": "Lituania", "LU": "Luxemburgo", "LV": "Letonia",
    "LY": "Libia", "MA": "Marruecos", "MC": "Mónaco", "MD": "Moldavia",
    "ME": "Montenegro", "MF": "San Martín", "MG": "Madagascar",
    "MH": "Islas Marshall", "MK": "Macedonia del Norte", "ML": "Malí",
    "MM": "Birmania", "MN": "Mongolia", "MO": "Macao",
    "MP": "Marianas del Norte", "MQ": "Martinica", "MR": "Mauritania",
    "MS": "Montserrat", "MT": "Malta", "MU": "Mauricio", "MV": "Maldivas",
    "MW": "Malaui", "MX": "México", "MY": "Malasia", "MZ": "Mozambique",
    "NA": "Namibia", "NC": "Nueva Caledonia", "NE": "Níger",
    "NF": "Isla Norfolk", "NG": "Nigeria", "NI": "Nicaragua",
    "NL": "Países Bajos", "NO": "Noruega", "NP": "Nepal", "NR": "Nauru",
    "NU": "Niue", "NZ": "Nueva Zelanda", "OM": "Omán", "PA": "Panamá",
    "PE": "Perú", "PF": "Polinesia Francesa", "PG": "Papúa Nueva Guinea",
    "PH": "Filipinas", "PK": "Pakistán", "PL": "Polonia",
    "PM": "San Pedro y Miquelón", "PN": "Islas Pitcairn",
    "PR": "Puerto Rico", "PS": "Palestina", "PT": "Portugal",
    "PW": "Palaos", "PY": "Paraguay", "QA": "Catar", "RE": "Reunión",
    "RO": "Rumanía", "RS": "Serbia", "RU": "Rusia", "RW": "Ruanda",
    "SA": "Arabia Saudí", "SB": "Islas Salomón", "SC": "Seychelles",
    "SD": "Sudán", "SE": "Suecia", "SG": "Singapur", "SH": "Santa Elena",
    "SI": "Eslovenia", "SJ": "Svalbard y Jan Mayen", "SK": "Eslovaquia",
    "SL": "Sierra Leona", "SM": "San Marino", "SN": "Senegal",
    "SO": "Somalia", "SR": "Surinam", "SS": "Sudán del Sur",
    "ST": "Santo Tomé y Príncipe", "SV": "El Salvador",
    "SX": "Sint Maarten", "SY": "Siria", "SZ": "Esuatini",
    "TC": "Islas Turcas y Caicos", "TD": "Chad",
    "TF": "Terr. Australes Franceses", "TG": "Togo", "TH": "Tailandia",
    "TJ": "Tayikistán", "TK": "Tokelau", "TL": "Timor Oriental",
    "TM": "Turkmenistán", "TN": "Túnez", "TO": "Tonga", "TR": "Turquía",
    "TT": "Trinidad y Tobago", "TV": "Tuvalu", "TW": "Taiwán",
    "TZ": "Tanzania", "UA": "Ucrania", "UG": "Uganda",
    "UM": "Islas Ultramarinas de EE. UU.", "US": "Estados Unidos",
    "UY": "Uruguay", "UZ": "Uzbekistán", "VA": "Vaticano",
    "VC": "San Vicente y las Granadinas", "VE": "Venezuela",
    "VG": "Islas Vírgenes Británicas", "VI": "Islas Vírgenes de EE. UU.",
    "VN": "Vietnam", "VU": "Vanuatu", "WF": "Wallis y Futuna",
    "WS": "Samoa", "YE": "Yemen", "YT": "Mayotte", "ZA": "Sudáfrica",
    "ZM": "Zambia", "ZW": "Zimbabue",
}


def bandera(cc: str) -> str:
    """Bandera a partir del codigo ISO 3166-1 alfa-2.

    Se construye con los dos indicadores regionales, no con una tabla: vale
    para cualquier pais sin mantener nada. Un codigo que no sean dos letras
    devuelve la bandera negra, que se ve raro a proposito ---es mejor que
    ensenar la bandera equivocada---.
    """
    cc = (cc or "").strip().upper()
    if len(cc) != 2 or not cc.isalpha():
        return "\U0001F3F4"
    return chr(0x1F1E6 + ord(cc[0]) - 65) + chr(0x1F1E6 + ord(cc[1]) - 65)


class Geo:
    """Pais de una IP, si hay tablas. Si no las hay, se calla y se dice.

    Las tablas son DATOS GENERADOS y no estan en el repositorio (son 17 MB
    que se rehacen cada quince dias), asi que aqui se buscan en los sitios
    donde pueden estar en vez de exigir que te acuerdes de pasar --geoip.
    """

    CANDIDATOS = (
        os.path.join(REPO, "TELEGRAM SCRIPTS", "geoip"),
        "/opt/dirtyland/geoip",
        os.path.expanduser("~/.dirtyland/geoip"),
    )

    def __init__(self, dirtorio: str | None):
        self.activo = False
        self.donde = ""
        self._codigo = None
        self._cache: dict[str, str] = {}
        self._nombres = None
        # SI SE PASA --geoip, MANDA: si ahi no hay tablas, no se buscan en
        # otro sitio. Caer al siguiente candidato en silencio significaria
        # usar unas tablas que no son las que se pidieron ---y probablemente
        # mas viejas--- sin decirlo. Ademas deja la prueba determinista: sin
        # esto, el resultado dependia de si la maquina tenia tablas sueltas.
        candidatos = [dirtorio] if dirtorio else list(self.CANDIDATOS)
        for cand in candidatos:
            if not cand or not os.path.isdir(cand):
                continue
            try:
                ruta_py = os.path.join(REPO, "TELEGRAM SCRIPTS", "geoip")
                if ruta_py not in sys.path:
                    sys.path.insert(0, ruta_py)
                os.environ["DIRTYLAND_GEOIP"] = cand
                import paises                          # noqa: PLC0415
                importlib.reload(paises)
                if paises.codigo("8.8.8.8"):
                    self._codigo = paises.codigo
                    self.activo = True
                    self.donde = cand
                    break
            except Exception:                          # noqa: BLE001
                continue

    def cc(self, ip: str) -> str:
        if not self.activo:
            return ""
        if ip in self._cache:
            return self._cache[ip]
        try:
            v = (self._codigo(ip) or "").upper()
        except Exception:                              # noqa: BLE001
            v = ""
        # Con miles de IPs y varias tablas que se consultan por busqueda
        # binaria sobre fichero, repetir la consulta sale caro. Cada IP sale
        # en el resumen, en su guion y en las TTPs.
        self._cache[ip] = v
        return v

    def _iso_codes(self):
        """Nombres CON TILDE, del paquete iso-codes del sistema.

        nombres.txt los guarda SIN tildes y es una decision deliberada del
        generador: los scripts de Telegram corren desde cron y no quieren
        depender del locale con el que arranque. Aqui no aplica ---esto
        escribe un HTML declarado en UTF-8--- y "Sudafrica" o "Espana" en un
        informe cantan.
        
        Asi que se leen de la MISMA fuente que usa el generador en vez de
        mantener una lista de tildes a mano, que se quedaria corta en cuanto
        apareciera un pais nuevo. Si el paquete no esta, se sigue con
        nombres.txt y no pasa nada.
        """
        try:
            import gettext
            datos = json.load(open("/usr/share/iso-codes/json/iso_3166-1.json",
                                   encoding="utf-8"))
            tr = gettext.translation("iso_3166-1", "/usr/share/locale",
                                     languages=["es"])
            return {x["alpha_2"]: tr.gettext(x["name"])
                    for x in datos["3166-1"] if x.get("alpha_2")}
        except Exception:                              # noqa: BLE001
            return {}

    def nombre(self, cc: str) -> str:
        """'ES' -> 'Espana'. De nombres.txt, que SI esta en el repositorio
        (es la lista ISO entera, no un dato derivado), asi que vale aunque
        no haya tablas de geolocalizacion."""
        if self._nombres is None:
            # DOS FUENTES Y UNA REGLA PARA MEZCLARLAS.
            #
            # iso-codes da el nombre OFICIAL y con tildes ("Federación
            # Rusa"); nombres.txt da el que el proyecto eligio a mano, mas
            # corto y sin tildes ("Rusia"). Se quiere lo corto Y con tildes.
            #
            # La regla: si el nombre corto es el oficial al que le han
            # quitado las tildes, se le devuelven; si es OTRO nombre
            # ---porque alguien lo acorto a proposito--- manda el corto.
            # Asi los ~220 normales salen con tilde solos y los treinta
            # acortados no se pierden.
            oficial = self._iso_codes()
            self._nombres = {}
            for k, v in oficial.items():
                self._nombres[k] = v
            for base in (os.path.join(REPO, "TELEGRAM SCRIPTS", "geoip"),
                         self.donde or ""):
                ruta = os.path.join(base, "nombres.txt") if base else ""
                if ruta and os.path.exists(ruta):
                    try:
                        with open(ruta, encoding="utf-8") as fh:
                            for linea in fh:
                                if linea.startswith("#") or " " not in linea:
                                    continue
                                k, v = linea.rstrip("\n").split(" ", 1)
                                ofi = self._nombres.get(k)
                                if ofi is None or sin_tildes(ofi) != v:
                                    # Nombre acortado a mano: manda el corto.
                                    self._nombres[k] = v
                        break
                    except OSError:
                        pass
            # Y por encima de todo, la lista revisada: es la que manda.
            self._nombres.update(NOMBRES_PAISES)
        return self._nombres.get((cc or "").upper(), cc)

    def etiqueta(self, ip: str) -> str:
        """'ES 🇪🇸' o '' si no se sabe. Bandera SIEMPRE con su codigo al lado:
        la bandera sola no se distingue bien en pantallas pequenas y hay
        pares que se parecen mucho."""
        c = self.cc(ip)
        return ("%s %s" % (c, bandera(c))) if c else ""


# ------------------------------------------------------- leer el respaldo
def busca(raiz: str, *patrones) -> list[str]:
    """Primer patron que encuentra algo, ya ordenado. Lista vacia si nada."""
    for patron in patrones:
        hallado = sorted(glob.glob(os.path.join(raiz, patron), recursive=True))
        if hallado:
            return hallado
    return []


class Fuentes:
    """Donde esta cada cosa dentro del respaldo, y que falta.

    Se busca con comodines en vez de escribir las rutas: el respaldo puede
    venir de un `tar -C /` (y entonces cuelga de var/ y opt/) o de una
    carpeta que alguien ha movido. Lo que NO se hace es adivinar en silencio:
    lo que no aparece se dice en la primera seccion del informe.
    """

    def __init__(self, raiz: str):
        self.raiz = raiz
        self.cowrie_log = busca(raiz, "**/log/cowrie/cowrie.json*",
                                "**/cowrie.json*")
        self.cowrie_dl = busca(raiz, "**/lib/cowrie/downloads",
                               "**/downloads")
        self.dionaea_db = busca(raiz, "**/dionaea.sqlite*")
        self.dionaea_bin = busca(raiz, "**/lib/dionaea/binaries", "**/binaries")
        self.estado_rep = busca(raiz, "**/dirtyland-reporter/state.sqlite3")
        self.memoria = busca(raiz, "**/cowrie_telegram_state.json")
        # EL ORIGEN DE CADA BANEO SOLO VIVE AQUI. La memoria del bot guarda
        # "banned" como una lista plana; quien sabe si un baneo fue automatico
        # o a mano es el COMENTARIO del elemento en nftables. Si el respaldo
        # no trae el volcado, el informe lo dice en vez de inventarse un
        # reparto.
        self.nft = busca(raiz, "**/nftables-ruleset*", "**/nft-ruleset*",
                         "**/nftables.dump", "**/nftables.conf")

    def filas(self):
        return [
            ("Sesiones de Cowrie", "cowrie.json*", self.cowrie_log),
            ("Malware de Cowrie", "lib/cowrie/downloads/", self.cowrie_dl),
            ("Eventos de Dionaea", "dionaea.sqlite", self.dionaea_db),
            ("Malware de Dionaea", "lib/dionaea/binaries/", self.dionaea_bin),
            ("Estado del reporter", "state.sqlite3", self.estado_rep),
            ("Memoria del bot", "cowrie_telegram_state.json", self.memoria),
            ("Reglas del cortafuegos", "nftables-ruleset", self.nft),
        ]


# ------------------------------------------------- el origen de un baneo
#
# nft escribe cada elemento del conjunto con su comentario, y el guion de
# baneo pone uno distinto segun quien lo ordene:
#
#   auto)   "IP BANEADA COWRIE AUTOMATICO"
#   manual) "IP BANEADA COWRIE MANUAL DESDE TELEGRAM"
#
# Se busca "MANUAL" y no la cadena entera porque la etiqueta ya cambio una vez
# ---lo cuenta telegram-notification-ban--- y lo que lleve la vieja se
# reconoce como "de antes, y de origen desconocido", que es justo lo que hay
# que poder distinguir de un automatico de verdad.
_RE_NFT = re.compile(
    r"((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,})\s+comment\s+\"([^\"]*)\"")


def origen_de_baneos(rutas):
    """{ip: "manual"|"auto"|"desconocido"} leyendo el volcado de nftables."""
    origen = {}
    for ruta in rutas or []:
        try:
            with open(ruta, encoding="utf-8", errors="replace") as fh:
                texto = fh.read()
        except OSError:
            continue
        for ip, com in _RE_NFT.findall(texto):
            c = com.upper()
            if "MANUAL" in c:
                origen[ip] = "manual"
            elif "AUTOMATICO" in c or "AUTO" in c:
                origen[ip] = "auto"
            else:
                origen[ip] = "desconocido"
    return origen


# -------------------------------------------------------------- sesiones
class Sesion:
    __slots__ = ("id", "ip", "protocolo", "inicio", "fin", "ordenes",
                 "creds_ok", "creds_mal", "muestras", "cliente", "hassh",
                 "duracion")

    def __init__(self, sid):
        self.id = sid
        self.ip = ""
        self.protocolo = ""
        self.inicio = None
        self.fin = None
        self.ordenes = []
        self.creds_ok = []
        self.creds_mal = []
        self.muestras = []
        # LO QUE EL ATACANTE NO ELIGE. El guion de ordenes lo escribe el;
        # la version del cliente y el HASSH los pone su HERRAMIENTA al
        # negociar, antes de teclear nada. Dos IPs con el mismo HASSH
        # corren el mismo binario aunque hagan cosas distintas, y eso no se
        # puede disimular sin recompilar.
        self.cliente = ""
        self.hassh = ""
        self.duracion = None


# ---------------------------------------------------------------- progreso
#
# SIN ESTO PARECE UN CUELGUE. Un cowrie.json de varios cientos de MB son
# millones de lineas y json.loads sobre cada una tarda minutos. La primera
# version no escribia nada hasta el final, y lo primero que hizo quien la
# uso fue cortarla con Ctrl-C creyendo que se habia colgado --- con razon:
# un programa que no dice nada durante cinco minutos no se distingue de uno
# parado.
#
# Va a stderr para no mezclarse con nada, y se calla si la salida no es un
# terminal (un cron o una tuberia no quieren una barra de progreso).
# La linea que se reescribe sobre si misma solo tiene sentido en un terminal:
# en un fichero o en una tuberia, los "\r" salen como basura. Ahi se callan
# los avances y se dejan solo los hitos.
_TERMINAL = sys.stderr.isatty()


_ANCHO = [0]


def paso(texto, fin=False):
    if not fin and not _TERMINAL:
        return
    # Se rellena con espacios hasta tapar lo que hubiera escrito antes. Sin
    # esto, un hito corto detras de una linea de avance larga deja la cola de
    # la anterior pegada detras y se lee una sola linea con dos mensajes.
    relleno = " " * max(0, _ANCHO[0] - len(texto))
    _ANCHO[0] = 0 if fin else len(texto)
    print(texto + relleno, file=sys.stderr, flush=True,
          end=("\n" if fin else "\r"))


def lee_cowrie(ficheros, tz):
    """cowrie.json* -> sesiones, y los descartes contados.

    Las lineas ilegibles NO se tragan en silencio: se cuentan y el informe lo
    dice. Un log a medias es informacion ---suele significar que el respaldo
    se hizo en caliente--- y callarlo convierte un recuento incompleto en uno
    que parece completo.
    """
    sesiones: dict[str, Sesion] = {}
    rotas = 0
    propias_ev = propias_cmd = 0
    propias_ips = set()
    propias_ses = set()
    lineas = 0
    total = sum(os.path.getsize(x) for x in ficheros if os.path.isfile(x))
    paso("leyendo las sesiones: %s, %.0f MB en total"
         % (cuantos(len([x for x in ficheros if os.path.isfile(x)]),
                    "fichero", "ficheros"), total / 1048576.0),
         fin=True)
    for n_f, ruta in enumerate(ficheros, 1):
        if os.path.isdir(ruta):
            continue
        try:
            fh = open(ruta, encoding="utf-8", errors="replace")
        except OSError:
            continue
        corto = os.path.basename(ruta)
        with fh:
            for linea in fh:
                if lineas and lineas % 100000 == 0:
                    paso("  [%d/%d] %-28s %8.1fM líneas, %d sesiones   "
                         % (n_f, len(ficheros), corto[:28], lineas / 1e6,
                            len(sesiones)))
                linea = linea.strip()
                if not linea:
                    continue
                lineas += 1
                try:
                    ev = json.loads(linea)
                except ValueError:
                    rotas += 1
                    continue
                # ANTES DE CREAR LA SESION, no despues: si se filtra luego
                # queda una sesion fantasma, creada por algun evento sin
                # src_ip y sin nada dentro, que se cuela en el recuento.
                ip = ev.get("src_ip")
                if ip and es_nuestra(ip):
                    propias_ev += 1
                    propias_ips.add(ip)
                    if ev.get("session"):
                        propias_ses.add(ev["session"])
                    if ev.get("eventid", "") in ("cowrie.command.input",
                                                 "cowrie.command.failed"):
                        propias_cmd += 1
                    continue
                sid = ev.get("session") or ip or "?"
                s = sesiones.get(sid)
                if s is None:
                    s = sesiones[sid] = Sesion(sid)
                if ip:
                    s.ip = ip
                if ev.get("protocol"):
                    s.protocolo = ev["protocol"]
                ts = parse_timestamp(ev.get("timestamp"), tz)
                if ts:
                    if s.inicio is None or ts < s.inicio:
                        s.inicio = ts
                    if s.fin is None or ts > s.fin:
                        s.fin = ts
                eid = ev.get("eventid", "")
                if eid in ("cowrie.command.input", "cowrie.command.failed"):
                    orden = (ev.get("input") or "").strip()
                    if orden:
                        s.ordenes.append(orden)
                elif eid == "cowrie.login.success":
                    s.creds_ok.append("%s:%s" % (ev.get("username", ""),
                                                 ev.get("password", "")))
                elif eid == "cowrie.login.failed":
                    s.creds_mal.append("%s:%s" % (ev.get("username", ""),
                                                  ev.get("password", "")))
                elif eid == "cowrie.client.version":
                    s.cliente = (ev.get("version") or "").strip()
                elif eid == "cowrie.client.kex":
                    s.hassh = (ev.get("hassh") or "").strip()
                elif eid == "cowrie.session.closed":
                    d = ev.get("duration_ms")
                    if isinstance(d, (int, float)):
                        s.duracion = float(d)
                elif eid in ("cowrie.session.file_download",
                             "cowrie.session.file_upload"):
                    sha = (ev.get("shasum") or "").strip().lower()
                    if sha:
                        s.muestras.append((sha, (ev.get("url") or "").strip(),
                                           eid.rsplit(".", 1)[-1]))
    paso("  leídas %s, %s%s"
         % (cuantos(lineas, "línea", "líneas"),
            cuantos(len(sesiones), "sesión", "sesiones"),
            (", %s" % cuantos(rotas, "ilegible", "ilegibles")) if rotas else ""), fin=True)
    return (sesiones, lineas, rotas,
            (len(propias_ses), propias_cmd, sorted(propias_ips)))


# ------------------------------------------------------------------ TTPs
def lee_ttp(ruta):
    """ttp.tsv -> [(id, nombre, regex compilada, nota)]. Las malas se dicen."""
    filas, malas = [], []
    if not os.path.exists(ruta):
        return filas, ["no existe %s" % ruta]
    with open(ruta, encoding="utf-8") as fh:
        for n, linea in enumerate(fh, 1):
            linea = linea.rstrip("\n")
            if not linea.strip() or linea.lstrip().startswith("#"):
                continue
            campos = linea.split("\t")
            if len(campos) < 3:
                malas.append("línea %d: menos de tres columnas" % n)
                continue
            tid, nombre, patron = campos[0], campos[1], campos[2]
            nota = campos[3] if len(campos) > 3 else ""
            try:
                rx = re.compile(patron, re.I)
            except re.error as exc:
                malas.append("línea %d (%s): patrón inválido, %s" % (n, tid, exc))
                continue
            filas.append((tid.strip(), nombre.strip(), rx, nota.strip()))
    return filas, malas


# -------------------------------------------------------------- utilidades
# ============================================================ el HTML
#
# POR QUE HTML Y NO MARKDOWN. El informe acaba en el documento principal, y
# una tabla de Markdown pegada en un procesador de textos llega como un
# churro de barras verticales. Pegada desde el navegador llega como TABLA.
# Ademas se abre de un doble clic en Linux y en Windows sin instalar nada.
#
# Va todo en un solo fichero ---el CSS dentro, sin imagenes ni fuentes de
# fuera--- porque un informe que depende de la red es un informe que dentro
# de un ano no se ve igual.
ESTILO = """
:root { color-scheme: light;
        /* EL ALTO DE LA BANDA DE h2, que se pega arriba al bajar.
           Lo necesitan DOS reglas ---la banda y las cabeceras de tabla, que
           se pegan justo debajo--- y tienen que moverse juntas: si se
           tocan los 13px de relleno del h2 y no esto, las cabeceras se
           meten por debajo de la banda y se comen la primera fila.
           26 de relleno + 21 de cuerpo por 1.6 de interlineado = 60. */
        --banda: 60px;
        /* 10 de relleno + 14.5 de cuerpo por 1.6 de interlineado = 33.2 */
        --sub: 34px; }
* { box-sizing: border-box; }
body { margin: 0; background: #f6f7f9; color: #15181d;
       font: 15px/1.6 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
       /* HACEN FALTA LOS DOS, html y body, y no es redundante: el
          desbordamiento del elemento raiz SE PROPAGA al viewport, asi que
          html se queda en la practica en "visible" y no recorta nada ---se
          midio: 8px de sobra---. Lo que hace el de html es impedir que el
          de body se propague a su vez, y entonces body si recorta. */
       overflow-x: clip; }
/* main NO SE TOCA. Estrechar main y devolver la anchura hijo a hijo se
   probo y sale mal: .aviso, .indice, .tarjetas, .pie y .datos declaran su
   propio margen con selector de CLASE (0,1,0), que gana siempre a un
   "main > *" (0,0,2). Los hijos sin clase se centraban y los que tenian
   clase se quedaban a la izquierda. Se escapa solo el h2, abajo. */
html { overflow-x: clip; }              /* ver la nota en body */
main { max-width: 1180px; margin: 0 auto; padding: 32px 24px 96px; }
h1 { font-size: 30px; margin: 0 0 4px; letter-spacing: -.02em; }
h2 { font-size: 21px; font-weight: 600;
     /* LA BANDA A SANGRE, Y EL TEXTO EN SU COLUMNA.
        El margen negativo (50% - 50vw) lleva cada borde del h2 al borde de
        la ventana; el relleno (50vw - 50%) es su inverso exacto, asi que
        devuelve el texto justo a donde lo tiene main. Al ser el uno el
        negativo del otro, cuadran solos en cualquier anchura, tambien
        cuando main ya no se centra porque la ventana es estrecha.
        100vw incluye la barra de desplazamiento vertical ---que este
        informe siempre tiene--- y la banda sobresale ~15px. Se recorta con
        overflow-x: clip en html, que NO crea contenedor de scroll y por
        tanto no rompe el position: sticky de las cabeceras de tabla;
        overflow-x: hidden si lo habria roto. */
     /* SE QUEDA ARRIBA AL BAJAR. No hay efecto de EMPUJE ---el titulo
        saliente no lo levanta el entrante--- porque para eso cada apartado
        tendria que ir en su propio contenedor, y aqui no puede: los
        conmutadores y el ordenador de paises funcionan con selectores de
        HERMANO (~), y meterlos en cajas los romperia. Lo que hay es
        RELEVO: al llegar arriba, el titulo nuevo tapa al anterior, que
        ademas casan porque miden lo mismo y el fondo es opaco.
        z-index 3 para quedar por encima de las cabeceras de tabla (2). */
     position: sticky; top: 0; z-index: 3;
     display: flex; align-items: center;
     margin: 46px calc(50% - 50vw) 14px;
     padding: 13px calc(50vw - 50%);
     /* Sitio para el boton, que va fijo encima de la banda: sin esto, un
        titulo largo se le mete debajo en pantallas estrechas. */
     padding-right: calc(50vw - 50% + 46px);
     border-radius: 0; letter-spacing: -.01em;
     /* EL TEXTO VA OSCURO Y NO BLANCO. El degradado acaba en amarillo, y
        los titulos largos ---"9. INFERIDO - a escribir a mano"--- llegan
        hasta ese extremo, donde el blanco no se lee. El marron oscuro
        contrasta sobre todo el recorrido, del naranja al amarillo. */
     color: #3d1f00;
     background: linear-gradient(90deg, #f97316 0%, #fbbf24 58%, #fde047 100%);
     /* Sin esto los navegadores tiran los fondos al imprimir y el titulo
        sale como texto suelto sobre blanco. */
     -webkit-print-color-adjust: exact; print-color-adjust: exact; }
/* LA FRANJA DE LOS SUBAPARTADOS. Mismo comportamiento que la banda de los
   apartados ---a sangre, pegada al bajar y relevada por la siguiente---
   pero fina y en gris, que es un segundo nivel y no puede competir con el
   naranja. Se pega DEBAJO de la banda, en --banda, y las cabeceras de
   tabla bajan a --banda + --sub para no meterse debajo de ninguna de las
   dos. Blanco sobre #5f6875 son 6.1:1 de contraste, de sobra. */
h3 { font-size: 14.5px; font-weight: 600; color: #fff;
     background: #5f6875; letter-spacing: .01em;
     margin: 28px calc(50% - 50vw) 10px;
     padding: 5px calc(50vw - 50%);
     position: sticky; top: var(--banda); z-index: 3;
     -webkit-print-color-adjust: exact; print-color-adjust: exact; }
/* UN TITULO YA RELEVADO SE DESPEGA: lo marca el guion de abajo. Sin el, al
   entrar en un apartado nuevo seguia viendose colgada la ultima franja del
   anterior, y en un movil una banda de dos lineas asomaba por debajo de la
   de una linea que la habia relevado. */
h2.fuera, h3.fuera { position: static; }
/* EN UN MOVIL, MENOS LETRA EN LAS BANDAS. Pegadas arriba, banda, franja y
   cabecera de tabla se comen pantalla; con el cuerpo de escritorio, ademas,
   mas titulos se parten en dos lineas. */
@media (max-width: 640px) {
  h2 { font-size: 18px; padding-top: 10px; padding-bottom: 10px; }
  h3 { font-size: 13.5px; }
}
p { margin: 10px 0; }
.sub { color: #5d6673; margin-bottom: 26px; }
table { border-collapse: collapse; width: 100%; margin: 12px 0 4px;
        background: #fff; font-size: 14px;
        box-shadow: 0 1px 2px rgba(16,22,30,.06); }
th, td { padding: 7px 10px; text-align: left; border-bottom: 1px solid #e8ebef;
         vertical-align: top; }
th { background: #eef1f5; font-weight: 600; font-size: 13px;
     /* DEBAJO DE LA BANDA, no en lo alto de la ventana: con top: 0 las dos
        se pegaban en el mismo sitio y la banda tapaba la cabecera, que es
        justo la fila que hay que poder leer mientras se recorre la tabla
        de guiones o la de IPs. */
     position: sticky; top: calc(var(--banda) + var(--sub)); z-index: 2; }
/* Si no hay ninguna franja gris colgada, las cabeceras suben a ras de la
   banda naranja. Lo pone el guion; sin el se queda el hueco de 34px, que es
   feo pero no rompe nada. */
body.sin-sub th { top: var(--banda); }
tr:last-child td { border-bottom: 0; }
tbody tr:hover { background: #fafbfc; }
td.n, th.n { text-align: right; font-variant-numeric: tabular-nums;
             white-space: nowrap; }
code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas,
              monospace; font-size: 12.5px; }
code { background: #eef1f5; padding: 1px 5px; border-radius: 3px; }
pre { background: #1d2330; color: #e6edf3; padding: 14px 16px; overflow-x: auto;
      border-radius: 6px; font-family: ui-monospace, Menlo, Consolas, monospace;
      font-size: 12.5px; line-height: 1.55; margin: 8px 0 18px; }
.aviso { border-left: 4px solid #c48a12; background: #fdf7e7; padding: 10px 14px;
         margin: 14px 0; border-radius: 0 4px 4px 0; }
.malo { border-left-color: #b3261e; background: #fdeceb; }
.ok { border-left-color: #2f7d3a; background: #eef7ef; }
.nota { color: #5d6673; font-size: 13.5px; }
.tarjetas { display: grid; gap: 12px; margin: 16px 0 6px;
            grid-template-columns: repeat(auto-fill, minmax(148px, 1fr)); }
.t { background: #fff; border: 1px solid #e2e6ec; border-radius: 8px;
     padding: 12px 16px; }
.t b { display: block; font-size: 24px; font-variant-numeric: tabular-nums;
       letter-spacing: -.02em; }
.t span { color: #5d6673; font-size: 12.5px; }
.hue { color: #5d6673; font-size: 12px; }
.conm > .v { display: none; }
.conm input, .orden input { position: absolute; opacity: 0;
                            pointer-events: none; }
.conm label, .orden label { display: inline-block; padding: 5px 12px; margin: 0 6px 10px 0;
               border: 1px solid #d5dae1; border-radius: 999px; cursor: pointer;
               font-size: 13px; color: #48505c; background: #fff;
               user-select: none; }
.conm label:hover, .orden label:hover { border-color: #9aa3ae; }
.conm input:checked + label, .orden input:checked + label {
    background: #1f5f9e; border-color: #1f5f9e; color: #fff; }
.paises { display: grid; grid-auto-flow: column; gap: 0 26px;
          grid-template-rows: repeat(var(--filas), auto);
          margin: 4px 0 2px; }
/* TRES COLUMNAS NO CABEN SIEMPRE. Con el reparto fijo, por debajo de unos
   990px las filas se salian y el documento entero sacaba barra horizontal
   ---277 elementos desbordaban, medido---. Al pasar a reparto por filas se
   pierde el orden "hacia abajo y luego a la derecha", pero la lista se lee;
   lo otro no. */
@media (max-width: 1000px) {
  .paises { grid-auto-flow: row; grid-template-rows: none;
            grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 640px) {
  .paises { grid-template-columns: minmax(0, 1fr); }
}
/* Y LAS TABLAS ANCHAS, QUE ROMPAN. La de malware son nueve columnas y no
   cabe por debajo de unos 1000px: los hashes y las URLs son fichas sin
   espacios y no tienen por donde partir. Como el documento RECORTA el
   desbordamiento horizontal ---hace falta para que las bandas a sangre no
   saquen barra, ver overflow-x: clip--- lo que se salia no se podia
   desplazar: se PERDIA. Partido por medio de un hash es feo, pero se lee. */
@media (max-width: 1100px) {
  td { overflow-wrap: anywhere; }
}
/* EN UN MOVIL ESO NO BASTA. Partir por cualquier sitio deja columnas de
   una letra ("Captu-ras", hashes en cinco trozos) y, aun asi, la tabla de
   guiones seguia saliendose y la ultima columna se PERDIA. Aqui cada tabla
   se desliza de lado dentro de su caja, como en GitHub, y las palabras
   vuelven a partirse solo por los espacios. Lo que se pierde es que la
   cabecera de la tabla se quede pegada: un elemento que desplaza de lado
   pasa a ser el contenedor del pegado, y ya no se pegaria a la ventana. */
@media (max-width: 640px) {
  table { display: block; max-width: 100%; overflow-x: auto; }
  td { overflow-wrap: normal; }
  th { position: static; }
}
.pa { display: flex; align-items: baseline; gap: 8px; padding: 2px 0;
      font-size: 13.5px; border-bottom: 1px solid #f0f2f5; }
.pa .nom { flex: 1; order: 1; white-space: nowrap; overflow: hidden;
           text-overflow: ellipsis; color: #48505c; }
/* Las dos cifras nacen IGUALES y discretas; despues se asciende la que
   manda. Asi no hay que deshacer estilos en cada modo, que es de donde
   salen las inconsistencias. */
.pa b { font-variant-numeric: tabular-nums; font-weight: 400; font-size: 12px;
        color: #909aa6; min-width: 58px; text-align: right; }
/* LA INSIGNIA DE POSICION. El numero se pinta DESDE LA VARIABLE que ya
   llevaba la fila para reordenarse: counter-reset acepta un custom property
   y counter() lo escribe. Por eso no hubo que tocar el marcado ni repetir
   el dato tres veces.
   LA COLUMNA NO SE MUEVE: order 0, por delante del nombre (1) y de las dos
   cifras (2 y 3), que si se intercambian segun el orden elegido. El #1 se
   queda arriba a la izquierda, el #2 debajo, y lo que viaja es el pais.
   El azul va algo mas hondo que un celeste puro: sobre #38bdf8 el blanco
   se lee mal a cuerpo 11. */
.pa::before { counter-reset: pos var(--a); content: "#" counter(pos);
              order: 0; flex: none; box-sizing: border-box; min-width: 38px;
              padding: 1px 5px; border: 1px solid #fff; border-radius: 999px;
              background: #0ea5e9; color: #fff; font-size: 11px;
              font-weight: 600; font-variant-numeric: tabular-nums;
              text-align: center; line-height: 1.5;
              -webkit-print-color-adjust: exact; print-color-adjust: exact; }
#op-cmd:checked ~ .paises .pa::before { counter-reset: pos var(--c); }
#op-ips:checked ~ .paises .pa::before { counter-reset: pos var(--i); }
#op-ips:checked ~ .paises .pa { order: var(--i); }
#op-cmd:checked ~ .paises .pa { order: var(--c); }
#op-abc:checked ~ .paises .pa { order: var(--a); }
/* Quien ordena, manda: pasa a la segunda columna y se pone en negro. */
#op-abc:checked ~ .paises .nom { font-weight: 600; color: #15181d; }
#op-abc:checked ~ .paises .c-ips { order: 2; }
#op-abc:checked ~ .paises .c-cmd { order: 3; }
#op-ips:checked ~ .paises .c-ips { order: 2; font-weight: 600;
                                   font-size: 13.5px; color: #15181d; }
#op-ips:checked ~ .paises .c-cmd { order: 3; }
#op-cmd:checked ~ .paises .c-cmd { order: 2; font-weight: 600;
                                   font-size: 13.5px; color: #15181d; }
#op-cmd:checked ~ .paises .c-ips { order: 3; }
@media print { .orden label, .conm label { display: none; }
               .conm > .v { display: block; } }
ul.datos { margin: 8px 0 14px; padding-left: 20px; }
ul.datos li { margin: 3px 0; }
ul.datos li b { color: #15181d; }
p.pie { margin: 4px 0 12px; color: #5d6673; font-size: 13.5px; }
h3 + p, h3 + ul.datos { margin-top: 6px; }
ul.indice { margin: 14px 0; padding-left: 20px; }
ul.indice > li { margin-bottom: 12px; }
ul.indice > li > b { font-size: 15px; }
ul.indice ul { margin: 4px 0 0; padding-left: 18px; color: #48505c;
               font-size: 13.5px; }
ul.indice ul li { margin: 3px 0; }
/* EL BOTON TIENE QUE VERSE. Era un rectangulo blanco con borde gris claro
   sobre un fondo casi blanco: se camuflaba y las ordenes de cada guion
   ---que son de lo mas interesante del informe--- pasaban desapercibidas.
   Lleva el naranja de las bandas, que ya es el color con el que este
   documento marca lo que separa y lo que se pulsa, y va CENTRADO para que
   no se confunda con el texto corrido que tiene encima y debajo. */
details { margin: 14px 0 22px; text-align: center; }
summary { cursor: pointer; display: inline-block; padding: 9px 20px;
          border: 0; border-radius: 999px; font-size: 13.5px;
          font-weight: 600; color: #3d1f00; user-select: none;
          background: linear-gradient(90deg, #f97316 0%, #fbbf24 60%,
                                       #fde047 100%);
          box-shadow: 0 1px 4px rgba(120,60,0,.28);
          -webkit-print-color-adjust: exact; print-color-adjust: exact; }
/* La flecha dice que se abre, y al abrirse se da la vuelta. El display:
   inline-block del summary se lleva por delante el triangulo nativo, asi
   que sin esto no habria ninguna senal de que aquello despliega algo. */
summary::after { content: "▾"; display: inline-block; margin-left: 9px;
                 font-size: 11px; transition: transform .12s; }
summary:hover { filter: brightness(1.06); }
/* El codigo de dentro, en blanco translucido: el gris de fuera sobre el
   naranja parecia un recuadro pegado. */
summary code { background: rgba(255,255,255,.62); color: #3d1f00; }
details[open] summary { margin-bottom: 12px; }
details[open] summary::after { transform: rotate(180deg); }
/* El centrado es del BOTON, no de las ordenes: un listado de comandos
   centrado es ilegible. */
details pre { margin-top: 0; text-align: left; }
@media print { details { display: none; } }
figure { margin: 18px 0 8px; background: #fff; border: 1px solid #e2e6ec;
         border-radius: 8px; padding: 16px 18px 10px; }
figcaption { color: #5d6673; font-size: 13px; margin-top: 8px; }
figure svg { display: block; }
/* DE QUE SENUELO HABLA LA FIGURA. Tres franjas iguales, y NO hablan del
   mismo conjunto: la primera es de los dos senuelos y las otras dos solo de
   Cowrie. Sin decirlo hay que deducirlo sumando las cifras de la leyenda,
   que es justo lo que una figura tiene que ahorrar. Va ARRIBA y no de pie
   de foto: se lee antes de mirar la barra, no despues. */
.ambito { margin: 0 0 14px; padding-bottom: 12px; font-size: 12.5px;
          line-height: 1.7; color: #5d6673;
          border-bottom: 1px solid #eef1f5; }
/* En linea y no en flex: con flex, cada trozo de texto suelto y cada <b>
   serian un elemento mas de la fila y la frase se partiria en cachos. */
.ambito > span { display: inline-block; margin-right: 7px; padding: 2px 10px;
                 background: #eef2f7; border: 1px solid #dbe2ea;
                 border-radius: 999px; color: #15181d; font-weight: 600; }
.ambito b { color: #38404d; }
/* Los globos de las figuras. Las reglas que los ENSENAN se generan con la
   figura (ver globo()); esto es solo el aspecto.
   LOS NOMBRES "gf" Y "gg" SON FEOS A PROPOSITO. Nacieron como .s y .t, y
   el informe YA usaba .t para las tarjetas del resumen: ".t { opacity: 0 }"
   dejo invisibles las diez cifras de cabecera, con el marcado impecable y
   sin un solo error por ningun lado. Un nombre de clase es CODIGO, y en un
   documento de un solo fichero el espacio de nombres es COMUN. La suite lo
   comprueba ahora ("las clases de los globos no chocan...").
   pointer-events: none en el grupo es imprescindible: sin ello el globo se
   interpone bajo el raton, deja de estar encima la forma, se oculta, vuelve
   a estar encima la forma... y parpadea. */
.gtp { pointer-events: none; }
.gg { opacity: 0; transition: opacity .08s linear; }
.gf:hover { filter: brightness(1.14); }
@media print { .gg { display: none; } }

/* ------------------------------------------------------- el indice
   La casilla vive escondida y la mueven diez etiquetas, una por banda.
   El fondo (.ix-f) cubre la pantalla por DEBAJO del panel: cierra al
   pulsar fuera sin estorbar a los enlaces, que van encima. */
/* FIJA Y NO ABSOLUTA, y no es un capricho: al pulsar una etiqueta el
   navegador ENFOCA su casilla y la trae a la vista. Posicionada al
   principio de <main>, eso arrastraba la pagina entera al encabezado cada
   vez que se abria o se cerraba el indice. Fija en el borde superior ya
   esta siempre visible, asi que no hay nada que desplazar. */
#ix { position: fixed; top: 0; left: 0; width: 1px; height: 1px;
      opacity: 0; pointer-events: none; }
/* Fijo, y alineado con el borde derecho de la columna: en posicion fija el
   50% es el del VIEWPORT y ya descuenta la barra. 566 = 1132/2.
   Va en blanco solido y no translucido porque ya no vive siempre sobre la
   banda naranja: arriba del todo, antes de que ninguna se pegue, cae sobre
   el fondo gris del documento. */
.ix-b { position: fixed; top: 15px; z-index: 10;
        right: max(24px, calc(50% - 566px));
        width: 30px; height: 30px; border-radius: 7px;
        display: flex; align-items: center; justify-content: center;
        cursor: pointer; color: #b45309; background: #fff;
        border: 1px solid #e0c9a6; box-shadow: 0 1px 4px rgba(70,40,0,.22); }
.ix-b:hover { color: #7c2d12; border-color: #b45309; }
.ix-b svg { display: block; }
.ix-f { display: none; position: fixed; inset: 0; z-index: 8; }
#ix:checked ~ .ix-f { display: block; }
nav.ix { display: none; position: fixed; z-index: 9; top: 64px;
         /* En posicion fija el 50% es el del VIEWPORT y ya descuenta la
            barra, asi que esto cae justo bajo el boton. 566 = 1132/2. */
         right: max(24px, calc(50% - 566px));
         width: min(430px, calc(100vw - 48px));
         max-height: calc(100vh - 88px); overflow: auto;
         background: #fff; border: 1px solid #d9dde4; border-radius: 9px;
         box-shadow: 0 12px 32px rgba(16,22,30,.20); padding-bottom: 8px; }
#ix:checked ~ nav.ix { display: block; }
.ix-t { margin: 0; padding: 11px 14px 9px; font-size: 12px; font-weight: 600;
        letter-spacing: .04em; text-transform: uppercase; color: #737b87;
        border-bottom: 1px solid #eceff3; display: flex;
        justify-content: space-between; align-items: center;
        /* z-index, y no sobra: la guia del arbol obliga a que .ix-h3 sea
           position: relative, o sea POSICIONADO, y un posicionado se pinta
           por encima de lo que no lo esta aunque vaya antes. Los
           subapartados se colaban ENCIMA de esta cabecera al desplazar la
           lista; los de primer nivel no, porque esos no van posicionados.
           Se veia solo con el panel desplazado. */
        position: sticky; top: 0; z-index: 2; background: #fff; }
.ix-x { cursor: pointer; font-size: 19px; line-height: 1; color: #909aa6;
        padding: 0 4px; }
.ix-x:hover { color: #15181d; }
nav.ix ul { list-style: none; margin: 0; padding: 6px 0 0; }
nav.ix li { margin: 0; }
nav.ix a { display: block; padding: 5px 14px; font-size: 13.5px;
           color: #38404d; text-decoration: none;
           border-left: 3px solid transparent; }
nav.ix a:hover { background: #f2f5f9; }
/* OJO CON LA ESPECIFICIDAD: estas dos van dentro de "nav.ix" a proposito.
   Escritas como ".ix-h3 > a" valen (0,1,1) y las machacaba "nav.ix a", que
   vale (0,1,2): el indice salia PLANO ---sin sangria, sin cuerpo menor y
   sin color propio--- con el marcado perfectamente correcto. Es el tercer
   tropiezo igual, despues de ".t" y de "main > *": la ultima regla escrita
   no gana; gana la mas especifica. */
nav.ix .ix-h2 > a { font-weight: 600; color: #15181d; margin-top: 4px; }
nav.ix .ix-h3 > a { padding-left: 34px; font-size: 13px; color: #5d6673; }
/* La guia vertical de los subapartados, como el arbol de GitHub. */
.ix-h3 { position: relative; }
.ix-h3::before { content: ""; position: absolute; left: 21px; top: 0;
                 bottom: 0; width: 1px; background: #e1e6ec; }
/* Que el titulo al que se salta no quede DEBAJO de la banda pegada. Los h2
   se pegan solos ahi arriba; los h3 necesitan que se les reserve el hueco. */
h3[id] { scroll-margin-top: calc(var(--banda) + 12px); }
@media print { .ix-b, .ix-f, nav.ix, #ix { display: none; } }
footer { margin-top: 48px; color: #737b87; font-size: 12.5px;
         border-top: 1px solid #d9dde4; padding-top: 14px; }
@media print { body { background: #fff; } h2 { break-before: auto; }
                table { box-shadow: none; } th { position: static; }
                h2 { position: static; } }
"""


def esc(t) -> str:
    return (str(t).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))


def mono(t) -> str:
    return '<code>%s</code>' % esc(t)


def tabla(cabeceras, filas, numericas=()):
    """Tabla HTML. `numericas` son los indices de columna que van alineados
    a la derecha: una columna de cuentas alineada a la izquierda obliga a
    comparar cifras de distinta longitud, y eso se lee fatal."""
    if not filas:
        return '<p class="nota">(ninguno)</p>'
    out = ["<table><thead><tr>"]
    for i, c in enumerate(cabeceras):
        out.append('<th%s>%s</th>' % (' class="n"' if i in numericas else "",
                                      esc(c)))
    out.append("</tr></thead><tbody>")
    for f in filas:
        out.append("<tr>")
        for i, c in enumerate(f):
            out.append('<td%s>%s</td>'
                       % (' class="n"' if i in numericas else "", c))
        out.append("</tr>")
    out.append("</tbody></table>")
    return "".join(out)


CSS_CONM = []


def conmutador(ident, variantes):
    """Varias figuras y unos botones que ensenan una. SIN JavaScript.

    Se dibujan LAS TRES y se ocultan dos con CSS. Cuesta tres veces el SVG
    ---unos 20 KB por figura--- y a cambio el informe sigue sin ejecutar
    nada, que es la condicion para que se abra dentro de un ano. Redibujar
    un SVG al vuelo si que necesitaria JavaScript; ensenar y esconder, no.

    `variantes` son tuplas (clave, etiqueta, explicacion, svg). La primera
    es la que viene marcada.
    """
    o = ['<div class="conm" id="c-%s">' % ident]
    for i, (clave, etiqueta, _txt, _svg) in enumerate(variantes):
        # autocomplete="off": ver la nota en con_indice(). Sin esto, al
        # recargar el navegador devuelve la pestana que dejo PUESTA quien
        # abrio el fichero antes, y no la que marca este documento.
        o.append('<input type="radio" name="%s" id="%s-%s" '
                 'autocomplete="off"%s><label for="%s-%s">%s</label>'
                 % (ident, ident, clave, " checked" if i == 0 else "",
                    ident, clave, esc(etiqueta)))
    for clave, _e, texto, svg in variantes:
        o.append('<div class="v %s-v-%s">%s<figure>%s</figure></div>'
                 % (ident, clave,
                    ("<p>%s</p>" % texto) if texto else "", svg))
        # Las reglas van por ID y no por nth-of-type: con nth-of-type habia
        # que escribirlas a mano en el CSS fijo y dejaban de valer en
        # cuanto un conmutador tenia mas pestanas que otro.
        CSS_CONM.append("#%s-%s:checked ~ .%s-v-%s { display: block; }"
                        % (ident, clave, ident, clave))
    o.append("</div>")
    return "".join(o)


def lista(items, clase="datos"):
    """Una lista corta. Es la forma por defecto de dar cifras en el informe.

    Un parrafo con cinco numeros dentro obliga a leerlo entero para sacar
    uno; en lista se ve cual interesa y se salta el resto. Y cada punto
    lleva su UNIDAD y que significa, porque "104.566" a secas no dice nada
    y "104.566 participaciones en un dia" si.
    """
    return ('<ul class="%s">%s</ul>'
            % (clase, "".join("<li>%s</li>" % x for x in items if x)))


def tarjetas(pares):
    out = ['<div class="tarjetas">']
    for valor, etiqueta in pares:
        out.append('<div class="t"><b>%s</b><span>%s</span></div>'
                   % (esc(valor), esc(etiqueta)))
    out.append("</div>")
    return "".join(out)


def miles(n) -> str:
    return "{:,}".format(n).replace(",", ".")


def fecha(ts):
    return ts.strftime("%Y-%m-%d %H:%M") if ts else "?"


def hashes_de(ruta: str):
    """(sha256, md5) de un fichero, en UNA sola lectura y a trozos.

    Los dos a la vez y no en dos pasadas: Dionaea solo apunta el MD5 en su
    base, pero lo que se publica y se busca es el SHA-256, asi que hacen
    falta ambos para poder cruzarlos. Con gigabytes de capturas, leer el
    disco dos veces es el doble de todo a cambio de nada.
    """
    hs, hm = hashlib.sha256(), hashlib.md5()
    try:
        with open(ruta, "rb") as fh:
            for trozo in iter(lambda: fh.read(1 << 20), b""):
                hs.update(trozo)
                hm.update(trozo)
    except OSError:
        return "", ""
    return hs.hexdigest(), hm.hexdigest()


# LO QUE NO SE PUEDE ESCRIBIR, ESCRITO. Por el telnet entra negociacion
# IAC y carga binaria, y Cowrie la anota en "input" como si fuera una orden
# tecleada. Un NUL o un \x07 en una tabla HTML no se ven: la fila sale en
# blanco o partida, y parece un fallo del informe cuando lo que hay es un
# byte de control. Escritos como \x00 se leen, y se ve que son bytes.
_INVISIBLE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def visible(t) -> str:
    return _INVISIBLE.sub(lambda m: "\\x%02x" % ord(m.group(0)), str(t))


# EL CARACTER DE REEMPLAZO NO SE PUEDE DESHACER, Y HAY QUE DECIRLO. Es el
# rombo con la interrogacion, U+FFFD. NO lo pone este guion: lo escribe
# COWRIE, que decodifica los bytes del atacante con errors="replace" antes
# de anotarlos ---118.096 veces en este respaldo---. Cuando el informe lo
# lee, el byte original ya no existe en ningun sitio. Ensenarlo en
# hexadecimal es imposible: no hay nada que ensenar. Lo unico honesto es
# contarlas y decir donde se perdio el dato.
def es_binaria(t) -> bool:
    return bool(_INVISIBLE.search(str(t))) or "\ufffd" in str(t)


def tamano(b) -> str:
    """Bytes, en la unidad en que se entienden."""
    if b < 1024:
        return "%d B" % b
    if b < 1048576:
        return ("%.1f KB" % (b / 1024.0)).replace(".", ",")
    if b < 1073741824:
        return ("%.1f MB" % (b / 1048576.0)).replace(".", ",")
    return ("%.2f GB" % (b / 1073741824.0)).replace(".", ",")


def cuantos(n, uno, varios) -> str:
    """"1 muestra", "0 muestras", "3 muestras". Como plural(), pero escribe
    tambien el cero: es para frases que dan la cifra siempre."""
    return "%s %s" % (miles(n), uno if n == 1 else varios)


# EL SINGULAR DE LAS UNIDADES. Las cifras del informe van pegadas a una
# unidad en plural ("1.056 IPs", "37 conexiones a Dionaea") y con 1 eso se
# lee "1 IPs". nu() pasa al singular las palabras de la unidad que estan
# aqui; las que no estan se quedan como vienen.
SINGULAR = {
    "IPs": "IP", "contactos": "contacto", "conexiones": "conexión",
    "participaciones": "participación", "sesiones": "sesión",
    "órdenes": "orden", "días": "día", "países": "país",
    "intentos": "intento", "fallidos": "fallido", "muestras": "muestra",
    "entregas": "entrega", "binarios": "binario", "puestas": "puesta",
    "llegaron": "llegó", "acertaron": "acertó", "fueron": "fue",
    "están": "está", "tecleadas": "tecleada", "distintas": "distinta",
    "distintos": "distinto", "baneadas": "baneada",
    "acciones": "acción", "usadas": "usada",
}


def singular(texto) -> str:
    return " ".join(SINGULAR.get(p, p) for p in texto.split(" "))


def nu(n, unidad) -> str:
    """"1 IP" / "3 IPs", "1 conexión a Dionaea" / "2 conexiones a Dionaea"."""
    return "%s %s" % (miles(n), singular(unidad) if n == 1 else unidad)


def y_lista(cosas) -> str:
    """"a", "a y b", "a, b y c"."""
    cosas = [c for c in cosas if c]
    if len(cosas) < 2:
        return "".join(cosas)
    return ", ".join(cosas[:-1]) + " y " + cosas[-1]


def la_hora(h) -> str:
    """"la 01:00" pero "las 13:00"."""
    return ("la %02d:00" if h == 1 else "las %02d:00") % h


def que_hicieron(n, tec) -> str:
    """Lo que hicieron las n sesiones que entraron, de las que tec teclearon
    algo. Escrita entera para cada caso: con 1, con 0 y con todas, las
    plantillas con huecos daban "la otra entro" cuando no habia otra."""
    if n == 1:
        return ("Tecleó algo" if tec else
                "Se fue sin escribir una sola orden")
    if tec == 0:
        return "Ninguna tecleó nada: todas se fueron sin escribir una sola orden"
    if tec == n:
        return "Todas teclearon algo"
    resto = n - tec
    return ("<b>%s de ellas %s algo</b> (el %s%%); %s sin escribir una "
            "sola orden"
            % (miles(tec), "tecleó" if tec == 1 else "teclearon",
               ("%.1f" % (100.0 * tec / n)).replace(".", ","),
               "la otra entró y se fue" if resto == 1 else
               "las otras %s entraron y se fueron" % miles(resto)))


def fuera_del_dibujo(n, resto) -> str:
    """"Queda fuera del dibujo: 1 país..." o "Quedan fuera...: 3 países...".
    Vacio si no queda ninguno."""
    if n <= 0:
        return ""
    return "<b>%s fuera del dibujo:</b> %s %s" % (
        "Queda" if n == 1 else "Quedan", cuantos(n, "país", "países"), resto)


def plural(n, uno, varios) -> str:
    """"1 sesión" y no "1 sesiones". Vacio si no hay ninguna: un cero en
    una lista de lo que hizo alguien se lee como que hizo algo."""
    if not n:
        return ""
    return "%s %s" % (miles(n), uno if n == 1 else varios)


def dura(ms) -> str:
    """Milisegundos, en la unidad en que se entienden."""
    if ms is None:
        return "?"
    sg = ms / 1000.0
    if sg < 1:
        return "%d ms" % int(ms)
    if sg < 90:
        return ("%.1f s" % sg).replace(".", ",")
    if sg < 3600:
        return "%d min %d s" % (int(sg // 60), int(sg % 60))
    return "%d h %d min" % (int(sg // 3600), int((sg % 3600) // 60))


def recorta(t, n=70):
    t = visible(t).replace("\n", " ")
    return t if len(t) <= n else t[:n - 1] + "…"


# ------------------------------------------------- clasificar un fichero
#
# EL DIRECTORIO DE CAPTURAS DE COWRIE NO ES TODO MALWARE, Y CONTARLO COMO SI
# LO FUERA INFLABA LA CIFRA POR SIETE. En el primer respaldo real habia
# 28.395 ficheros ahi dentro y solo 4.244 eran capturas: 21.300 eran ficheros
# de CERO BYTES con nombres como
#
#   20260822-143525-f74e48e67f11-0-redir__var_run__x
#
# que es lo que deja Cowrie cuando el atacante hace ">/var/run/.x". O sea la
# SONDA DE DIRECTORIO ESCRIBIBLE de Gafgyt y compania: se prueba dónde se
# puede escribir antes de soltar el binario.
#
# Eso no es una muestra, pero tampoco es basura que tirar: es la huella de
# una conducta, y va contada aparte.
_RE_SHA = re.compile(r"^[0-9a-f]{64}$")
_RE_TMP = re.compile(r"^tmp[a-z0-9]{6,10}$")


# ------------------------------------------------ que ES cada captura
#
# NO TODO LO QUE HAY EN downloads/ ES UNA MUESTRA, Y ESTO NO SE PUEDE
# DECIDIR POR EL NOMBRE. En el primer respaldo real, 4.161 de las 4.244
# capturas con nombre SHA-256 eran copias de NUESTRO PROPIO
# /var/log/auth.log falso: commands/authlog.py lo genera al abrir cada
# sesion y lo persiste con Artifact(), y Artifact escribe justo ahi,
# nombrando por hash. O sea 280 MB de log nuestro en el directorio de
# malware, y un recuento de "4.244 muestras" que era falso por cincuenta.
#
# Asi que se mira el CONTENIDO ---los primeros bytes--- y no el nombre. Y
# el reconocimiento del artefacto va por la FORMA de la linea de syslog, no
# por el hostname del senuelo: el hostname se cambia y esto seguiria
# valiendo.
_RE_SYSLOG = re.compile(
    rb"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[.\d]*[+-]\d\d:\d\d \S+ \S+\[\d+\]:")


def tipo_de(ruta: str) -> str:
    """Que es el fichero, mirando sus primeros bytes. No lo ejecuta."""
    try:
        with open(ruta, "rb") as fh:
            cab = fh.read(512)
    except OSError:
        return "ilegible"
    if not cab:
        return "vacio"
    if cab[:4] == b"\x7fELF":
        return "ELF"
    if cab[:2] == b"MZ":
        return "PE"
    if cab[:2] == b"#!":
        return "script"
    if _RE_SYSLOG.match(cab):
        return "artefacto"
    # Texto si casi todo son caracteres imprimibles.
    imprimibles = sum(1 for b in cab if 32 <= b < 127 or b in (9, 10, 13))
    return "texto" if imprimibles > len(cab) * 0.92 else "binario"


# Lo que de verdad cuenta como muestra.
MUESTRA = ("ELF", "PE", "script", "binario")


def clase_fichero(nombre: str) -> str:
    if _RE_SHA.match(nombre):
        return "captura"
    if "-redir_" in nombre or "-redir__" in nombre:
        return "redir"
    if _RE_TMP.match(nombre):
        return "temporal"
    return "otro"



# =========================================================== los esquemas
#
# SVG ESCRITO A MANO, SIN LIBRERIAS. El informe tiene que abrirse solo dentro
# de un ano, en otra maquina y sin red: cualquier <script src="..."> de un CDN
# convierte el informe en algo que un dia deja de verse. SVG en linea lo ve
# cualquier navegador, se imprime bien y se pega en un documento como imagen.
#
# Los colores salen de una rampa fija y no de un degradado calculado: con seis
# tonos se distinguen en pantalla, en papel en blanco y negro y para quien no
# distingue el rojo del verde.
# La llave de debajo del cronograma. Escrito una vez: las tres variantes
# del conmutador ---todas, Cowrie, Dionaea--- cubren el mismo periodo, y
# tres copias del mismo texto es la forma de que un dia digan cosas
# distintas.
TODO_EL_TIEMPO = "Todo el periodo que cubre el respaldo"

MESES_ES = ("enero", "febrero", "marzo", "abril", "mayo", "junio", "julio",
            "agosto", "septiembre", "octubre", "noviembre", "diciembre")
RAMPA = ("#1b3a6b", "#1f5f9e", "#2b87c4", "#59b0d9", "#9bd0e8", "#cfe8f4")


def color_rampa(valor, maximo):
    if maximo <= 0:
        return RAMPA[-1]
    # Escala por raiz: con una lineal, un pais que multiplica por mil a los
    # demas deja a todos los demas del mismo color y el esquema no dice nada.
    frac = (valor / float(maximo)) ** 0.5
    idx = min(len(RAMPA) - 1, int((1 - frac) * len(RAMPA)))
    return RAMPA[idx]


# ---------------------------------------------------- el globo de ayuda
#
# Los <title> de SVG ya daban el dato, pero son el globo NATIVO del
# navegador: tarda cerca de un segundo en salir, no se puede dar estilo y
# hay navegadores que no lo ensenan sobre SVG. Se quedan igualmente ---son
# el nombre accesible de cada forma, y lo que se lee si :has() no esta---
# y encima se dibuja este.
#
# VA EN UN GRUPO APARTE Y AL FINAL DEL SVG. El SVG no tiene z-index: pinta
# en el orden en que esta escrito, asi que un globo puesto junto a su
# propia forma lo taparia la forma siguiente. Al final, las tapa a todas.
#
# Y SE ENSENA CON :has(), que es lo que permite UNA REGLA POR NUMERO en vez
# de una por dato: hay cientos de datos, pero la figura mas poblada tiene
# unas decenas de elementos, y la regla `svg:has(.s7:hover) .t7` vale para
# el septimo de CUALQUIER figura ---:has() no sale del <svg> que lo
# contiene, asi que dos figuras no se cruzan---.
_TIP_N = set()


# ALINEAR UN CUADRITO DE COLOR CON SU TEXTO: CONTRA LA TINTA, NO CONTRA LA
# CAJA DE LA FUENTE. Es el arreglo que costo tres intentos.
#
# La caja de la fuente (lo que devuelve getExtentOfChar, y lo que pinta el
# navegador al seleccionar) va del ascendente al descendente: sobra hueco
# por abajo, porque reserva sitio para las colas de la g y la p. El ojo no
# ve esa caja: ve la TINTA, y en una linea de cifras y mayusculas la tinta
# va de la linea base hacia arriba y nada mas. Centrar el cuadro en la caja
# lo deja BAJO respecto de lo que se lee, y entonces parece que el texto
# esta alto ---que es exactamente como se describio el fallo---.
#
# CIFRAS_ALTO es cuanto sube la tinta de una cifra sobre la linea base, en
# fracciones del cuerpo. Medido con canvas (actualBoundingBoxAscent) en la
# familia de la hoja: 10/13.5 y 9/12.5, o sea 0.72 largo.
CIFRAS_ALTO = 0.72


def cuadro_y(base, lado, cuerpo):
    """Y del cuadrito de `lado` para que su centro caiga en el de la tinta.

    `base` es la LINEA BASE del texto, no su atributo y. Por eso las
    leyendas que llevan cuadrito no usan dominant-baseline: con "middle" la
    linea base sale corrida un pico que depende de la fuente y del
    navegador ---aqui eran 3.9 sobre un cuerpo de 13.5--- y desde Python no
    hay forma de saber cuanto. Escribiendo la base a pelo, esto es
    aritmetica y no una estimacion.
    """
    return base - CIFRAS_ALTO * cuerpo / 2.0 - lado / 2.0


def globo(n, x, y, texto, an, color=None):
    """Un globo para el dato n-esimo de una figura, anclado en (x, y).

    `texto` es una cadena o VARIAS LINEAS. Con varias, el ancho sale de la
    MAS LARGA y no de la primera: midiendo la primera, una segunda linea
    mas larga se sale de la caja y se lee cortada contra el fondo.

    El ancho se ESTIMA de los caracteres: medir texto de verdad necesita
    JavaScript, y aqui no hay. 6.75 px por caracter a cuerpo 12.5 va justo
    con holgura; pasarse un poco es inofensivo y quedarse corto parte el
    texto, asi que la estimacion tira hacia arriba.
    """
    _TIP_N.add(n)
    lineas = [esc(l) for l in
              ([texto] if isinstance(texto, str) else list(texto))]
    hueco = 15 if color else 0
    ancho = 22 + hueco + max(len(l) for l in lineas) * 6.75
    salto = 17
    alto = 24 + salto * (len(lineas) - 1)
    # Que no se salga del lienzo; si no cabe por arriba, se pone debajo.
    x0 = min(max(4.0, x - ancho / 2.0), max(4.0, an - ancho - 4))
    y0 = y - alto - 9
    if y0 < 4:
        y0 = y + 13
    o = ['<g class="gg gg%d">' % n,
         '<rect x="%.1f" y="%.1f" width="%.1f" height="%d" rx="6" '
         'fill="#15181d" opacity=".93"/>' % (x0, y0, ancho, alto)]
    tx = x0 + 11
    if color:
        # Contra la base de la PRIMERA linea: con varias, el cuadro se
        # alinea con la de arriba, que es la que lleva el nombre.
        base1 = y0 + alto / 2.0 + 5.0 - salto * (len(lineas) - 1) / 2.0
        o.append('<rect x="%.1f" y="%.1f" width="9" height="9" rx="2" '
                 'fill="%s"/>' % (tx, cuadro_y(base1, 9, 12.5), color))
        tx += hueco
    # Las lineas van CENTRADAS en la caja, no colgando de arriba: con el
    # cuadrito de color al lado, una sola linea pegada al techo queda
    # desalineada con el.
    # y1 es la LINEA BASE de la primera linea, no su centro: el +5 es medio
    # alto de tinta (0.72 * 12.5 / 2), que es lo que baja la base respecto
    # del centro optico de la caja.
    y1 = y0 + alto / 2.0 + 5.0 - salto * (len(lineas) - 1) / 2.0
    for i, linea in enumerate(lineas):
        o.append('<text x="%.1f" y="%.1f" font-size="12.5" font-weight="600" '
                 'fill="#fff">%s</text>'
                 % (tx, y1 + i * salto, linea))
    o.append("</g>")
    return "".join(o)


def css_globos():
    salto = chr(10)
    return salto.join("svg:has(.gf%d:hover) .gg%d { opacity: 1; }" % (n, n)
                      for n in sorted(_TIP_N))


def svg_franja(partes, an=900, alto=30):
    """Una barra de 100% partida en trozos, con su leyenda debajo.

    PARA CIFRAS QUE SON PARTES DE UN TODO, y solo para eso. El resumen tenia
    diez tarjetas iguales para cosas que no lo son: unas se suman entre si
    (Cowrie + Dionaea = participaciones), otras son una proporcion (cuantas
    sesiones llegan a teclear) y otras son dimensiones (cuantas IPs). Diez
    rectangulos identicos dicen que las diez cifras son del mismo tipo, y no
    lo son: la relacion, que es lo que se quiere ver, habia que deducirla.

    EL TROZO QUE INTERESA VA EL PRIMERO, a la izquierda. En las proporciones
    de verdad es diminuto ---23.130 de 595.705 es un 3,9%--- y al borde
    izquierdo se ve; perdido en medio de la barra, no.

    NO LLEVA GLOBO, al reves que las demas figuras: aqui todas las cifras
    estan escritas en la leyenda, justo debajo. Un globo que repite lo que ya
    se lee es ruido.

    `partes` son tuplas (etiqueta, valor, color).
    """
    total = float(sum(v for _e, v, _c in partes)) or 1.0
    leyenda = 22 * len(partes)
    al = alto + 16 + leyenda
    o = ['<svg viewBox="0 0 %d %d" width="100%%" role="img" aria-label="%s">'
         % (an, al, esc(" y ".join(e for e, _v, _c in partes)))]
    # DOS PASADAS: PRIMERO TODOS LOS TROZOS Y DESPUES TODOS LOS ROTULOS.
    #
    # En una sola pasada el rotulo de un trozo lo tapa el rectangulo del
    # SIGUIENTE, porque el SVG no tiene z-index y pinta en el orden en que
    # esta escrito. Se veia justo en el caso que importa: el "3,9%" del trozo
    # rojo cae en x=42 y el trozo gris empieza en x=35 y llega al final, asi
    # que lo borraba entero. El rotulo estaba en el marcado y no se veia en
    # la pagina.
    x = 0.0
    trozos = []
    for etiqueta, valor, color in partes:
        ancho = max(2.0, an * (valor / total))
        trozos.append((etiqueta, valor, color, x, ancho))
        x += ancho

    for etiqueta, valor, color, x0, ancho in trozos:
        pct = 100.0 * valor / total
        o.append('<rect x="%.1f" y="0" width="%.1f" height="%d" fill="%s">'
                 '<title>%s: %s (%s%%)</title></rect>'
                 % (x0, ancho, alto, color, esc(etiqueta), miles(valor),
                    ("%.1f" % pct).replace(".", ",")))

    # LA BARRA NO LLEVA NINGUN NUMERO DENTRO, Y ES DELIBERADO.
    #
    # Llevaba el porcentaje de cada trozo: centrado si cabia, y pegado fuera
    # si el trozo era diminuto. Costo dos arreglos ---uno de colocacion y otro
    # de orden de pintado--- y seguia leyendose mal, porque un numero flotando
    # sobre una barra no tiene con que alinearse: ni con el texto de al lado,
    # ni con el borde del trozo, ni con la leyenda.
    #
    # Y sobraba. TODAS esas cifras estan en la leyenda de aqui abajo, con su
    # valor absoluto al lado, que es mas de lo que decia la barra. Asi la
    # barra hace una sola cosa ---ensenar la proporcion de un vistazo--- y los
    # numeros se leen donde se leen los numeros. Es el mismo criterio que con
    # los globos: lo que repite algo que ya se lee es ruido.

    # `base` es la LINEA BASE de cada renglon. Sin dominant-baseline: ver
    # cuadro_y(). Con "middle" la base caia 3.9 por debajo del atributo y, y
    # el cuadrito, colocado a ojo contra el atributo, quedaba descuadrado
    # respecto de la tinta ---primero bajo y despues, corrigiendo a ojo otra
    # vez, alto por el mismo pico---.
    base = alto + 27
    for etiqueta, valor, color in partes:
        pct = ("%.1f" % (100.0 * valor / total)).replace(".", ",")
        o.append('<rect x="0" y="%.1f" width="11" height="11" rx="2" '
                 'fill="%s"/>' % (cuadro_y(base, 11, 13.5), color))
        o.append('<text x="19" y="%.1f" font-size="13.5" fill="#38404d">'
                 '<tspan font-weight="600">%s</tspan>'
                 ' %s  <tspan fill="#737b87">(%s%%)</tspan></text>'
                 % (base, miles(valor),
                    esc(singular(etiqueta) if valor == 1 else etiqueta), pct))
        base += 22
    o.append("</svg>")
    return "".join(o)


def figura_franja(ambito, nota, partes):
    """Una franja en su caja, con el AMBITO escrito encima.

    `ambito` es de que senuelo habla ---"Solo Cowrie", "Cowrie y
    Dionaea"--- y `nota` por que es asi. Se escribe con las mismas
    palabras que el conmutador de los cronogramas ("Solo Cowrie", "Solo
    Dionaea"): dos nombres distintos para el mismo recorte obligan a
    comprobar que son el mismo.
    """
    return ('<figure><p class="ambito"><span>%s</span> %s</p>%s</figure>'
            % (esc(ambito), nota, svg_franja(partes)))


def svg_circulo_triangulos(datos, titulo, unidad, paises_total=None):
    """Un triangulo por pais, repartidos en circulo, el tamano por cantidad.

    El AREA es proporcional al dato, no el lado: si se escalara el lado, un
    pais con el doble de ataques se veria cuatro veces mas grande y el
    esquema mentiria. Por eso el lado va por la raiz cuadrada.
    """
    if not datos:
        return ""
    an, al = 940, 640
    cx, cy = an / 2.0, al / 2.0 + 4
    # El radio sale del NUMERO de paises, no de un valor fijo: la separacion
    # entre vecinos es 2*pi*r/n y tiene que ser mayor que el ancho del
    # triangulo mas grande, o los dos mayores se solapan.
    radio = max(150, int(len(datos) * 9.6))
    maximo = max(v for _c, v in datos)
    n = len(datos)
    o = ['<svg viewBox="0 0 %d %d" width="100%%" role="img" '
         'aria-label="%s">' % (an, al, esc(titulo))]
    o.append('<circle cx="%.1f" cy="%.1f" r="%d" fill="none" stroke="#dfe4ea" '
             'stroke-dasharray="3 5"/>' % (cx, cy, radio))
    globos = []
    for i, (cc, valor) in enumerate(datos):
        ang = -math.pi / 2 + (2 * math.pi * i / n)
        x = cx + radio * math.cos(ang)
        y = cy + radio * math.sin(ang)
        # Tope atado a la separacion entre vecinos (ancho = 2*0.866*lado).
        tope = (2 * math.pi * radio / n) * 0.56
        lado = 7 + tope * ((valor / float(maximo)) ** 0.5)
        pts = "%.1f,%.1f %.1f,%.1f %.1f,%.1f" % (
            x, y - lado, x - lado * 0.866, y + lado * 0.5,
            x + lado * 0.866, y + lado * 0.5)
        col = color_rampa(valor, maximo)
        o.append('<polygon class="gf gf%d" points="%s" fill="%s" stroke="#fff" '
                 'stroke-width="1.5"><title>%s: %s</title></polygon>'
                 % (i + 1, pts, col, esc(cc), esc(nu(valor, unidad))))
        globos.append(globo(i + 1, x, y - lado,
                            "%s: %s" % (cc, nu(valor, unidad)),
                            an, col))
        # La etiqueta va FUERA del circulo y alineada segun el lado en el que
        # cae: centrada siempre, los nombres de la izquierda se montaban
        # sobre los triangulos.
        lx = cx + (radio + lado + 20) * math.cos(ang)
        ly = cy + (radio + lado + 20) * math.sin(ang)
        anclaje = "middle"
        if math.cos(ang) > 0.34:
            anclaje = "start"
        elif math.cos(ang) < -0.34:
            anclaje = "end"
        o.append('<text x="%.1f" y="%.1f" text-anchor="%s" font-size="13" '
                 'fill="#38404d" dominant-baseline="middle">%s %s</text>'
                 % (lx, ly, anclaje, bandera(cc), esc(cc)))
    # EL CENTRO DICE TAMBIEN LO QUE NO SE VE. La figura dibuja los N
    # paises de arriba, no todos: sin decirlo, la cifra del centro se lee
    # como el total y no lo es. En el respaldo real son 24 triangulos de
    # 151 paises, o sea que se estan dejando fuera 127 ---la cola larga, que
    # el informe cuenta aparte justamente porque es mayoria---.
    fuera = max(0, (paises_total or n) - n)
    suma = miles(sum(v for _c, v in datos))
    # TRES LINEAS, DE MAS A MENOS: la cifra y de cuantos paises es, de
    # cuantos hay, y cuantos faltan. Cada escalon mas pequeno y mas claro
    # que el anterior, que es lo que dice en que orden se lee.
    #
    # LA PRIMERA VA EN UNA SOLA LINEA Y CON DOS TAMANOS. A cuerpo 26 entera
    # mide unos 420 y dentro del circulo solo caben ~378 ---el hueco libre
    # es el radio menos el triangulo mas grande---: se montaria sobre los
    # triangulos de los lados. Con el numero grande y el resto a 15 se
    # queda en ~280. Y los dos trozos comparten LINEA BASE, que es por lo
    # que no llevan dominant-baseline (ver cuadro_y).
    if fuera:
        y1, y2, y3 = cy - 10, cy + 12, cy + 30
    else:
        y1 = cy + 8
    o.append('<text x="%.1f" y="%.1f" text-anchor="middle" fill="#15181d">'
             '<tspan font-size="26" font-weight="600">%s</tspan>'
             '<tspan font-size="15"> %s por %s</tspan></text>'
             % (cx, y1, suma,
                esc(singular(unidad + " usadas") if suma == "1"
                    else unidad + " usadas"),
                cuantos(n, "país", "países")))
    if fuera:
        o.append('<text x="%.1f" y="%.1f" text-anchor="middle" '
                 'font-size="12.5" fill="#737b87">de los %d países en total'
                 '</text>' % (cx, y2, paises_total or n))
        o.append('<text x="%.1f" y="%.1f" text-anchor="middle" '
                 'font-size="11.5" fill="#9aa3ae">por lo que no %s '
                 '%s</text>' % (cx, y3, "aparece" if fuera == 1 else "aparecen",
                                cuantos(fuera, "país", "países")))
    o.append('<g class="gtp">%s</g>' % "".join(globos))
    o.append("</svg>")
    return "".join(o)


def svg_barras(datos, titulo, unidad, extra=None, banderas=True,
               columnas=None):
    """Barras horizontales ordenadas, con el desglose DEBAJO de cada barra.

    `extra` es el desglose de esa fila: de que se compone la cifra y desde
    cuantas IPs sale. Va en su propia linea y NO dentro de la barra ni
    pegado detras: mezclar dos escalas en la misma barra es la forma tipica
    de mentir con un grafico, y pegado detras obligaba a encoger las barras
    hasta el minimo ---el hueco de la derecha sale de la etiqueta mas
    larga--- con lo que la figura dejaba de comparar nada.

    `columnas` son los dos rotulos de arriba, con su llave: que es la
    primera columna y que es la segunda. Sin ellos, la misma figura vale
    para tres cosas distintas ---los dos senuelos, solo Cowrie, solo
    Dionaea--- y al cambiar de pestana nada dice cual se esta mirando.
    """
    if not datos:
        return ""
    fila = 44 if extra else 30
    arriba = 46 if columnas else 18
    izq = 112 if banderas else max(112, 18 + int(
        max(len(str(c)) for c, _v in datos) * 7.6))
    an = 900
    al = arriba + fila * len(datos) + 16
    maximo = max(v for _c, v in datos) or 1
    # El hueco de la derecha se calcula de la cifra MAS LARGA que se va a
    # escribir al final de la barra, no a ojo: con un valor fijo, la fila
    # de Pakistan se salia del lienzo y se leia cortada.
    largo_txt = max(len(miles(v)) for _c, v in datos)
    ancho_util = max(120, an - izq - 24 - int(largo_txt * 7.6))
    o = ['<svg viewBox="0 0 %d %d" width="100%%" role="img" '
         'aria-label="%s">' % (an, al, esc(titulo))]

    if columnas:
        # Las llaves, con las patas hacia ABAJO: lo que rotulan esta
        # debajo. Es la misma figura que la del cronograma, al reves.
        for x0, x1, txt in ((max(8.0, izq - 104.0), izq - 12.0, columnas[0]),
                            (float(izq), an - 24.0, columnas[1])):
            o.append('<line x1="%.1f" y1="30" x2="%.1f" y2="30" '
                     'stroke="#c8cfd8" stroke-width="1.5"/>' % (x0, x1))
            for x in (x0, x1):
                o.append('<line x1="%.1f" y1="30" x2="%.1f" y2="36" '
                         'stroke="#c8cfd8" stroke-width="1.5"/>' % (x, x))
            o.append('<text x="%.1f" y="22" text-anchor="middle" '
                     'font-size="12.5" fill="#5d6673">%s</text>'
                     % ((x0 + x1) / 2.0, esc(txt)))

    globos = []
    for i, (cc, valor) in enumerate(datos):
        y = arriba + i * fila
        largo = max(2.0, ancho_util * (valor / float(maximo)))
        # text-anchor="end": sin esto el nombre del pais se escribia hacia
        # la derecha desde el margen y quedaba DEBAJO de su propia barra.
        o.append('<text x="%d" y="%.1f" font-size="14" fill="#38404d" '
                 'text-anchor="end" dominant-baseline="middle">%s%s</text>'
                 % (izq - 12, y + 9,
                    (bandera(cc) + " ") if banderas else "", esc(cc)))
        col = color_rampa(valor, maximo)
        o.append('<rect class="gf gf%d" x="%d" y="%.1f" width="%.1f" '
                 'height="18" rx="3" fill="%s">'
                 '<title>%s: %s</title></rect>'
                 % (i + 1, izq, y, largo, col, esc(cc),
                    esc(nu(valor, unidad))))
        globos.append(globo(i + 1, izq + largo / 2.0, y,
                            "%s: %s" % (cc, nu(valor, unidad)),
                            an, col))
        o.append('<text x="%.1f" y="%.1f" font-size="13" font-weight="600" '
                 'fill="#38404d" dominant-baseline="middle">%s</text>'
                 % (izq + largo + 8, y + 9, miles(valor)))
        if extra and cc in extra:
            o.append('<text x="%d" y="%.1f" font-size="11.5" fill="#737b87">'
                     '%s</text>' % (izq, y + 34, esc(extra[cc])))
    o.append('<g class="gtp">%s</g>' % "".join(globos))
    o.append("</svg>")
    return "".join(o)


def rellena_dias(por_dia):
    """Del primer dia al ultimo, con ceros en los huecos.

    La usan el dibujo y el texto que lo acompana. Si cada uno rellenara por
    su cuenta ---o peor, si solo rellenara el dibujo--- el grafico ensenaria
    veintiun dias y el texto hablaria de la media de dieciseis.
    """
    if not por_dia:
        return {}
    d, ultimo = min(por_dia), max(por_dia)
    out = {}
    while d <= ultimo:
        out[d] = por_dia.get(d, 0)
        d += timedelta(days=1)
    return out


# Paleta CATEGORICA, no la rampa azul: en un pastel los trozos no estan
# ordenados por intensidad, son categorias distintas y tienen que
# distinguirse entre si. Estos siete se separan tambien en escala de grises
# ---o sea al imprimir--- y para quien no distingue el rojo del verde.
QUESITOS = ("#1f5f9e", "#d9534f", "#7a51a8", "#2f8f5b", "#d98324",
            "#3aa8c1", "#8a6d3b")


def svg_quesitos(datos, titulo, unidad, extra=None):
    """Pastel con la leyenda a la izquierda, y OTRO pastel para lo diminuto.

    Un pastel solo vale para PARTES DE UN TODO y con pocas categorias: con
    quince trozos no se distingue ninguno y hay que leer la leyenda, que es
    tanto como no tener grafico. Aqui son cinco protocolos y suman el
    total, que es exactamente el caso en el que gana a unas barras.

    EL SEGUNDO PASTEL ES POR UN FALLO REAL DEL PRIMERO: MSSQL y RPC son el
    0,1% cada uno y sus trozos miden MENOS DE MEDIO GRADO. Estaban
    dibujados ---y con su globo, y en la leyenda--- pero en la figura no se
    veian, asi que el pastel ensenaba tres protocolos donde hay cinco.
    Ahora todo lo que no llega al 1% se junta en un trozo gris y se amplia
    al lado, repartido entre si: es la unica forma de ver la proporcion
    ENTRE ellos, que no tiene nada que ver con la del total.

    El valor y el porcentaje van EN LA LEYENDA: un pastel dice bien "esto
    es la mitad y esto un cuarto" y dice fatal "esto son 487.937".
    """
    datos = [(k, v) for k, v in datos if v > 0]
    if not datos:
        return ""
    total = float(sum(v for _k, v in datos))
    # El color va por el ORDEN ORIGINAL y no por el orden de cada pastel:
    # asi el verde de MSSQL en la leyenda es el verde de MSSQL en el pastel
    # de al lado, que es lo unico que ata los dos dibujos.
    col_de = {k: QUESITOS[i % len(QUESITOS)] for i, (k, _v) in enumerate(datos)}

    # UNO SOLO NO SE AMPLIA: un pastel de un unico trozo es un circulo que
    # dice 100%, y eso no explica nada. Con uno solo se queda donde esta,
    # invisible pero en la leyenda con su cifra.
    pequenos = [(k, v) for k, v in datos if v / total < 0.01]
    if len(pequenos) < 2:
        pequenos = []
    claves_peq = set(k for k, _v in pequenos)
    grandes = [(k, v) for k, v in datos if k not in claves_peq]
    resto = sum(v for _k, v in pequenos)

    an, al = 900, max(320, 60 + 30 * len(datos))
    cx2 = r2 = 0
    if pequenos:
        cx, cy = 560, al / 2.0
        r = min(116, al / 2.0 - 30)
        cx2, r2 = 800, r * 0.52
    else:
        cx, cy = 660, al / 2.0
        r = min(130, al / 2.0 - 26)
    o = ['<svg viewBox="0 0 %d %d" width="100%%" role="img" '
         'aria-label="%s">' % (an, al, esc(titulo))]

    globos = []
    nn = [0]

    def pastel(trozos, ox, oy, rr, denom):
        """Dibuja un pastel y devuelve el arco de cada trozo.

        `trozos` son (etiqueta, valor, color, texto del globo) y `denom` el
        total contra el que se miden: en el pastel de al lado es la suma de
        los pequenos y no la de todo, porque lo que ensena es como se
        reparten ENTRE ELLOS.
        """
        arcos = []
        ang = -math.pi / 2
        for clave, valor, col, tip in trozos:
            frac = valor / float(denom) if denom else 0.0
            nn[0] += 1
            n = nn[0]
            fin = ang + 2 * math.pi * frac
            if frac >= 0.9995:
                # Un solo trozo: el arco degenera ---el punto inicial y el
                # final coinciden y no se dibuja nada--- asi que va un
                # circulo.
                o.append('<circle class="gf gf%d" cx="%.1f" cy="%.1f" '
                         'r="%.1f" fill="%s"><title>%s</title></circle>'
                         % (n, ox, oy, rr, col, esc(tip)))
            else:
                x1, y1 = ox + rr * math.cos(ang), oy + rr * math.sin(ang)
                x2, y2 = ox + rr * math.cos(fin), oy + rr * math.sin(fin)
                o.append('<path class="gf gf%d" d="M %.1f %.1f L %.1f %.1f '
                         'A %.1f %.1f 0 %d 1 %.1f %.1f Z" fill="%s" '
                         'stroke="#fff" stroke-width="1.5">'
                         '<title>%s</title></path>'
                         % (n, ox, oy, x1, y1, rr, rr,
                            1 if frac > 0.5 else 0, x2, y2, col, esc(tip)))
            med = (ang + fin) / 2.0
            globos.append(globo(n, ox + rr * 0.58 * math.cos(med),
                                oy + rr * 0.58 * math.sin(med) - 2,
                                tip, an, col))
            # El porcentaje solo dentro de los trozos que lo admiten: en
            # una porcion del 0,2% el numero tapa el trozo entero.
            if frac >= 0.06:
                o.append('<text x="%.1f" y="%.1f" text-anchor="middle" '
                         'dominant-baseline="middle" font-size="%d" '
                         'font-weight="600" fill="#fff">%.0f%%</text>'
                         % (ox + rr * 0.62 * math.cos(med),
                            oy + rr * 0.62 * math.sin(med),
                            14 if rr > 90 else 12, frac * 100))
            arcos.append((ang, fin))
            ang = fin
        return arcos

    def pct(valor):
        # Con coma, como el resto del informe. La leyenda ponia "60.6%" con
        # punto, que en un informe en espanol se lee como otra cosa.
        return ("%.1f" % (100.0 * valor / total)).replace(".", ",")

    def tip_de(clave, valor):
        return "%s: %s (%s%%)" % (clave, nu(valor, unidad), pct(valor))

    trozos = [(k, v, col_de[k], tip_de(k, v)) for k, v in grandes]
    if pequenos:
        trozos.append((
            "resto", resto, "#c3cad3",
            "Lo que no se ve: %s (%s%%)"
            % (y_lista(k for k, _v in pequenos), pct(resto))))
    arcos = pastel(trozos, cx, cy, r, total)

    if pequenos:
        # LA LUPA, CON SUS DOS LINEAS. Sin ellas el segundo pastel parece
        # otra figura distinta; con ellas se ve de que trozo sale. Las dos
        # salen de los bordes del trozo gris, que en el respaldo real estan
        # a medio grado uno de otro: por eso parecen un cono.
        a0, a1 = arcos[-1]
        for a, yb in ((a0, cy - r2), (a1, cy + r2)):
            o.append('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" '
                     'stroke="#c3cad3" stroke-width="1" '
                     'stroke-dasharray="3 3"/>'
                     % (cx + r * math.cos(a), cy + r * math.sin(a),
                        cx2 - r2, yb))
        pastel([(k, v, col_de[k], tip_de(k, v)) for k, v in pequenos],
               cx2, cy, r2, resto)
        o.append('<text x="%.1f" y="%.1f" text-anchor="middle" '
                 'font-size="12.5" fill="#5d6673">ese %s%% de cerca</text>'
                 % (cx2, cy + r2 + 22, pct(resto)))
        o.append('<text x="%.1f" y="%.1f" text-anchor="middle" '
                 'font-size="11.5" fill="#909aa6">y cómo se reparte</text>'
                 % (cx2, cy + r2 + 38))

    # Igual que en svg_franja: `y` es la linea base del nombre, y el
    # cuadrito se alinea con la tinta y no con la caja de la fuente.
    y = (al - 26 * len(datos)) / 2.0 + 9
    for clave, valor in datos:
        o.append('<rect x="24" y="%.1f" width="14" height="14" rx="3" '
                 'fill="%s"/>' % (cuadro_y(y, 14, 14), col_de[clave]))
        o.append('<text x="46" y="%.1f" font-size="14" fill="#15181d">%s</text>'
                 % (y, esc(clave)))
        detalle = "%s %s (%s%%)" % (miles(valor), esc(unidad), pct(valor))
        if extra and clave in extra:
            detalle += " · %s" % extra[clave]
        o.append('<text x="46" y="%.1f" font-size="12" fill="#737b87">'
                 '%s</text>' % (y + 15, detalle))
        y += 26 + 10
    o.append('<g class="gtp">%s</g>' % "".join(globos))
    o.append("</svg>")
    return "".join(o)


def svg_cronograma(por_dia, titulo, unidad, pie=None):
    """Barras por dia con DOS EJES: el numero de dia arriba y el mes abajo.

    Repetir "2026-08-22, 2026-08-23..." bajo cada barra es ilegible y
    ademas repite veinte veces un dato que solo cambia una vez. Asi el eje
    de arriba lleva el dia y el de abajo el mes, agrupado con su tramo.
    """
    if not por_dia:
        return ""
    # LOS DIAS SIN NADA TAMBIEN OCUPAN SITIO. Si se dibujan solo los dias
    # que aparecen en los datos, el eje sale "22, 23, 28, 29..." y deja de
    # ser una linea de tiempo: un hueco de cuatro dias sin actividad ---que
    # es justo lo que hay que ver--- se convierte en dos barras vecinas.
    # Pasaba con Dionaea, que estuvo cuatro dias sin anotar una conexion.
    por_dia = rellena_dias(por_dia)
    dias = sorted(por_dia)
    an, alto_barras = 860, 250
    izq, der, arriba = 62, 16, 14
    abajo = 116 if pie else 76
    al = arriba + alto_barras + abajo
    maximo = max(por_dia.values()) or 1
    paso_x = (an - izq - der) / float(len(dias))
    ancho = max(3.0, paso_x * 0.68)
    o = ['<svg viewBox="0 0 %d %d" width="100%%" role="img" '
         'aria-label="%s">' % (an, al, esc(titulo))]

    # Rejilla horizontal con su cifra: sin ella, las barras se comparan
    # entre si pero no se sabe de que orden de magnitud se habla.
    for frac in (0.25, 0.5, 0.75, 1.0):
        y = arriba + alto_barras - alto_barras * frac
        o.append('<line x1="%d" y1="%.1f" x2="%d" y2="%.1f" stroke="#e4e8ed"/>'
                 % (izq, y, an - der, y))
        o.append('<text x="%d" y="%.1f" text-anchor="end" font-size="11" '
                 'fill="#909aa6" dominant-baseline="middle">%s</text>'
                 % (izq - 8, y, miles(int(maximo * frac))))

    MESES = MESES_ES
    globos = []
    tramos = []
    for i, d in enumerate(dias):
        v = por_dia[d]
        x = izq + i * paso_x + (paso_x - ancho) / 2.0
        h = max(1.5, alto_barras * (v / float(maximo)))
        y = arriba + alto_barras - h
        col = color_rampa(v, maximo)
        o.append('<rect class="gf gf%d" x="%.1f" y="%.1f" width="%.1f" '
                 'height="%.1f" rx="2" fill="%s">'
                 '<title>%s: %s</title></rect>'
                 % (i + 1, x, y, ancho, h, col, d.isoformat(), miles(v)))
        # A DOS LINEAS: la fecha arriba y la cifra CON SU UNIDAD debajo.
        # En una sola, "2026-09-11: 180.000 participaciones" son sesenta
        # caracteres y el globo cruzaba media figura.
        globos.append(globo(i + 1, x + ancho / 2.0, y,
                            (d.isoformat(),
                             nu(v, unidad)), an, col))
        # Eje de arriba: el numero de dia. Con muchos dias se ensena uno de
        # cada dos, porque si no los numeros se tocan y no se lee ninguno.
        if len(dias) <= 32 or i % 2 == 0:
            xc = izq + i * paso_x + paso_x / 2.0
            o.append('<text x="%.1f" y="%.1f" text-anchor="middle" '
                     'font-size="11" fill="#5d6673">%d</text>'
                     % (xc, arriba + alto_barras + 15, d.day))
            # Y DEBAJO, LA INICIAL DEL DIA DE LA SEMANA. Miercoles es X
            # ---no M--- para no chocar con martes, que es como se abrevia
            # en espanol. weekday() da lunes=0, asi que el orden es fijo.
            o.append('<text x="%.1f" y="%.1f" text-anchor="middle" '
                     'font-size="9" fill="#aeb6c0">%s</text>'
                     % (xc, arriba + alto_barras + 26,
                        "LMXJVSD"[d.weekday()]))
        clave = (d.year, d.month)
        if not tramos or tramos[-1][0] != clave:
            tramos.append([clave, i, i])
        else:
            tramos[-1][2] = i
    o.append('<line x1="%d" y1="%.1f" x2="%d" y2="%.1f" stroke="#c8cfd8"/>'
             % (izq, arriba + alto_barras, an - der, arriba + alto_barras))

    # Eje de abajo: el mes, una vez por tramo y en grande.
    ybase = arriba + alto_barras + 40
    for (anio, mes), i0, i1 in tramos:
        x0 = izq + i0 * paso_x + 1
        x1 = izq + (i1 + 1) * paso_x - 1
        o.append('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" '
                 'stroke="#9aa3ae" stroke-width="1.5"/>'
                 % (x0, ybase, x1, ybase))
        for x in (x0, x1):
            o.append('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" '
                     'stroke="#9aa3ae" stroke-width="1.5"/>'
                     % (x, ybase, x, ybase - 5))
        o.append('<text x="%.1f" y="%.1f" text-anchor="middle" font-size="16" '
                 'font-weight="600" fill="#38404d">%s de %d</text>'
                 % ((x0 + x1) / 2.0, ybase + 20, MESES[mes - 1], anio))
    # UNA LLAVE DEBAJO DE TODO, PARA DECIR QUE ES "TODO". Con los meses
    # agrupados, lo que se ve son dos tramos ---agosto y septiembre--- y no
    # hay nada que diga si eso es una muestra de un periodo mas largo o es
    # el periodo entero. Son cosas distintas al leer las cifras, y la
    # diferencia no se puede deducir de la figura.
    if pie:
        ypie = ybase + 34
        x0, x1 = izq + 1, an - der - 1
        o.append('<line x1="%.1f" y1="%d" x2="%.1f" y2="%d" '
                 'stroke="#c8cfd8" stroke-width="1.5"/>' % (x0, ypie, x1, ypie))
        for x in (x0, x1):
            o.append('<line x1="%.1f" y1="%d" x2="%.1f" y2="%d" '
                     'stroke="#c8cfd8" stroke-width="1.5"/>'
                     % (x, ypie, x, ypie - 6))
        o.append('<text x="%.1f" y="%d" text-anchor="middle" font-size="13" '
                 'fill="#5d6673">%s</text>'
                 % ((x0 + x1) / 2.0, ypie + 18, esc(pie)))
    o.append('<g class="gtp">%s</g>' % "".join(globos))
    o.append("</svg>")
    return "".join(o)

# ------------------------------------------------------------ el indice
#
# UN BOTON EN CADA BANDA Y UNA SOLA CASILLA. Las diez etiquetas apuntan al
# mismo <input>, asi que da igual en cual se pulse. El boton va DENTRO del
# h2 y no flotando: la banda ya coloca su contenido en la columna, asi que
# queda alineado sin calcular ningun margen y no se despega nunca.
#
# DONDE ESTAMOS: se marca con :target, o sea el apartado al que se ha
# SALTADO. Seguir el scroll de verdad ---ir destacando segun se baja--- no
# se puede sin JavaScript, y el informe no ejecuta nada. La regla por
# apartado se genera aqui, igual que las de los globos.
CSS_IX = []

# --------------------------------------------------- el guion del indice
#
# EL UNICO JAVASCRIPT DEL INFORME, y va ENTERO AQUI DENTRO: no descarga
# nada, no usa librerias y no toca la red, asi que el fichero sigue siendo
# uno solo y se abre igual en cualquier maquina y sin conexion. Eso era lo
# que protegia la regla de "no ejecutar nada", y se sigue cumpliendo.
#
# HACE DOS COSAS, LAS DOS PRESCINDIBLES. Sin el, el informe se lee entero:
# el indice sigue marcando el apartado al que se SALTA (con :target) y las
# franjas se siguen pegando; lo que se pierde es que sigan al scroll.
#   1. Marca en el indice por donde vas.
#   2. Despega cada banda y cada franja en cuanto otra la releva, y coloca
#      la franja y las cabeceras de tabla segun lo que MIDE lo que hay
#      pegado encima (en un movil un titulo puede ocupar dos lineas).
GUION_IX = """<script>
(function () {
  var m = document.querySelector('main');
  if (!m) return;
  m.className = m.className ? m.className + ' js' : 'js';
  var tit = [].slice.call(m.querySelectorAll('h2[id],h3[id]'));
  var ap = null, sub = null;
  function mirar() {
    /* offsetTop Y NO getBoundingClientRect: el rect de un elemento PEGADO
       devuelve donde esta pintado (arriba del todo), no donde vive. Con el
       rect, una franja obsoleta colgada en 60px contaba como la actual, se
       marcaba fuera, se despegaba, volvia a contar... y parpadeaba.
       offsetTop no lo toca el pegado. */
    var corte = pageYOffset + 70, a = '', s = '';
    /* AL FONDO DEL TODO, el ultimo apartado. Los ultimos titulos pueden no
       llegar nunca a la linea de corte, porque el documento ya no da mas de
       si: al final de la pagina se marcaba el apartado ANTERIOR y no habia
       forma de llegar al ultimo. */
    if (pageYOffset + innerHeight >= document.documentElement.scrollHeight - 2) {
      corte = Infinity;
    }
    for (var i = 0; i < tit.length; i++) {
      if (tit[i].offsetTop > corte) break;
      if (tit[i].tagName === 'H2') { a = tit[i].id; s = ''; } else { s = tit[i].id; }
    }
    if (a !== ap) {
      ap = a;
      m.setAttribute('data-ap', a);
    }
    if (s !== sub) {
      sub = s;
      m.setAttribute('data-sub', s);
    }
    pegar();
  }
  /* QUE TITULO ESTA PEGADO DE VERDAD, Y CUANTO MIDE.
     Las bandas se relevan tapandose: la nueva se pinta encima de la vieja.
     Eso solo funciona si miden lo mismo, y en un movil no: un titulo largo
     ocupa dos lineas. Pasaban dos cosas:
       - la vieja, si era mas alta, ASOMABA por debajo de la nueva (la
         segunda linea de "1.1 ... capturas de Cowrie" se veia colgando
         bajo el 1.2);
       - la franja gris se pegaba a 60px fijos, y una banda de dos lineas
         mide 93: la gris le tapaba la segunda linea.
     Ahora se despega (clase "fuera") todo titulo ya relevado, y la franja
     gris y las cabeceras de tabla se colocan con la altura MEDIDA de lo
     que hay pegado encima, no con la que se supuso. */
  var raiz = document.documentElement.style;
  function pegar() {
    var y = pageYOffset, i2 = -1, i3 = -1, banda = 0;
    for (var i = 0; i < tit.length; i++) {
      var x = tit[i];
      if (x.tagName === 'H2') {
        if (x.offsetTop > y + 1) break;
        i2 = i; i3 = -1; banda = x.offsetHeight;
      } else if (i2 >= 0 && x.offsetTop <= y + banda + 1) {
        i3 = i;
      }
    }
    for (var j = 0; j < tit.length; j++) {
      var t = tit[j];
      t.classList.toggle('fuera', j < (t.tagName === 'H2' ? i2 : Math.max(i2, i3)));
    }
    raiz.setProperty('--banda', (i2 >= 0 ? tit[i2].offsetHeight : 60) + 'px');
    raiz.setProperty('--sub', (i3 >= 0 ? tit[i3].offsetHeight : 34) + 'px');
    document.body.classList.toggle('sin-sub', i3 < 0);
  }
  /* SIN requestAnimationFrame. Con el panel en segundo plano el navegador
     lo congela, y la bandera de "ya hay uno pedido" se quedaba puesta para
     siempre: al volver, esto no se actualizaba nunca mas. Llamar directo
     cuesta 26 lecturas de offsetTop, y el navegador ya limita el evento a
     una por fotograma. */
  addEventListener('scroll', mirar, { passive: true });
  addEventListener('resize', mirar);
  mirar();
})();
</script>"""


ICONO_IX = ('<svg viewBox="0 0 16 16" width="15" height="15" '
            'aria-hidden="true" fill="currentColor">'
            '<circle cx="1.6" cy="3" r="1.6"/><rect x="5" y="2" width="11" '
            'height="2" rx="1"/><circle cx="1.6" cy="8" r="1.6"/>'
            '<rect x="5" y="7" width="11" height="2" rx="1"/>'
            '<circle cx="1.6" cy="13" r="1.6"/><rect x="5" y="12" width="11" '
            'height="2" rx="1"/></svg>')

_RE_TITULO = re.compile(r"<(h2|h3)>(.*?)</\1>")


def con_indice(cuerpo: str) -> str:
    """Numera los titulos, mete el boton en las bandas y arma el indice.

    SE HACE AL FINAL Y DE UNA PASADA, no en cada sitio donde se escribe un
    titulo: son diez h2 y dieciseis h3 repartidos por mil lineas, y
    numerarlos donde nacen obliga a arrastrar un contador vivo por toda la
    funcion, que es justo lo que se olvida al anadir un apartado nuevo.

    LOS IDs VAN EN ASCII ---"ap-3-2" y no el titulo en minusculas--- porque
    un id es un ATRIBUTO, y hay una prueba que exige que ningun atributo
    lleve tildes. "#ap-actores-que-se-repiten" seria mas bonito de
    compartir y se rompe en cuanto alguien acentua un titulo.
    """
    entradas = []
    cuenta = {"h2": 0, "h3": 0, "visible": "0"}

    def marca(m):
        etiqueta, texto = m.group(1), m.group(2)
        if etiqueta == "h2":
            cuenta["h2"] += 1
            cuenta["h3"] = 0
            ident = "ap-%d" % cuenta["h2"]
            # EL NUMERO QUE SE ENSENA SE LEE DEL TITULO, no se cuenta
            # aparte: el anexo va con letra ("A.") y no con numero, y
            # el 9 solo existe si hay conclusiones, asi que un contador
            # propio se equivocaria.
            # Leyendolo, renumerar los apartados renumera los subapartados
            # solos.
            nm = re.match(r"\s*(\d+|[A-Z])\.", texto)
            cuenta["visible"] = nm.group(1) if nm else str(cuenta["h2"] - 1)
        else:
            cuenta["h3"] += 1
            ident = "ap-%d-%d" % (cuenta["h2"], cuenta["h3"])
            texto = "%s.%d&nbsp; %s" % (cuenta["visible"], cuenta["h3"], texto)
        entradas.append((etiqueta, ident, texto))
        # DOS REGLAS POR ENTRADA, y no una con dos selectores: mandan
        # cosas distintas. Sin guion manda :target ---el apartado al que se
        # salto---; con guion manda por donde vas, y entonces :target
        # sobra, porque si no quedarian DOS entradas marcadas a la vez.
        dato = "data-sub" if etiqueta == "h3" else "data-ap"
        CSS_IX.append(
            'main:not(.js):has(#%s:target) .ix a[href="#%s"],'
            ' main.js[%s="%s"] .ix a[href="#%s"]'
            ' { background: #fff7ed; border-left-color: #f97316;'
            ' color: #15181d; }' % (ident, ident, dato, ident, ident))
        if etiqueta == "h2":
            return '<h2 id="%s"><span>%s</span></h2>' % (ident, texto)
        return '<h3 id="%s">%s</h3>' % (ident, texto)

    marcado = _RE_TITULO.sub(marca, cuerpo)
    # AL RECARGAR, TODO COMO NACE. Los navegadores RESTAURAN el estado de
    # los controles de formulario ---es lo que hace que un formulario a
    # medias sobreviva a un F5--- y aqui eso significa que el informe se
    # abria con el indice desplegado, o con "Quien tiene mas IPs" puesto,
    # porque asi lo dejo quien lo miro antes. El marcado decia una cosa y
    # la pantalla ensenaba otra. autocomplete="off" lo desactiva sin
    # JavaScript, que es la unica via que tenemos.
    # EL BOTON ES UNO Y NO UNO POR BANDA. Al principio iba dentro de cada
    # h2 ---asi quedaba alineado con la columna sin calcular nada--- pero
    # cuando se ven dos bandas a la vez se veian DOS botones, y un control
    # que aparece duplicado deja de leerse como un control. Fijo en
    # pantalla es uno solo, esta siempre y no depende de que haya una banda
    # pegada; la alineacion se calcula, que es el precio.
    nav = ['<input type="checkbox" id="ix" autocomplete="off">',
           '<label class="ix-b" for="ix" title="Índice del informe">%s</label>'
           % ICONO_IX,
           '<label class="ix-f" for="ix"></label>',
           '<nav class="ix"><p class="ix-t">Ir a un apartado'
           '<label class="ix-x" for="ix" title="Cerrar">&times;</label></p>',
           "<ul>"]
    for etiqueta, ident, texto in entradas:
        nav.append('<li class="ix-%s"><a href="#%s">%s</a></li>'
                   % (etiqueta, ident, texto))
    nav.append("</ul></nav>")
    marcado += GUION_IX
    return "".join(nav) + marcado


# ==================================================== anonimizar
#
# SE HACE SOBRE EL HTML YA ESCRITO, NO DATO A DATO. Las IPs no salen solo
# en las columnas de IP: van dentro de las ordenes (wget http://IP/x.sh),
# en las URLs de origen de las muestras, en los ejemplos de las TTPs, en
# los globos de las figuras. Sustituirlas donde nace cada tabla deja
# fuera justo la que nadie esperaba. Pasando una vez por todo el texto,
# no se escapa ninguna.
#
# CADA IP SE CAMBIA SIEMPRE POR LA MISMA ETIQUETA dentro del informe
# (<IP-CN-004> es la misma maquina en todas las tablas), asi que las
# cuentas y los cruces se siguen pudiendo leer. Entre dos informes, no:
# el numero sale del orden de aparicion.
_OCTETO = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_RE_IPV4 = re.compile(r"(?<![\d.])(%s(?:\.%s){3})(/24)?(?!\d|\.\d)"
                      % (_OCTETO, _OCTETO))
_RE_IPV6 = re.compile(r"(?<![0-9A-Za-z:])(?:[0-9a-fA-F]{0,4}:){2,7}"
                      r"[0-9a-fA-F]{0,4}(?![0-9A-Za-z:.])")
# Las claves privadas que pegan los atacantes, en claro y en base64
# ("LS0tLS1CRUdJTi" es "-----BEGIN"). El cuerpo se quita; la cabecera se
# deja, porque que alguien intente dejar una clave tambien es un dato.
_RE_CLAVE = re.compile(r"(-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----)"
                       r".*?(-----END [A-Z0-9 ]*PRIVATE KEY-----|(?=[<\"]))",
                       re.S)
_RE_CLAVE_B64 = re.compile(r"LS0tLS1CRUdJTi[A-Za-z0-9+/=]{20,}")


def ips_del_senuelo(f) -> list[str]:
    """Las IPs publicas en las que escucha Dionaea, de su propia base."""
    if not f.dionaea_db:
        return []
    try:
        con = sqlite3.connect("file:%s?mode=ro" % f.dionaea_db[0], uri=True)
        vistas = [r[0] for r in con.execute(
            "SELECT DISTINCT local_host FROM connections")]
        con.close()
    except sqlite3.Error:
        return []
    return sorted(ip for ip in vistas
                  if ip and not es_nuestra(ip) and _RE_IPV4.fullmatch(ip))


def anonimiza(html: str, geo, vps) -> tuple[str, dict]:
    """Devuelve el HTML sin IPs ni claves privadas, y lo que ha cambiado."""
    etiquetas, por_pais = {}, collections.Counter()
    vps = list(dict.fromkeys(vps))
    for i, ip in enumerate(vps):
        etiquetas[ip] = "[IP VPS]" if i == 0 else "[IP VPS %d]" % (i + 1)

    def etiqueta(ip, red=False):
        clave = ip + ("/24" if red else "")
        if clave not in etiquetas:
            cc = geo.cc(ip) or "XX"
            tipo = "RED" if red else "IP"
            por_pais[(tipo, cc)] += 1
            etiquetas[clave] = "&lt;%s-%s-%03d&gt;%s" % (
                tipo, cc, por_pais[(tipo, cc)], "/24" if red else "")
        return etiquetas[clave]

    def v4(m):
        ip, red = m.group(1), bool(m.group(2))
        if es_nuestra(ip) or ip in ("0.0.0.0", "255.255.255.255"):
            return m.group(0)
        return etiqueta(ip, red)

    def v6(m):
        try:
            a = ipaddress.IPv6Address(m.group(0))
        except ValueError:
            return m.group(0)
        if a.is_unspecified or es_nuestra(str(a)):
            return m.group(0)
        return etiqueta(str(a))

    claves = [0]

    def sin_clave(m):
        claves[0] += 1
        return m.group(1) + "&lt;CLAVE PRIVADA OMITIDA&gt;" + m.group(2)

    def sin_clave_b64(m):
        claves[0] += 1
        return "&lt;CLAVE PRIVADA OMITIDA&gt;"

    html = _RE_CLAVE.sub(sin_clave, html)
    html = _RE_CLAVE_B64.sub(sin_clave_b64, html)
    html = _RE_IPV4.sub(v4, html)
    html = _RE_IPV6.sub(v6, html)
    return html, {
        "ips": sum(n for (t, _c), n in por_pais.items() if t == "IP"),
        "redes": sum(n for (t, _c), n in por_pais.items() if t == "RED"),
        "vps": sum(1 for ip in vps if etiquetas[ip] in html),
        "claves": claves[0]}


def sin_rutas(t: str) -> str:
    """Cada ruta absoluta, reducida a su ultimo nombre: no dice de quien
    es el ordenador ni donde guarda las cosas."""
    return re.sub(r"(?:[A-Za-z]:)?[\\/][^\s\"']*[\\/]([^\\/\s\"']+)", r"\1", t)


# ==================================================== el informe
def informe(args) -> str:
    tz = resolver_huso(args.tz)
    f = Fuentes(args.respaldo)
    geo = Geo(args.geoip)
    o = []
    w = o.append

    sesiones, lineas, rotas, propias = lee_cowrie(f.cowrie_log, tz)
    conordenes = [s for s in sesiones.values() if s.ordenes]
    ips = {s.ip for s in sesiones.values() if s.ip}
    marcas = [s.inicio for s in sesiones.values() if s.inicio]
    # CUANTOS DIAS CUBRE ESTE RESPALDO. Se CALCULA, no se escribe a mano.
    # El informe se vuelve a generar sobre respaldos cada vez mas largos, y
    # una cifra escrita en el texto envejece en silencio: las figuras
    # ensenarian veintiseis dias y la letra seguiria diciendo veintiuno.
    n_dias = ((max(marcas).date() - min(marcas).date()).days + 1
              if marcas else 0)
    n_cmd = sum(len(s.ordenes) for s in sesiones.values())
    n_mal = sum(len(s.creds_mal) for s in sesiones.values())
    n_ok = sum(len(s.creds_ok) for s in sesiones.values())

    # --- la memoria del bot: baneos y recuentos --------------------------
    baneadas, mem_txt = set(), ""
    if f.memoria:
        try:
            with open(f.memoria[0], encoding="utf-8") as fh:
                mem = json.load(fh)
            baneadas = set(mem.get("banned", []))
            mem_txt = ("%s, %s, %s y %s"
                       % (cuantos(len(mem.get("playbooks", {})), "guion", "guiones"),
                          cuantos(len(mem.get("ips", {})), "IP", "IPs"),
                          cuantos(len(mem.get("samples", [])), "muestra", "muestras"),
                          cuantos(len(mem.get("creds", [])), "credencial", "credenciales")))
        except (OSError, ValueError):
            pass

    # --- lo publicado, del estado del reporter ---------------------------
    publicadas, denunciadas = set(), set()
    if f.estado_rep:
        try:
            con = sqlite3.connect("file:%s?mode=ro" % f.estado_rep[0], uri=True)
            # LAS CLAVES NO SON EL HASH A SECAS. Cada reporter compone la
            # suya con lo que necesita para no repetirse: AbuseIPDB pone
            # "<ip>@<fecha>" y MalwareBazaar "upload:<sha256>" y
            # "comment:<sha256>", que son dos envios distintos de la misma
            # muestra. Cortar solo por "@" dejaba "upload:0936b1..." y
            # entonces NINGUNA muestra casaba: el informe decia "0
            # publicados" con 843 envios a VirusTotal en la misma base.
            #
            # No se parte por ":" ---una IPv6 esta llena de dos puntos---:
            # se busca un hash dentro de la clave, y si no lo hay se usa lo
            # que haya antes de la arroba, que es la IP.
            rx_hash = re.compile(r"[0-9a-fA-F]{64}|[0-9a-fA-F]{32}")
            for plat, clave in con.execute("SELECT platform, key FROM sent"):
                base = str(clave).split("@")[0]
                m = rx_hash.search(base)
                publicadas.add((m.group(0) if m else base).lower())
                if plat == "abuseipdb":
                    denunciadas.add(base.lower())
            con.close()
        except sqlite3.Error:
            pass

    w("<h1>Análisis del señuelo</h1>")
    w('<p class="sub">%s a %s &middot; generado el %s desde <code>%s</code></p>'
      % (esc(fecha(min(marcas)) if marcas else "?"),
         esc(fecha(max(marcas)) if marcas else "?"),
         datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
         esc(os.path.basename(os.path.normpath(args.respaldo)))))
    w('<div class="aviso ok"><b>Todo lo que sigue es OBSERVADO</b>: sale de '
      'contar los registros y se puede volver a comprobar en el mismo '
      'fichero. La columna ATT&amp;CK es la única <b>inferida</b>, y sale de '
      '<code>ANALISIS/ttp.tsv</code>. <b>Ninguna muestra se ha ejecutado</b>: '
      'de los binarios solo se lee el contenido para calcular su hash.</div>')
    # LA HORA, DICHA UNA VEZ Y ARRIBA. Todas las marcas del informe van en
    # UTC, pero eso solo se decia en la linea de "generado el ...", que
    # habla de OTRA hora ---la de generacion---. Una fecha sin huso en un
    # informe que se lee en otro sitio no significa nada, y aqui ademas hay
    # una correccion por medio que el lector tiene derecho a saber.
    w("<!--anonimizado-->")
    w('<p class="nota"><b>Todas las fechas y horas de este informe van en '
      'UTC</b>, incluidas las de las tablas. Cowrie firma sus marcas con una &quot;Z&quot;, pero escribe la <b>hora local del contenedor</b>, así que se '
      'reinterpretan como <code>%s</code> y se convierten a UTC al leerlas; '
      'sin esa corrección, las marcas saldrían corridas y con pinta de '
      'correctas. Dionaea sí guarda UTC de verdad.</p>' % esc(args.tz))

    # ============================================== 1. lo que no se sabe
    #
    # LOS LIMITES VAN DELANTE Y LA METODOLOGIA DETRAS. Lo primero se
    # tiene que leer antes que cualquier cifra; lo segundo solo le hace
    # falta a quien quiera repetir el informe, y arriba retrasaba los
    # datos varias pantallas. Los avisos (lineas rotas, sesiones
    # nuestras, fuentes que faltan) se quedan aqui: cambian como se
    # leen las cifras.
    # LO QUE NO SE PUEDE SABER, ESCRITO POR NOSOTROS. Un informe que no
    # dice donde estan sus limites obliga al lector a suponerlos, y va a
    # suponer mal en las dos direcciones: o se lo cree entero o no se cree
    # nada. Esto no lo debilita; lo blinda.
    w("<h2>1. Lo que este informe no puede saber</h2>")
    w(lista([
        "<b>El país de una IP no es el país de quien ataca.</b> La "
        "geolocalización es aproximada y sale de una tabla pública; una VPN, "
        "un proxy o una máquina ajena ya comprometida salen con el país de "
        "la máquina, no con el de la persona.",
        "<b>Una IP no es una persona ni un actor.</b> Detrás de una "
        "dirección puede haber una red entera con NAT, y un mismo operador "
        "puede ir rotando por cientos de direcciones. Cuando aquí se habla de &quot;IPs distintas&quot;, se habla solo de direcciones.",
        "<b>Cowrie emula un shell.</b> Lo que se ve es lo que el atacante "
        "hizo <b>contra un señuelo</b>: qué habría hecho en una máquina de "
        "verdad no se puede saber, y hay herramientas que se van en cuanto "
        "algo no responde como esperan.",
        "<b>Unos días de datos no son una tendencia.</b> Sirven para "
        "describir este periodo, no para decir que algo sube o baja.",
        "<b>Esto es una máquina, en un proveedor, en un país.</b> Lo que "
        "recibe un señuelo depende del rango en el que esté; no es una muestra de todo internet.",
        "<b>Lo que Cowrie no pudo decodificar se perdió antes de llegar "
        "aquí.</b> Los bytes que anotó como carácter de reemplazo no están "
        "en el registro y no hay forma de recuperarlos.",
        "<b>La columna ATT&amp;CK es interpretación nuestra</b>, y la única "
        "del informe: sale de <code>ttp.tsv</code>, que escribimos a mano.",
    ]))

    if rotas:
        w('<div class="aviso"><b>%s de <code>cowrie.json</code> no se '
          '%s podido leer</b> (de %s). Suele ser el respaldo hecho en '
          'caliente: la última línea se quedó a medias. Se %s descartado y '
          'no cuenta%s en nada de lo que sigue.</div>'
          % (cuantos(rotas, "línea", "líneas"), "ha" if rotas == 1 else "han",
             miles(lineas), "ha" if rotas == 1 else "han",
             "" if rotas == 1 else "n"))

    # LO NUESTRO TAMBIEN SE DICE, igual que las lineas rotas y que el
    # auth.log del propio senuelo. Si no se dijera, la unica pista de que
    # faltan sesiones seria que las cifras no cuadran con el log ---y eso se
    # descubre tarde y mal---.
    n_ses_p, n_cmd_p, ips_p = propias
    if n_ses_p or n_cmd_p:
        w('<div class="aviso"><b>%s %s NUESTRA%s y se %s descartado.</b> %s de %s, que no %s de internet, sino el propio señuelo hablando consigo mismo: al '
          'probarlo desde la VPS, la conexión entra por la puerta de enlace '
          'del puente de Docker y Cowrie la anota como una sesión más, con '
          'sus logins y sus órdenes. No es un ataque y no cuenta en nada de '
          'lo que sigue. El reporter ya las descartaba por su cuenta '
          '(<code>ipguard</code>), así que nunca se ha denunciado a '
          'nadie por esto.</div>'
          % (y_lista([cuantos(n_ses_p, "sesión", "sesiones") if n_ses_p else "",
                      cuantos(n_cmd_p, "orden", "órdenes") if n_cmd_p else ""]),
             "es" if n_ses_p + n_cmd_p == 1 else "son",
             "" if n_ses_p + n_cmd_p == 1 else "S",
             "ha" if n_ses_p + n_cmd_p == 1 else "han",
             "Viene" if n_ses_p + n_cmd_p == 1 else "Vienen",
             y_lista("<code>%s</code>" % esc(x) for x in ips_p),
             "es una dirección" if len(ips_p) == 1 else "son direcciones"))

    faltan = [nombre for nombre, _q, hallado in f.filas() if not hallado]
    if faltan:
        w('<div class="aviso"><b>%s del respaldo no %s</b>: %s. Lo que '
          'depende de %s sale vacío, y no porque no hubiera actividad. El '
          'anexo del final dice qué se buscó y dónde.</div>'
          % (cuantos(len(faltan), "fuente", "fuentes").capitalize(),
             "estaba" if len(faltan) == 1 else "estaban",
             y_lista(esc(x) for x in faltan),
             "ella" if len(faltan) == 1 else "ellas"))

    # ============================================== A. anexo
    #
    # SE ESCRIBE AQUI Y SE PEGA AL FINAL. Lo que se calcula en este
    # bloque (los ficheros de capturas) lo usan los apartados de
    # abajo, asi que no se puede mover el codigo: se mueve la salida.
    anexo = []
    w = anexo.append
    w("<h2>A. De dónde salen los datos</h2>")
    w("<p>Una sección vacía más arriba puede significar dos cosas distintas: "
      "que no hubo actividad, o que el fichero no estaba en el respaldo. "
      "Esta tabla las separa.</p>")

    def ficheros_en(carpetas):
        """Nombre -> ruta de todo lo que hay en esas carpetas."""
        out = {}
        for carpeta in carpetas:
            if not os.path.isdir(carpeta):
                continue
            for nombre in os.listdir(carpeta):
                ruta = os.path.join(carpeta, nombre)
                if os.path.isfile(ruta):
                    out[nombre] = ruta
        return out

    ficheros_cow = ficheros_en(f.cowrie_dl)
    ficheros_dio = ficheros_en(f.dionaea_bin)
    clases = collections.Counter(clase_fichero(n) for n in ficheros_cow)

    filas = []
    for nombre, que, hallado in f.filas():
        if not hallado:
            filas.append([esc(nombre), mono(que),
                          '<b style="color:#b3261e">NO ESTÁ</b>', ""])
            continue
        if os.path.isdir(hallado[0]):
            n = len([x for x in os.listdir(hallado[0])
                     if os.path.isfile(os.path.join(hallado[0], x))])
            det = cuantos(n, "fichero", "ficheros")
        else:
            tam = sum(os.path.getsize(x) for x in hallado if os.path.isfile(x))
            det = "%s, %s" % (cuantos(len(hallado), "fichero", "ficheros"),
                              tamano(tam))
        filas.append([esc(nombre), mono(que), "sí", det])
    w(tabla(["Fuente", "Qué", "Está", "Detalle"], filas))

    # EL DIRECTORIO DE CAPTURAS NO ES TODO MALWARE, y decir "28.395 ficheros"
    # como si lo fuera multiplica la cifra por siete.
    if clases:
        w("<h3>Y qué hay en el directorio de capturas de Cowrie</h3>")
        w(tabla(["Qué es", "Ficheros", "Qué significa"], [
            ["Capturas", miles(clases.get("captura", 0)),
             "Ficheros con nombre SHA-256: esto sí es malware capturado"],
            ["Sondas de escritura", miles(clases.get("redir", 0)),
             "Ficheros de 0 bytes que deja Cowrie cuando el atacante redirige "
             "la salida a un fichero para ver si puede escribir (por ejemplo "
             "<code>&gt;/var/run/.x</code>). <b>No son muestras</b>: son la huella de una prueba para encontrar un directorio escribible"],
            ["Temporales", miles(clases.get("temporal", 0)),
             "Restos de <code>tempfile</code>"],
            ["Otros", miles(clases.get("otro", 0)), "Sin clasificar"],
        ], numericas=(1,)))

    # CADENA DE CUSTODIA. Sin esto, el informe es un panel bonito: nadie
    # de fuera puede repetirlo ni comprobar que se hizo sobre lo que dice.
    # Con el hash de cada fuente, cualquiera puede coger el respaldo, sacar
    # los mismos hashes y saber que mira exactamente los mismos bytes.
    #
    # SE HASHEAN LOS FICHEROS, NO LOS DIRECTORIOS. Las capturas ya van una
    # a una en el apartado 6 ---con su SHA-256 calculado del fichero--- y
    # repetir aqui cuatro mil hashes no anade nada.
    w("<h3>Cómo se ha hecho este informe</h3>")
    w("<p>Para que esto se pueda <b>repetir y comprobar</b>: de dónde "
      "salieron los datos, con qué se leyeron y qué hay exactamente dentro "
      "de cada fuente. Los hashes son de los ficheros del respaldo <b>tal "
      "como estaban al leerlos</b>.</p>")
    guion_sha, _md5 = hashes_de(os.path.abspath(__file__))
    w(tabla(["Qué", "Valor"], [
        # ANONIMIZADO, SIN RUTAS: la ruta completa dice el usuario del
        # ordenador y donde guarda las cosas, y para repetir el informe
        # basta con el nombre del respaldo.
        ["Respaldo analizado", mono(
            os.path.basename(os.path.normpath(args.respaldo))
            if args.anonimizar else os.path.abspath(args.respaldo))],
        ["Orden que lo generó", mono(recorta(
            sin_rutas(" ".join(sys.argv)) if args.anonimizar
            else " ".join(sys.argv), 96))],
        ["Herramienta", "%s &middot; SHA-256 %s"
         % (mono(os.path.basename(__file__)), mono(guion_sha[:32] + "…"))],
        ["Entorno", esc("Python %s en %s"
                        % (sys.version.split()[0], sys.platform))],
        ["Generado", esc(datetime.now(timezone.utc)
                         .strftime("%Y-%m-%d %H:%M:%S UTC"))],
        ["Huso aplicado a Cowrie", mono(args.tz)],
    ]))

    filas_h = []
    detalles = []
    for nombre, patron, rutas in f.filas():
        ficheros = [r for r in (rutas or []) if os.path.isfile(r)]
        carpetas = [r for r in (rutas or []) if os.path.isdir(r)]
        if not ficheros and not carpetas:
            filas_h.append([esc(nombre), mono(patron), "-",
                            "<b>no estaba en el respaldo</b>"])
            continue
        if carpetas:
            n = sum(len([x for x in os.listdir(c)
                         if os.path.isfile(os.path.join(c, x))])
                    for c in carpetas)
            filas_h.append([
                esc(nombre), mono(patron), cuantos(n, "fichero", "ficheros"),
                "el SHA-256 de cada uno se calcula aparte (ver "
                "&quot;Malware capturado&quot;)"])
            continue
        cada = sorted((os.path.basename(r), hashes_de(r)[0],
                       os.path.getsize(r)) for r in ficheros)
        # HASH DE HASHES cuando la fuente son varios ficheros: el resumen
        # de la lista ordenada "sha256 nombre". Cambia si cambia cualquiera
        # de ellos, y se puede rehacer a mano con sha256sum y sort.
        # ORDENADO POR LINEA, no por nombre: asi es EXACTAMENTE lo
        # que sale de `sha256sum * | sort | sha256sum`, que es la
        # orden que el informe publica. Un resumen que no se puede
        # rehacer con la orden que se da no sirve de nada.
        junto = hashlib.sha256("".join(
            sorted("%s  %s\n" % (h, n_) for n_, h, _t in cada))
            .encode("utf-8")).hexdigest()
        filas_h.append([
            esc(nombre), mono(patron),
            "%s &middot; %s" % (plural(len(cada), "fichero", "ficheros"),
                                tamano(sum(t for _n, _h, t in cada))),
            mono((cada[0][1] if len(cada) == 1 else junto)[:32] + "…")])
        if len(cada) > 1:
            detalles.append(
                "<details><summary>Los %s ficheros de <b>%s</b>, uno a uno"
                "</summary><pre>%s</pre></details>"
                % (miles(len(cada)), esc(nombre),
                   esc("\n".join("%s  %s" % (h, n_) for n_, h, _t in cada))))
    w(tabla(["Fuente", "Patrón", "Qué hay", "SHA-256"], filas_h))
    w('<p class="pie">Cuando una fuente son <b>varios ficheros</b>, el hash '
      'de la tabla es el de la lista ordenada de sus hashes: exactamente '
      'lo que sale de <code>sha256sum FICHEROS | sort | sha256sum</code> '
      'en la carpeta del respaldo. No es el hash de ningún fichero '
      'concreto; los individuales están aquí debajo.</p>')
    for d in detalles:
        w(d)
    w('<p class="pie">Con el mismo respaldo y la misma herramienta, las '
      'cifras salen iguales: lo único que cambia entre dos ejecuciones es '
      'la marca de generación de arriba.</p>')

    w = o.append

    # ============================================== 2. resumen
    w("<h2>2. Resumen</h2>")

    # Todo lo que se cuenta por pais y por dia, de una vez: lo usan el
    # resumen, la lista de paises y los tres esquemas.
    ses_pais = collections.Counter()
    cmd_pais = collections.Counter()
    ip_pais = collections.Counter()
    ban_pais = collections.Counter()
    por_dia = collections.Counter()
    for s_ in sesiones.values():
        if s_.inicio:
            por_dia[s_.inicio.date()] += 1
        c = geo.cc(s_.ip) if s_.ip else ""
        if c:
            ses_pais[c] += 1
            cmd_pais[c] += len(s_.ordenes)
    vistas_ip = set()
    for s_ in sesiones.values():
        if s_.ip and s_.ip not in vistas_ip:
            vistas_ip.add(s_.ip)
            c = geo.cc(s_.ip)
            if c:
                ip_pais[c] += 1
                if s_.ip in baneadas:
                    ban_pais[c] += 1

    # --- Lo mismo, pero del lado de Dionaea ------------------------------
    #
    # Son magnitudes DISTINTAS y hay que tenerlo presente: de Cowrie se
    # cuentan sesiones (alguien entra a un shell) y de Dionaea conexiones
    # (alguien toca un puerto). Se pueden poner juntas como "conexiones de
    # ataque" porque las dos son un intento de contacto, pero lo que NO se
    # puede es sumar ordenes de Cowrie con conexiones de Dionaea: Dionaea
    # no tiene shell y no hay ordenes que contar.
    dia_dio = collections.Counter()
    ip_pais_dio = collections.Counter()
    conn_pais_dio = collections.Counter()
    conn_ip_dio = collections.Counter()
    hora_dio = collections.Counter()
    ips_dio = set()
    if f.dionaea_db:
        try:
            con = sqlite3.connect("file:%s?mode=ro" % f.dionaea_db[0], uri=True)
            for d, n in con.execute(
                    "SELECT date(connection_timestamp,'unixepoch'), COUNT(*) "
                    "FROM connections WHERE connection_type='accept' "
                    "GROUP BY 1"):
                if d:
                    try:
                        dia_dio[datetime.strptime(d, "%Y-%m-%d").date()] = n
                    except ValueError:
                        pass
            # La hora de Dionaea sale de la base y en UTC: sus marcas si
            # son UTC de verdad, al reves que las de Cowrie.
            for h, n in con.execute(
                    "SELECT CAST(strftime('%H', "
                    "datetime(connection_timestamp,'unixepoch')) AS INTEGER), "
                    "COUNT(*) FROM connections WHERE connection_type='accept' "
                    "GROUP BY 1"):
                if h is not None:
                    hora_dio[int(h)] += n
            for ip, n in con.execute(
                    "SELECT remote_host, COUNT(*) FROM connections "
                    "WHERE connection_type='accept' GROUP BY remote_host"):
                if not ip:
                    continue
                ips_dio.add(ip)
                conn_ip_dio[ip] = n
                c = geo.cc(ip)
                if c:
                    ip_pais_dio[c] += 1
                    conn_pais_dio[c] += n
            con.close()
        except sqlite3.Error:
            pass

    # --- Por protocolo ---------------------------------------------------
    #
    # EL PUERTO QUE SE ENSENA ES EL PUBLICO, NO EL INTERNO. Cowrie escucha
    # en 2222 y 2223 dentro del contenedor, pero el atacante marco el 22 y
    # el 23: Docker hace la traduccion. Poner 2222 en un informe seria
    # contar nuestra fontaneria en vez de lo que hizo el atacante --- es la
    # misma correccion que ya hace el colector del reporter.
    NOMBRE_PROTO = {"ssh": ("SSH", 22), "telnet": ("Telnet", 23),
                    "smbd": ("SMB", 445), "mssqld": ("MSSQL", 1433),
                    "epmapper": ("RPC", 135), "httpd": ("HTTP", 80),
                    "ftpd": ("FTP", 21), "mysqld": ("MySQL", 3306),
                    "SipSession": ("SIP", 5060), "pptpd": ("PPTP", 1723),
                    "mqttd": ("MQTT", 1883), "tftpd": ("TFTP", 69)}

    def bonito(proto):
        # "Telnet (Puerto 23)" y no "Telnet (23)": un numero suelto entre
        # parentesis al lado de un nombre no dice que es, y en un informe
        # lleno de cifras ---sesiones, IPs, contactos--- se lee como una mas.
        n, pt = NOMBRE_PROTO.get(proto, (proto or "?", 0))
        return "%s (puerto %s)" % (n, pt) if pt else n

    proto_total = collections.Counter()
    proto_pais = collections.defaultdict(collections.Counter)
    for s_ in sesiones.values():
        if not s_.protocolo:
            continue
        etq = bonito(s_.protocolo)
        proto_total[etq] += 1
        c = geo.cc(s_.ip) if s_.ip else ""
        if c:
            proto_pais[etq][c] += 1
    if f.dionaea_db:
        try:
            con = sqlite3.connect("file:%s?mode=ro" % f.dionaea_db[0], uri=True)
            for proto, ip, n in con.execute(
                    "SELECT connection_protocol, remote_host, COUNT(*) "
                    "FROM connections WHERE connection_type='accept' "
                    "GROUP BY 1, 2"):
                etq = bonito(proto)
                proto_total[etq] += n
                c = geo.cc(ip) if ip else ""
                if c:
                    proto_pais[etq][c] += n
            con.close()
        except sqlite3.Error:
            pass

    # Y el total: por dia se suman (las dos cosas son contactos), y por pais
    # las IPs se UNEN sin duplicar --- una misma IP que toque los dos
    # senuelos es una sola IP, no dos.
    dia_total = collections.Counter(por_dia)
    dia_total.update(dia_dio)
    ip_pais_total = collections.Counter()
    for ip in (vistas_ip | ips_dio):
        c = geo.cc(ip)
        if c:
            ip_pais_total[c] += 1


    # LA COLA LARGA DE PAISES. Las tablas y los esquemas ensenan los de
    # arriba, y eso deja fuera a la mayoria: hay paises con UNA sola IP que
    # no salen en ningun sitio y que tambien han atacado. El recuento va
    # entero, sobre todas las IPs y no sobre las mostradas.
    paises_todos = ip_pais_total
    ips_todas = vistas_ip | ips_dio
    solo_una = sum(1 for _c, n in paises_todos.items() if n == 1)
    sin_pais = len(ips_todas) - sum(paises_todos.values())

    # CUATRO BLOQUES Y NO DIEZ TARJETAS IGUALES.
    #
    # Las diez cifras del resumen NO son del mismo tipo, y una rejilla de diez
    # rectangulos identicos dice que si lo son. Hay cuatro clases mezcladas:
    # un todo con sus dos partes (participaciones = Cowrie + Dionaea), dos
    # proporciones, dos dimensiones (cuantas IPs, cuantos paises) y una cosa
    # que hicimos NOSOTROS (las baneadas). Cada una pide una forma.
    #
    # LAS DOS PROPORCIONES VAN POR SEPARADO Y NO EN UN EMBUDO DE TRES PASOS,
    # que es lo primero que se penso y habria sido falso: `conordenes` cuenta
    # SESIONES y `n_ok` cuenta INTENTOS DE CREDENCIAL. No son subconjuntos uno
    # del otro ni comparten unidad, asi que encadenarlos en una sola figura
    # seria mezclar dos escalas ---exactamente lo que este informe no hace en
    # ninguna otra parte---.
    n_dio = sum(dia_dio.values())
    total_part = len(sesiones) + n_dio
    # Se lee una sola vez y lo usan los dos apartados que hablan de baneos:
    # la franja del resumen y el desglose del apartado de IPs. Leerlo dos
    # veces es la forma de que un dia digan cosas distintas.
    orig_ban = origen_de_baneos(f.nft)

    w('<p class="pie"><b>Cuánto llegó.</b> Una <b>participación</b> es un '
      'contacto con cualquiera de los dos señuelos, y el total es la suma de '
      'los dos: <b>%s</b> en total.</p>' % miles(total_part))
    w(figura_franja(
        "Cowrie y Dionaea",
        "los dos señuelos, cada parte en su propia unidad",
        [("sesiones en Cowrie (SSH y Telnet)", len(sesiones), "#1f5f9e"),
         ("conexiones a Dionaea (SMB, MSSQL, RPC)", n_dio, "#d9843a")]))

    w('<p class="pie"><b>Qué hicieron.</b> Esta es la cifra que separa la actividad real del ruido de fondo. Las dos proporciones van '
      'aparte porque <b>no están en la misma unidad</b>: una cuenta sesiones '
      'y la otra intentos de credencial.</p>')
    w(figura_franja(
        "Solo Cowrie",
        "la barra entera son sus %s sesiones: <b>Dionaea no emula ningún "
        "shell</b> y ahí no hay nada que teclear" % miles(len(sesiones)),
        [("sesiones que llegaron a teclear algo", len(conordenes), "#c0392b"),
         ("se fueron sin teclear nada",
          max(0, len(sesiones) - len(conordenes)), "#d5dae1")]))
    w(figura_franja(
        "Solo Cowrie",
        "es el único del que se cuentan logins; de Dionaea solo se cuentan "
        "<b>conexiones</b>",
        [("intentos de login que acertaron", n_ok, "#2f8f5b"),
         ("intentos fallidos", n_mal, "#d5dae1")]))
    porsesion = (n_cmd / float(len(conordenes))) if conordenes else 0.0
    w(lista([
        ("<b>%s</b> en total, una media de <b>%s por sesión</b> entre las "
         "que teclean" % (cuantos(n_cmd, "orden tecleada", "órdenes tecleadas"),
                          ("%.0f" % porsesion).replace(".", ",")))
        if n_cmd else "Nadie tecleó ninguna orden",
        "Un <b>login correcto</b> es alguien que acertó una de las "
        "credenciales que pusimos nosotros a propósito",
    ]))

    w('<p class="pie"><b>Quién.</b> Cuántas IPs distintas hay detrás de esas participaciones. Una <b>IP distinta</b> es una dirección, participe '
      'una vez o mil.</p>')
    w(lista([
        "<b>%s</b>%s" % (
            cuantos(len(ips_todas), "IP distinta", "IPs distintas"),
            (", desde <b>%s</b>" % cuantos(len(paises_todos), "país", "países"))
            if geo.activo else ""),
        "Una media de <b>%s por IP</b>"
        % nu(int(round(total_part / float(len(ips_todas))))
             if ips_todas else 0, "participaciones"),
        # Los dos senuelos estan en direcciones publicas distintas, asi que
        # esto no es una curiosidad: es quien barrio el rango entero.
        ("<b>%s</b> de ellas %s <b>los dos señuelos</b>, que están en "
         "direcciones públicas distintas"
         % (miles(len(vistas_ip & ips_dio)),
            "tocó" if len(vistas_ip & ips_dio) == 1 else "tocaron"))
        if (vistas_ip & ips_dio) else "",
    ]))

    w('<p class="pie"><b>Qué hicimos nosotros.</b> La única cifra del resumen '
      'que no habla de los atacantes, sino de nuestra reacción: <b>%s</b>, '
      'según la memoria del bot.</p>'
      % cuantos(len(baneadas), "IP baneada", "IPs baneadas"))
    # LOS BANEOS TAMBIEN SON UN TODO CON SUS PARTES, asi que van en franja
    # como las demas cifras del resumen y no en una vineta suelta. Un "74
    # baneadas" no dice lo unico que se quiere saber de una reaccion: cuanta
    # la puso una maquina sola y cuanta la puso una persona.
    #
    # LA BARRA SUMA EXACTAMENTE LAS 74 de la linea de arriba. Por eso lleva
    # los cuatro trozos y no los tres del origen: las que el bot recuerda y
    # ya no estan en el cortafuegos son parte de la cuenta, y sin ellas la
    # figura diria 73 debajo de un texto que dice 74. Los trozos vacios no
    # se dibujan ---un trozo de cero con su linea de leyenda es ruido---.
    partes_ban = [
        ("puestas automáticamente por el vigilante",
         sum(1 for ip in baneadas if orig_ban.get(ip) == "auto"), "#1f5f9e"),
        ("puestas a mano desde Telegram",
         sum(1 for ip in baneadas if orig_ban.get(ip) == "manual"), "#d9843a"),
        ("con la etiqueta antigua, sin saber quién",
         sum(1 for ip in baneadas if orig_ban.get(ip) == "desconocido"),
         "#8a93a0"),
        ("que el bot recuerda y ya no están en el cortafuegos",
         sum(1 for ip in baneadas if ip not in orig_ban), "#d5dae1"),
    ]
    partes_ban = [t for t in partes_ban if t[1]]
    if orig_ban and partes_ban:
        w(figura_franja(
            "Cortafuegos",
            "de dónde salió cada baneo lo dice el <b>comentario de la regla "
            "en nftables</b>, no la memoria del bot: ahí <code>banned</code> "
            "es una lista sin más",
            partes_ban))
    else:
        w(lista(["<b>%s</b>, según la memoria del bot"
                 % cuantos(len(baneadas), "IP baneada", "IPs baneadas")]))
    if len(sesiones):
        pct = 100.0 * len(conordenes) / len(sesiones)
        w("<p>Lo que de verdad dicen esos números:</p>")
        w(lista([
            "El <b>%s%%</b> de las sesiones llega a teclear algo "
            "(%s de %s)" % (("%.1f" % pct).replace(".", ","),
                            miles(len(conordenes)), miles(len(sesiones))),
            "El resto prueba credenciales y se va. <b>Esa es la cifra que "
            "conviene citar</b>: el total de sesiones mide el ruido de fondo "
            "de internet, no la actividad real contra el señuelo",
            "Intentos de login que acertaron la credencial: <b>%s</b>"
            % miles(n_ok),
        ]))
    if geo.activo and paises_todos:
        w('<p class="nota">De %s, %s%s</p>'
          % ("ese único país" if len(paises_todos) == 1 else
             "esos <b>%s</b>" % cuantos(len(paises_todos), "país", "países"),
             ("<b>%s</b> %s con una sola IP: los primeros se llevan el volumen, pero la lista larga también atacó."
              % (miles(solo_una),
                 "aparece" if solo_una == 1 else "aparecen"))
             if solo_una else "ninguno aparece con una sola IP.",
             (" Y %s no se %s podido localizar."
              % (cuantos(sin_pais, "IP", "IPs"),
                 "ha" if sin_pais == 1 else "han")) if sin_pais else ""))
        # LA LISTA ENTERA, y ORDENABLE SIN UNA LINEA DE JAVASCRIPT.
        #
        # Se puede: cada pais lleva su posicion en cada orden metida en una
        # variable CSS, unos radios dicen cual mandan, y `order` de CSS
        # recoloca. El informe sigue sin ejecutar NADA, que es la condicion
        # de que se pueda abrir dentro de un ano sin sorpresas.
        #
        # Es una rejilla y no tres tablas porque `order` funciona sobre
        # hijos de grid o de flex, y con `grid-auto-flow: column` mas un
        # numero fijo de filas se llenan las columnas de arriba abajo, que
        # es como se lee una lista.
        cola = sorted(paises_todos.items(), key=lambda kv: geo.nombre(kv[0]))
        pos_ips = {c: i for i, (c, _n) in enumerate(
            sorted(paises_todos.items(), key=lambda kv: (-kv[1], kv[0])))}
        # Sin desempaquetar: sorted() sobre un Counter da CLAVES, no pares.
        # Desempaquetar "AL" en (c, n) no falla ---son dos caracteres--- y
        # construia el mapa con claves de una sola letra. El fallo aparecia
        # mucho despues, como un KeyError con el pais numero 148.
        pos_cmd = {c: i for i, c in enumerate(
            sorted(paises_todos, key=lambda x: (-cmd_pais.get(x, 0), x)))}
        pos_abc = {c: i for i, c in enumerate(
            sorted(paises_todos, key=lambda c: geo.nombre(c)))}

        w("<h3>Todos los países que han atacado</h3>")
        w(lista(["Los <b>%s países</b> en total que han participado, "
                 "incluidos los que no caben en ningún esquema"
                 % miles(len(cola)),
                 "De cada uno: sus <b>IPs distintas</b> y sus "
                 "<b>órdenes tecleadas</b>",
                 "<b>%s</b> %s con una sola IP" % (miles(solo_una), "aparece" if solo_una == 1 else "aparecen")]))
        w("<p>Elige cómo ordenarlo:</p>")
        w('<div class="orden">')
        # El alfabetico va primero y marcado: es el unico orden en el que
        # se BUSCA un pais concreto, que es lo que se hace con una lista de
        # 148. Los otros dos responden preguntas, y para eso estan los
        # esquemas de arriba.
        for ident, etiq, marcado in (("abc", "Alfabético", " checked"),
                                     ("cmd", "Quién ha atacado más", ""),
                                     ("ips", "Quién tiene más IPs", "")):
            w('<input type="radio" name="ordenpais" id="op-%s" '
              'autocomplete="off"%s><label for="op-%s">%s</label>'
              % (ident, marcado, ident, etiq))
        filas_col = (len(cola) + 2) // 3
        # El numero de filas va como VARIABLE y no como grid-template-rows
        # a pelo: un estilo en linea solo se puede pisar con !important, y
        # asi la consulta de medios de abajo puede cambiar el reparto sin
        # recurrir a eso.
        w('<div class="paises" style="--filas:%d">' % filas_col)
        for c, n in cola:
            w('<div class="pa" style="--i:%d;--c:%d;--a:%d">'
              '<span class="nom">%s %s</span>'
              '<b class="c-ips">%s</b><b class="c-cmd">%s</b></div>'
              # +1: enumerate() da 0 y la insignia diria "#0". Como `order`
              # da igual desplazarlas todas, que lo que cuenta es el orden
              # relativo.
              % (pos_ips[c] + 1, pos_cmd[c] + 1, pos_abc[c] + 1, bandera(c),
                 esc(geo.nombre(c)), miles(n),
                 miles(cmd_pais.get(c, 0))))
        w("</div></div>")
        w('<p class="pie">Destaca siempre <b>aquello por lo que se ordena</b>: '
          'el nombre en el orden alfabético, y la cifra correspondiente en los '
          'otros dos. Las demás cifras se quedan en gris a la derecha: se pueden comparar, pero no compiten con la que manda. La reordenación la hace el navegador '
          'con CSS, sin JavaScript: al copiar y pegar en un documento sale siempre en orden alfabético, que es como está escrito el fichero.</p>')

    if mem_txt:
        w('<p class="nota">La memoria del bot guarda %s, y <b>caduca a los 30 '
          'días</b> con tope de 5.000 IPs. Los recuentos de arriba salen de '
          '<code>cowrie.json</code>, que es el que no olvida.</p>' % mem_txt)

    # --- los tres esquemas -----------------------------------------------
    #
    # Van en el resumen y no en su propia seccion a proposito: son para
    # mirarlos antes de leer nada, y separarlos de las cifras los convierte
    # en decoracion al final del documento.
    # LA EXPLICACION VA DEBAJO DEL TITULO, no al pie de la figura. Se lee
    # antes de mirar el dibujo, que es cuando hace falta: al pie llega tarde
    # ---uno ya ha interpretado el grafico a su manera--- y deja un hueco
    # blanco entre el titulo y la figura que parece un fallo de maquetacion.
    if dia_total:
        # PARTICIPACIONES, Y NO "SESIONES" NI "ATAQUES".
        #
        # Lo que se cuenta son cosas muy distintas entre si: uno falla el
        # login y se va, otro entra y no hace nada, otro entra y suelta un
        # binario. Llamarlo "ataques" seria decir que todos consiguieron
        # algo; llamarlo "sesiones" no vale para Dionaea, que no las tiene.
        # "Participacion" los engloba sin afirmar de mas, y la palabra se
        # define en el informe para que no haya que adivinarla.
        MES = MESES_ES

        def datos_dia(d, unidad):
            d = rellena_dias(d)
            if not d:
                return ""
            cum = max(d.items(), key=lambda kv: kv[1])
            med = sum(d.values()) / float(len(d))
            veces = ("%.1f" % (cum[1] / med)).replace(".", ",") if med else "?"
            return lista([
                "<b>Total del periodo:</b> %s en %s"
                % (nu(sum(d.values()), unidad),
                   cuantos(len(d), "día", "días")),
                "<b>Media:</b> %s al día" % nu(int(round(med)), unidad),
                "<b>Día más movido:</b> %d de %s, con %s"
                % (cum[0].day, MES[cum[0].month - 1], nu(cum[1], unidad)),
                "<b>Ese día fue %s veces la media</b>" % veces,
            ])

        w("<h3>Cuándo han atacado más</h3>")
        w("<p>Qué se puede ver aquí:</p>")
        w(lista(["<b>Participaciones totales</b>, los dos señuelos juntos",
                 "<b>Participaciones solo vía Cowrie</b> (SSH y Telnet)",
                 "<b>Participaciones solo vía Dionaea</b> (SMB, MSSQL y RPC)"]))
        w('<p class="pie">Decimos <b>participaciones</b> y no &quot;ataques&quot; porque lo que se registra es muy distinto entre sí: unos fallan '
          'el login y se van, otros entran y no hacen nada, y otros entran y '
          'sueltan un binario. Llamarlo &quot;ataques&quot; daría a entender que todos '
          'consiguieron algo. Una participación es <b>un contacto con el '
          'señuelo</b>: una sesión en Cowrie o una conexión en Dionaea.</p>')
        w("<p>Cómo se lee el gráfico:</p>")
        w(lista(["<b>Eje horizontal (X):</b> los días, uno por barra. "
                 "Arriba el día del mes y la inicial del día de la semana "
                 "(L, M, X, J, V, S, D), abajo el mes",
                 "<b>Eje vertical (Y):</b> las participaciones de ese día",
                 "<b>Las barras más oscuras</b> son los días de más "
                 "actividad",
                 "<b>Pasando el ratón</b> por una barra salen su fecha y su "
                 "cifra exacta"]))
        w("<p>Elige qué visualizar:</p>")
        w(conmutador("cuando", [
            ("total", "Todas", datos_dia(dia_total, "participaciones"),
             svg_cronograma(dia_total, "Participaciones por día",
                            "participaciones", pie=TODO_EL_TIEMPO)),
            ("cowrie", "Solo Cowrie", datos_dia(por_dia, "sesiones"),
             svg_cronograma(por_dia, "Sesiones de Cowrie por día",
                            "sesiones en Cowrie", pie=TODO_EL_TIEMPO)),
            ("dionaea", "Solo Dionaea", datos_dia(dia_dio, "conexiones"),
             svg_cronograma(dia_dio, "Conexiones de Dionaea por día",
                            "conexiones a Dionaea", pie=TODO_EL_TIEMPO)),
        ]))

    # A QUE HORA. Con veintiun dias hay muestra de sobra, y la forma de la
    # curva contesta una pregunta que ninguna otra figura del informe
    # contesta: si esto lo llevan personas o lo llevan maquinas. Una curva
    # plana es automatizacion; un monton de ocho horas seria alguien con
    # horario. Va en UTC, como todo el informe.
    hora_cow = collections.Counter()
    for s_ in sesiones.values():
        if s_.inicio:
            hora_cow[s_.inicio.hour] += 1
    hora_total = collections.Counter()
    hora_total.update(hora_cow)
    hora_total.update(hora_dio)
    if hora_total:
        w("<h3>A qué hora</h3>")
        pico, n_pico = hora_total.most_common(1)[0]
        # La mas tranquila se busca en las VEINTICUATRO: un Counter no
        # guarda las horas a cero, y entonces salia como "la mas
        # tranquila" una hora con 12 mientras la figura ensenaba otras a 0.
        valle = min(range(24), key=lambda h: hora_total.get(h, 0))
        n_valle = hora_total.get(valle, 0)
        media = sum(hora_total.values()) / 24.0
        w(lista([
            "<b>La hora más movida:</b> %s UTC, con %s"
            % (la_hora(pico), nu(n_pico, "participaciones")),
            "<b>La más tranquila:</b> %s UTC, con %s"
            % (la_hora(valle), nu(n_valle, "participaciones")),
            ("<b>La hora más movida tiene %s veces la actividad de la más "
             "tranquila</b>, sobre una media de %s por hora"
             % (("%.1f" % (n_pico / float(n_valle))).replace(".", ","),
                miles(int(round(media)))))
            if n_valle else
            ("<b>Hay horas sin ninguna participación</b>; la media es de "
             "%s por hora" % miles(int(round(media)))),
        ]))
        w('<p class="pie">Aquí importa menos la hora punta que <b>lo parecidas que son las veinticuatro</b>. Un reparto plano indica automatización, porque las máquinas no duermen. Si la actividad se concentrara en unas ocho horas, apuntaría a personas con horario, y eso sería lo llamativo.</p>')
        w('<figure>%s</figure>'
          % svg_barras([("%02d:00" % h, hora_total.get(h, 0))
                        for h in range(24)],
                       "Participaciones por hora UTC", "participaciones",
                       banderas=False,
                       columnas=("Hora UTC",
                                 "Participaciones en esa hora, sumando "
                                 "todo el periodo")))

    # CUANTO DURAN. Cowrie apunta la duracion de cada sesion y no se estaba
    # leyendo. Separa sola al que toca el puerto y se va ---un escaner que
    # cierra antes de un segundo--- del que se queda dentro, y las sesiones
    # largas son las que hay que mirar a mano.
    duraciones = sorted(s_.duracion for s_ in sesiones.values()
                        if s_.duracion is not None)
    if duraciones:
        n = len(duraciones)
        cortas = sum(1 for d in duraciones if d < 1000)
        medias = sum(1 for d in duraciones if 1000 <= d < 10000)
        largas = sum(1 for d in duraciones if 10000 <= d < 60000)
        muylargas = n - cortas - medias - largas
        w("<h3>Cuánto duran</h3>")
        w(lista([
            "<b>La mitad</b> de las sesiones dura menos de <b>%s</b>"
            % dura(duraciones[n // 2]),
            "<b>Nueve de cada diez</b>, menos de <b>%s</b>"
            % dura(duraciones[int(n * 0.9)]),
            "<b>La más larga</b> duró <b>%s</b>" % dura(duraciones[-1]),
        ]))
        w(figura_franja(
            "Solo Cowrie",
            "Dionaea cuenta conexiones sueltas, no sesiones con principio y "
            "final; la duración es de las %s sesiones de Cowrie que la "
            "traen" % miles(n),
            [t for t in (
                ("menos de 1 segundo: tocar y salir", cortas, "#1f5f9e"),
                ("de 1 a 10 segundos", medias, "#3a86c8"),
                ("de 10 segundos a 1 minuto", largas, "#d9843a"),
                ("más de 1 minuto", muylargas, "#c0392b")) if t[1]]))

    if geo.activo and ip_pais_total:
        def datos_ips(mapa, quien, todas=0):
            if not mapa:
                return ""
            fuera = max(0, len(mapa) - args.paises)
            # SIN PAIS NO SE PUEDE DIBUJAR, Y LA FIGURA LO DICE. La figura
            # reparte por paises, asi que una IP que la tabla de geo no
            # localiza no cabe en ella. Son una o dos de miles, pero el
            # total baja y el lector ve dos cifras que no cuadran: sin esta
            # linea, una diferencia legitima parece una errata.
            sinpais = max(0, todas - sum(mapa.values()))
            cc0, n0 = mapa.most_common(1)[0]
            return lista([
                "<b>Total:</b> %s (%s), en %s"
                % (cuantos(sum(mapa.values()), "IP distinta", "IPs distintas"),
                   quien, cuantos(len(mapa), "país", "países")),
                ("<b>No entran en la figura:</b> %s que la tabla de "
                 "países no localiza" % cuantos(sinpais, "IP", "IPs")) if sinpais else "",
                "<b>El que más:</b> %s %s, con %s"
                % (bandera(cc0), esc(geo.nombre(cc0)),
                   cuantos(n0, "IP", "IPs")),
                (fuera_del_dibujo(fuera, "con menos IPs (%s en la lista de "
                                         "arriba)" % ("está" if fuera == 1
                                                      else "están todos")))
                if fuera else "",
            ])

        w("<h3>De dónde: desde cuántos sitios distintos</h3>")
        w("<p>Qué se puede ver aquí:</p>")
        w(lista(["<b>IPs distintas totales</b>, los dos señuelos juntos",
                 "<b>Solo las de Cowrie</b> (SSH y Telnet)",
                 "<b>Solo las de Dionaea</b> (SMB, MSSQL y RPC)"]))
        w('<p class="pie">Una <b>IP distinta</b> es una dirección desde la '
          'que llegó al menos una participación. Si la misma dirección '
          'participa mil veces, cuenta <b>una</b>. Por eso esta figura mide '
          'algo distinto de la siguiente: aquí se ve <b>desde cuántos sitios '
          'se ataca</b>, y en la siguiente <b>cuánto insiste cada uno</b>.'
          '</p>')
        w("<p>Cómo se lee el gráfico:</p>")
        w(lista(["<b>Cada triángulo es un país</b>, y van repartidos en círculo",
                 "<b>El área del triángulo</b> es proporcional a sus IPs. Se escala el área y no el lado, porque escalando el lado el doble se vería cuatro veces más grande",
                 "<b>En el centro</b>, cuántas IPs suman los países "
                 "dibujados y cuántos países quedan fuera",
                 "<b>Pasando el ratón</b> por un triángulo sale su cifra "
                 "exacta"]))
        w("<p>Elige qué visualizar:</p>")
        w(conmutador("dedonde", [
            # El total de paises va POR VARIANTE: los que ha visto Cowrie no
            # son los que ha visto Dionaea, y poner el de la suma en las tres
            # diria que a Dionaea le faltan paises que nunca le llegaron.
            ("total", "Todas", datos_ips(ip_pais_total, "los dos señuelos",
                                         len(ips_todas)),
             svg_circulo_triangulos(ip_pais_total.most_common(args.paises),
                                    "IPs por país", "IPs",
                                    len(ip_pais_total))),
            ("cowrie", "Solo Cowrie", datos_ips(ip_pais, "Cowrie",
                                                len(vistas_ip)),
             svg_circulo_triangulos(ip_pais.most_common(args.paises),
                                    "IPs por país", "IPs", len(ip_pais))),
            ("dionaea", "Solo Dionaea", datos_ips(ip_pais_dio, "Dionaea",
                                                  len(ips_dio)),
             svg_circulo_triangulos(ip_pais_dio.most_common(args.paises),
                                    "IPs por país", "IPs",
                                    len(ip_pais_dio))),
        ]))

        # EL DESGLOSE SE LEE SOLO. Antes era "287.135 · 281.143 ord. +
        # 5.992 conex. · 226 IPs": cuatro cifras seguidas separadas por
        # puntos, sin decir cual sale de donde ni de que senuelo es cada
        # una. Ahora cada numero lleva al lado que es y de donde sale, y va
        # en su propia linea debajo de la barra, que es lo que da sitio
        # para escribirlo.
        def ips_cow(c):
            ban = ban_pais.get(c, 0)
            return ("órdenes en Cowrie · desde %s (solo Cowrie)%s"
                    % (cuantos(ip_pais[c], "IP distinta", "IPs distintas"),
                       (", %s de ellas %s" % (miles(ban), "baneada" if ban == 1
                                              else "baneadas")) if ban else ""))

        extra_cow = {c: ips_cow(c) for c in cmd_pais}
        extra_dio = {c: "conexiones a Dionaea · desde %s (solo Dionaea)"
                        % cuantos(ip_pais_dio[c], "IP distinta", "IPs distintas")
                     for c in conn_pais_dio}
        act_total = collections.Counter()
        for c, v in cmd_pais.items():
            act_total[c] += v
        for c, v in conn_pais_dio.items():
            act_total[c] += v
        extra_tot = {c: "= %s + %s · desde %s (los dos señuelos)"
                        % (nu(cmd_pais.get(c, 0), "órdenes en Cowrie"),
                           nu(conn_pais_dio.get(c, 0), "conexiones a Dionaea"),
                           cuantos(ip_pais_total.get(c, 0), "IP distinta",
                                   "IPs distintas"))
                     for c in act_total}

        def mas_ips(cc0, ipm):
            """La linea que compara las IPs del pais que mas trabaja, con
            las IPs DE ESA PESTANA: en "Solo Cowrie" contaba tambien las de
            Dionaea, y no casaba con lo que dicen las barras de al lado."""
            n_suyas = ipm.get(cc0, 0)
            suyas = cuantos(n_suyas, "IP", "IPs")
            if not ipm:
                return "<b>Y lo hace desde %s</b>" % suyas
            cc_ips, n_ips = ipm.most_common(1)[0]
            if n_suyas >= n_ips:
                empate = sum(1 for v in ipm.values() if v == n_ips) > 1
                return ("<b>Y lo hace desde %s</b>, %s"
                        % (suyas, "tantas como el que más" if empate
                           else "más que ningún otro país"))
            return ("<b>Y lo hace desde %s</b>, cuando el país que más IPs "
                    "usa es %s %s, con %s"
                    % (suyas, bandera(cc_ips), esc(geo.nombre(cc_ips)),
                       miles(n_ips)))

        def datos_act(mapa, unidad, nota="", todo=0, ipm=None):
            con_algo = len([c for c, v in mapa.items() if v])
            if not con_algo:
                return ""
            cc0, n0 = mapa.most_common(1)[0]
            tot = sum(mapa.values())
            # Lo mismo que en la figura de las IPs: lo que no tiene pais no
            # se puede repartir por paises. Aqui son conexiones, no IPs.
            sinpais = max(0, todo - tot)
            return lista([
                "<b>Total:</b> %s desde %s"
                % (nu(tot, unidad), cuantos(con_algo, "país", "países")),
                ("<b>No entran en la figura:</b> %s de IPs que la tabla "
                 "de países no localiza" % nu(sinpais, unidad))
                if sinpais else "",
                "<b>El que más:</b> %s %s, con %s, el <b>%.0f%%</b> del total"
                % (bandera(cc0), esc(geo.nombre(cc0)), nu(n0, unidad),
                   100.0 * n0 / tot if tot else 0),
                # LA COMPARACION NECESITA EL NOMBRE DEL OTRO PAIS. "El
                # que mas IPs tiene, tiene 1.056" deja a medias justo lo
                # que se quiere ver: que el que mas trabaja no es el que
                # mas direcciones usa. Y si resulta ser el mismo, la frase
                # no puede comparar nada, asi que se dice de otra manera.
                mas_ips(cc0, ip_pais_total if ipm is None else ipm),
                fuera_del_dibujo(con_algo - 15, "con menos actividad") if con_algo > 15 else "",
                nota,
            ])

        w("<h3>Quién trabaja de verdad</h3>")
        w("<p>Qué se puede ver aquí:</p>")
        w(lista(["<b>Actividad total</b>, sumando los dos señuelos",
                 "<b>Solo las órdenes tecleadas</b> en Cowrie",
                 "<b>Solo las conexiones</b> a Dionaea"]))
        w('<p class="pie">Una <b>orden</b> es cada línea que el atacante '
          'teclea ya dentro del señuelo. Una <b>conexión</b> es cada vez que '
          'se toca un puerto de Dionaea. Son cosas distintas y no se pueden '
          'comparar entre sí, pero <b>sí se pueden sumar</b> para saber qué país está más activo, y por eso el total lleva el desglose '
          'en cada barra.</p>')
        w("<p>Cómo se lee el gráfico:</p>")
        w(lista(["<b>Cada barra es un país</b>, de más a menos actividad",
                 "<b>Al final de la barra</b>, su cifra; <b>debajo</b>, de "
                 "qué se compone y desde cuántas IPs distintas sale",
                 "<b>Arriba, las dos llaves</b> dicen qué es cada columna, "
                 "y cambian con la pestaña que elijas",
                 "<b>Mucha actividad con pocas IPs</b> es alguien "
                 "trabajando; <b>muchas IPs con poca actividad</b> es un "
                 "barrido automático"]))
        w("<p>Elige qué visualizar:</p>")
        w(conmutador("trabajo", [
            ("total", "Todo", datos_act(act_total, "acciones",
                                        todo=n_cmd + n_dio),
             svg_barras(act_total.most_common(15), "Actividad por país",
                        "acciones", extra_tot,
                        columnas=("Países", "Actividad total, "
                                            "Cowrie + Dionaea"))),
            ("cowrie", "Solo Cowrie (órdenes)",
             datos_act(cmd_pais, "órdenes", todo=n_cmd, ipm=ip_pais),
             svg_barras(cmd_pais.most_common(15), "Órdenes por país",
                        "órdenes", extra_cow,
                        columnas=("Países", "Actividad total, "
                                            "solo Cowrie"))),
            ("dionaea", "Solo Dionaea (conexiones)",
             datos_act(conn_pais_dio, "conexiones",
                       "Aquí no hay órdenes: <b>Dionaea no emula ningún "
                       "shell</b>, así que lo único contable es cuántas "
                       "veces se tocó un puerto", todo=n_dio,
                       ipm=ip_pais_dio),
             svg_barras(conn_pais_dio.most_common(15), "Conexiones por país",
                        "conexiones", extra_dio,
                        columnas=("Países", "Actividad total, "
                                            "solo Dionaea"))),
        ]))


    # --- Protocolos ------------------------------------------------------
    if proto_total:
        w("<h3>Protocolos: por dónde entran</h3>")
        w("<p>Qué se puede ver aquí:</p>")
        w(lista(["<b>El reparto</b> entre todos los protocolos, en un pastel"]
                + ["<b>Solo %s</b>: los países que más lo atacan" % p_
                   for p_, _n in proto_total.most_common()]))
        w('<p class="pie">Los <b>puertos son los públicos</b>, no los '
          'internos del contenedor: Cowrie escucha en 2222 y 2223, pero '
          'quien ataca marcó el 22 y el 23. Un <b>contacto</b> es una '
          'participación contra ese puerto.</p>')
        w("<p>Cómo se leen:</p>")
        w(lista(["<b>En el pastel</b>, el porcentaje va dentro del trozo y "
                 "la cifra exacta en la leyenda",
                 "<b>En las barras</b>, cada una es un país, de más a menos",
                 "<b>Muchos contactos y pocos países</b> es una botnet "
                 "concreta; <b>muchos de los dos</b> es ruido de fondo de "
                 "internet"]))
        variantes = [
            ("todos", "Todos",
             lista(["<b>Total:</b> %s en %s"
                    % (nu(sum(proto_total.values()), "contactos"),
                       cuantos(len(proto_total), "protocolo", "protocolos")),
                    "<b>El más atacado:</b> %s, con %s (el %.0f%%)"
                    % (proto_total.most_common(1)[0][0],
                       nu(proto_total.most_common(1)[0][1], "contactos"),
                       100.0 * proto_total.most_common(1)[0][1]
                       / sum(proto_total.values())),
                    "<b>El que atacan desde más países:</b> %s, desde %s"
                    % (max(proto_pais, key=lambda k: len(proto_pais[k])),
                       cuantos(max(len(v) for v in proto_pais.values()),
                               "país", "países"))
                    if proto_pais else ""]),
             svg_quesitos(proto_total.most_common(),
                          "Contactos por protocolo", "contactos",
                          {p_: cuantos(len(proto_pais.get(p_, {})), "país", "países")
                           for p_ in proto_total})),
        ]
        for etq, n in proto_total.most_common():
            paises = proto_pais.get(etq, collections.Counter())
            if not paises:
                continue
            cc0, n0 = paises.most_common(1)[0]
            fuera = max(0, len(paises) - 15)
            variantes.append(
                (re.sub(r"[^a-z0-9]", "", etq.lower()), "Solo %s" % etq,
                 lista(["<b>Total:</b> %s contra %s"
                        % (nu(n, "contactos"), esc(etq)),
                        "<b>Desde:</b> %s" % cuantos(len(paises), "país", "países"),
                        "<b>El que más:</b> %s %s, con %s (el %.0f%%)"
                        % (bandera(cc0), esc(geo.nombre(cc0)),
                           nu(n0, "contactos"), 100.0 * n0 / n if n else 0),
                        fuera_del_dibujo(fuera, "con menos contactos") if fuera else ""]),
                 svg_barras(paises.most_common(15), "Países en %s" % etq,
                            "contactos")))
        w("<p>Elige qué visualizar:</p>")
        w(conmutador("protos", variantes))
        if len(variantes) == 1:
            # Sin tablas de paises no hay pestanas por protocolo. Decirlo:
            # una seccion que se queda con un solo boton parece rota.
            w('<div class="aviso">Solo sale la vista de conjunto: para saber <b>qué países atacan cada protocolo</b> hacen falta las tablas de geolocalización, y no están. Se generan con <code>generar-tabla-paises.py</code> y se le pasan al análisis '
              'con <code>--geoip</code>.</div>')

    # ============================================== 3. actores
    w("<h2>3. Actores: los guiones que se repiten</h2>")
    w("<p>Un <b>guion</b> es el conjunto de órdenes ya normalizadas (URLs, "
      "IPs, hexadecimales y números largos sustituidos) que se repite entre "
      "sesiones. Que dos IPs compartan guion dice que <b>usan la misma "
      "herramienta</b>; no dice que sean el mismo actor.</p>")

    guiones = collections.defaultdict(
        lambda: {"ips": collections.Counter(), "ses": 0, "primera": None,
                 "ultima": None, "ordenes": [], "cmds": 0})
    for s in conordenes:
        fp = huella(normaliza(c) for c in s.ordenes)
        g = guiones[fp]
        g["ses"] += 1
        g["cmds"] += len(s.ordenes)
        if s.ip:
            g["ips"][s.ip] += 1
        if s.inicio and (g["primera"] is None or s.inicio < g["primera"]):
            g["primera"] = s.inicio
        if s.fin and (g["ultima"] is None or s.fin > g["ultima"]):
            g["ultima"] = s.fin
        if not g["ordenes"]:
            g["ordenes"] = [normaliza(c) for c in s.ordenes]
    orden = sorted(guiones.items(),
                   key=lambda kv: (-len(kv[1]["ips"]), -kv[1]["ses"]))

    filas = []
    for fp, g in orden[:args.top]:
        paises = collections.Counter(geo.cc(i) for i in g["ips"])
        paises.pop("", None)
        top_p = " ".join("%s&nbsp;%s" % (bandera(c), n)
                         for c, n in paises.most_common(4)) or "-"
        filas.append([mono(fp), miles(len(g["ips"])), miles(g["ses"]),
                      miles(g["cmds"]),
                      miles(g["cmds"] // max(1, len(g["ips"]))),
                      fecha(g["primera"]), fecha(g["ultima"]), top_p])
    w(tabla(["Guion", "IPs", "Sesiones", "Órdenes", "Órdenes por IP",
             "Primera vez", "Última vez", "Países (IPs)"], filas,
            numericas=(1, 2, 3, 4)))

    # DOS PREGUNTAS DISTINTAS, DOS TABLAS. La de arriba va por numero de
    # IPs: contesta "que se repite mas por ahi fuera". Pero el que manda
    # doce mil ordenes desde cinco IPs no sale ni en pantalla, y es justo el
    # que interesa ---es la misma distincion que explica la figura de 2.4:
    # mucha actividad con pocas IPs es alguien trabajando; muchas IPs con
    # poca actividad es un barrido---. Ordenar solo por una de las dos
    # esconde la otra, asi que van las dos.
    aprietan = sorted(((fp, g) for fp, g in guiones.items()
                       if g["ses"] >= 3 and len(g["ips"]) >= 1),
                      key=lambda kv: -(kv[1]["cmds"] / float(len(kv[1]["ips"]))
                                       or 0))[:10]
    if aprietan:
        w("<h3>Los que más aprietan</h3>")
        w("<p>Los mismos guiones, ordenados por la <b>media de órdenes por IP</b> en vez de por el número de IPs que los corren. Un guion con pocas IPs y muchísimas órdenes por cada una suele ser alguien que vuelve una y otra vez, no un barrido.</p>")
        w(tabla(["Guion", "IPs", "Sesiones", "Órdenes", "Órdenes por IP",
                 "Países (IPs)"],
                [[mono(fp), miles(len(g["ips"])), miles(g["ses"]),
                  miles(g["cmds"]),
                  miles(g["cmds"] // max(1, len(g["ips"]))),
                  " ".join("%s&nbsp;%s" % (bandera(c), n) for c, n
                           in collections.Counter(
                               x for x in (geo.cc(i) for i in g["ips"]) if x
                           ).most_common(4)) or "-"]
                 for fp, g in aprietan],
                numericas=(1, 2, 3, 4)))

    # COMO SE LLAMAN A SI MISMAS. Las tiras \xNN de las ordenes son texto
    # escrito byte a byte; en la orden son ruido y en claro son el nombre
    # que la herramienta se da o la senal con la que se reconoce.
    tiras = collections.Counter()
    tiras_ips = collections.defaultdict(set)
    for s_ in sesiones.values():
        for c in s_.ordenes:
            if es_binaria(c):
                continue
            for tira in _RX_TIRA.findall(c):
                if en_claro(tira):
                    tiras[tira] += 1
                    if s_.ip:
                        tiras_ips[tira].add(s_.ip)
    if tiras:
        w("<h3>Cómo se llaman a sí mismas</h3>")
        w("<p>Muchas órdenes llevan una tira del tipo "
          "<code>echo -e &quot;\\x4f\\x56\\x46&quot;</code>: "
          "la herramienta escribe una palabra <b>byte a byte</b> y espera "
          "leerla de vuelta, que es como comprueba que al otro lado hay un "
          "shell de verdad y no un dispositivo que ignora lo que recibe. En "
          "hexadecimal es ruido; en claro es el nombre que la variante se "
          "pone a sí misma o la señal con la que se reconoce.</p>")
        w('<p class="pie">La orden se enseña <b>tal como llegó</b> en el '
          'desplegable de más abajo: esto es una lectura de esa prueba, no '
          'una sustitución. Solo se descifran las tiras que salen <b>enteras</b> en texto imprimible: con media palabra legible no se puede leer nada sin adivinar.</p>')
        w(tabla(["En claro", "Tal como va en la orden", "Veces", "IPs"],
                [[mono(en_claro(t_)), mono(recorta(t_, 44)), miles(n),
                  miles(len(tiras_ips.get(t_, ())))]
                 for t_, n in tiras.most_common(args.top)],
                numericas=(2, 3)))

    # CON QUE SE CONECTAN. Esto NO lo elige el atacante: la version del
    # cliente y el HASSH los pone su herramienta al negociar la conexion,
    # antes de teclear una sola orden. Por eso vale mas que el guion para
    # decir "estos dos usan lo mismo": el guion se cambia escribiendo otro
    # guion; el HASSH solo cambia recompilando o cambiando de libreria.
    #
    # HASSH: el resumen de los algoritmos que el cliente ofrece al negociar
    # ---cifrados, intercambio de claves, MAC, compresion--- y en que orden.
    # Cowrie lo calcula solo y lo escribe en cowrie.client.kex.
    clientes = collections.Counter()
    cli_ips = collections.defaultdict(set)
    hasshes = collections.Counter()
    hassh_ips = collections.defaultdict(set)
    hassh_cli = collections.defaultdict(set)
    for s_ in sesiones.values():
        if s_.cliente:
            clientes[s_.cliente] += 1
            if s_.ip:
                cli_ips[s_.cliente].add(s_.ip)
        if s_.hassh:
            hasshes[s_.hassh] += 1
            if s_.ip:
                hassh_ips[s_.hassh].add(s_.ip)
            if s_.cliente:
                hassh_cli[s_.hassh].add(s_.cliente)
    if clientes:
        w("<h3>Con qué se conectan</h3>")
        n_cli = sum(clientes.values())
        cli0, v0 = clientes.most_common(1)[0]
        w("<p>La <b>versión del cliente</b> es la cadena que manda el "
          "programa del atacante nada más abrir la conexión, antes de "
          "probar ninguna credencial. <b>No la elige quien ataca: la pone "
          "su herramienta</b>, y por eso dice más de qué está corriendo que "
          "las órdenes que teclee después.</p>")
        w(lista([
            "<b>El que más:</b> %s, en %s de %s sesiones con cliente "
            "anotado (el %s%%)"
            % (mono(cli0), miles(v0), miles(n_cli),
               ("%.1f" % (100.0 * v0 / n_cli)).replace(".", ",")),
            "<b>Clientes distintos:</b> %s" % miles(len(clientes)),
        ]))
        w(tabla(["Cliente", "Sesiones", "IPs distintas"],
                [[mono(recorta(c, 46)), miles(n), miles(len(cli_ips[c]))]
                 for c, n in clientes.most_common(args.top)],
                numericas=(1, 2)))
    if hasshes:
        w('<p class="pie">El <b>HASSH</b> es el resumen de los algoritmos '
          'que el cliente ofrece al negociar la conexión (cifrados, intercambio de claves, MAC y compresión) y del orden en '
          'que los ofrece. Lo calcula Cowrie. Dos IPs con el mismo HASSH '
          'corren <b>el mismo programa</b> aunque tecleen cosas distintas: '
          'esa huella no se cambia sin recompilar o sin cambiar de '
          'librería, y el atacante no la ve.</p>')
        w(tabla(["HASSH", "Sesiones", "IPs distintas", "Se presenta como"],
                [[mono(h), miles(n), miles(len(hassh_ips[h])),
                  mono(recorta(" · ".join(sorted(hassh_cli[h])), 44))
                  if hassh_cli.get(h) else "-"]
                 for h, n in hasshes.most_common(args.top)],
                numericas=(1, 2)))

    # QUE IPs CORREN CADA GUION, Y CUANTAS VECES. Sin esto, el guion es un
    # hash suelto: se ve que algo se repite pero no quien lo repite, y es
    # justo lo que hace falta para decidir a quien se denuncia.
    w("<h3>Quién corre cada guion</h3>")
    for fp, g in orden[:args.detalle]:
        paises = collections.Counter(geo.cc(i) for i in g["ips"])
        paises.pop("", None)
        w("<p><b>%s</b>: %s, %s, %s &middot; visto del %s al %s</p>"
          % (mono(fp), cuantos(len(g["ips"]), "IP", "IPs"),
             cuantos(g["ses"], "sesión", "sesiones"),
             cuantos(g["cmds"], "orden", "órdenes"),
             fecha(g["primera"]), fecha(g["ultima"])))
        filas = []
        for ip, veces in g["ips"].most_common(args.ips_por_guion):
            marcas_ip = []
            if ip in baneadas:
                marcas_ip.append("baneada")
            if ip in denunciadas:
                marcas_ip.append("denunciada")
            cc_ = geo.cc(ip)
            # El nombre completo y no el codigo de dos letras: aqui sobra
            # ancho, y "MT" no le dice nada a nadie mientras que "Malta" si.
            # En las tablas estrechas se sigue usando el codigo.
            pais_ = ("%s %s" % (bandera(cc_), esc(geo.nombre(cc_)))
                     if cc_ else "-")
            filas.append([mono(ip), pais_, veces,
                          ", ".join(marcas_ip) or "-"])
        w(tabla(["IP", "País", "Sesiones con este guion", "Estado"], filas,
                numericas=(2,)))
        if len(g["ips"]) > args.ips_por_guion:
            w('<p class="hue">(y %s más)</p>'
              % cuantos(len(g["ips"]) - args.ips_por_guion, "IP", "IPs"))
        # DESPLEGABLE. Hay guiones de 146 ordenes y algunas ocupan lineas
        # enteras; desplegados todos, la seccion mide varias pantallas y
        # tapa lo que hay debajo. Se abre el que se quiera mirar.
        w("<details><summary>Ver %s de <code>%s</code></summary>"
          "<pre>%s</pre></details>"
          % ("la orden" if len(g["ordenes"]) == 1
             else ("las %s primeras de %s órdenes"
                   % (miles(args.ordenes), miles(len(g["ordenes"]))))
             if len(g["ordenes"]) > args.ordenes
             else "las %s órdenes" % miles(len(g["ordenes"])), esc(fp),
             esc("\n".join(g["ordenes"][:args.ordenes]
                          + (["... y %s más"
                              % cuantos(len(g["ordenes"]) - args.ordenes,
                                        "orden", "órdenes")]
                             if len(g["ordenes"]) > args.ordenes else [])))))

    # ============================================== 4. IPs
    w("<h2>4. IPs</h2>")
    porip = collections.defaultdict(
        lambda: {"ses": 0, "cmd": 0, "mal": 0, "ok": 0, "mues": set(),
                 "primera": None, "ultima": None, "proto": set(),
                 "ordenes": collections.Counter()})
    for s in sesiones.values():
        if not s.ip:
            continue
        d = porip[s.ip]
        d["ses"] += 1
        d["cmd"] += len(s.ordenes)
        d["mal"] += len(s.creds_mal)
        d["ok"] += len(s.creds_ok)
        d["mues"].update(m[0] for m in s.muestras)
        for c in s.ordenes:
            d["ordenes"][normaliza(c)] += 1
        if s.protocolo:
            d["proto"].add(s.protocolo)
        if s.inicio and (d["primera"] is None or s.inicio < d["primera"]):
            d["primera"] = s.inicio
        if s.fin and (d["ultima"] is None or s.fin > d["ultima"]):
            d["ultima"] = s.fin

    filas = []
    for ip, d in sorted(porip.items(),
                        key=lambda kv: (-kv[1]["cmd"], -kv[1]["ses"]))[:args.top]:
        marcas_ip = []
        if ip in baneadas:
            marcas_ip.append("baneada")
        if ip in denunciadas:
            marcas_ip.append("denunciada")
        mas = d["ordenes"].most_common(1)
        filas.append([mono(ip), geo.etiqueta(ip) or "-",
                      "/".join(sorted(d["proto"])) or "-",
                      miles(d["ses"]), miles(d["cmd"]),
                      # CERO Y "NO HAY" NO SON LO MISMO, y es el criterio
                      # que este informe usa con las fuentes que faltan. En
                      # este registro los eventos de login SOLO existen para
                      # SSH ---98.086 fallidos, ni uno de telnet---, asi que
                      # una fila de telnet con un 0 estaba diciendo "probo y
                      # no acerto" cuando lo cierto es que ahi no se mide.
                      miles(d["mal"]) if "ssh" in d["proto"] else "-",
                      len(d["mues"]),
                      (mono(recorta(mas[0][0], 38)) + ' <span class="hue">'
                       "&times;%d</span>" % mas[0][1]) if mas else "-",
                      ", ".join(marcas_ip) or "-"])
    w(tabla(["IP", "País", "Vía", "Sesiones", "Órdenes",
             "Logins fallidos (SSH)", "Muestras", "Su orden más repetida",
             "Estado"], filas, numericas=(3, 4, 5, 6)))
    w('<p class="pie">La columna de <b>logins fallidos</b> lleva un guion (-), y no un cero, en las IPs que solo entraron por <b>Telnet</b>: este informe solo cuenta los logins de SSH, así que de una sesión de Telnet no se sabe si probó credenciales. Un cero diría '
      'que probó y no acertó, que es otra cosa.</p>')

    if geo.activo:
        # ESTA TABLA ES DE COWRIE Y LA FIGURA DE 2.1 ES DE LOS DOS, y el
        # mismo pais sale con dos cifras de IPs distintas: 826 aqui y 1.056
        # alli para Estados Unidos. Las dos son correctas ---sesiones y
        # ordenes son conceptos de Cowrie, asi que sus IPs tambien--- pero
        # sin decirlo, lo que parece es que una de las dos esta mal.
        w("<h3>Por país</h3>")
        w('<p class="pie">Las cifras de esta tabla son <b>solo de '
          'Cowrie</b>: sesiones y órdenes son cosas de Cowrie, así que sus '
          'IPs también. La lista de <b>&quot;Todos los países que han '
          'atacado&quot;</b> cuenta las de los dos '
          'señuelos, y por eso un mismo país puede salir allí con más IPs que aquí. No es un descuadre: las dos cifras cuentan cosas distintas.</p>')
        w(tabla(["País", "IPs (Cowrie)", "Sesiones", "Órdenes tecleadas",
                 "Baneadas"],
                [["%s %s" % (bandera(c), c), miles(n), miles(ses_pais[c]),
                  miles(cmd_pais[c]), miles(ban_pais.get(c, 0))]
                 for c, n in ip_pais.most_common(args.top)],
                numericas=(1, 2, 3, 4)))
    else:
        w('<div class="aviso">Sin tablas de geolocalización a mano, así que '
          'las columnas de <b>país</b> y las banderas van vacías. Las tablas son datos generados y no están en el repositorio; se hacen con <code>generar-tabla-paises.py</code> (apartado 3.4.4) y se le pasa '
          'la carpeta con <code>--geoip</code>.</div>')

    # POR RED /24, Y LA CONCLUSION ES LA CONTRARIA DE LA QUE SE ESPERA.
    # Agrupar por /24 se hace para ensenar que detras de cientos de
    # direcciones hay unas pocas redes. Aqui NO: 7.574 IPs se reparten en
    # 6.061 redes distintas y la mas poblada aporta 94, el 1,2% del total.
    # El dato va igualmente, porque una dispersion asi tambien dice algo
    # ---no es un punado de granjas, es medio internet a la vez--- y porque
    # la unica forma de saber que la agrupacion no ayuda es hacerla.
    redes = collections.defaultdict(
        lambda: {"ips": set(), "ses": 0, "cmd": 0, "dio": 0, "ban": 0,
                 "paises": set()})
    otras = 0
    for ip in ips_todas:
        if ip.count(".") != 3:
            otras += 1          # IPv6: un /24 no significa nada ahi
            continue
        d = redes[ip.rsplit(".", 1)[0] + ".0/24"]
        d["ips"].add(ip)
        d["ses"] += porip.get(ip, {}).get("ses", 0)
        d["cmd"] += porip.get(ip, {}).get("cmd", 0)
        d["dio"] += conn_ip_dio.get(ip, 0)
        if ip in baneadas:
            d["ban"] += 1
        c = geo.cc(ip)
        if c:
            d["paises"].add(c)
    if redes:
        n_redes = len(redes)
        n_ips = sum(len(d["ips"]) for d in redes.values())
        mayor = max(redes.values(), key=lambda d: len(d["ips"]))
        w("<h3>Por red /24</h3>")
        w("<p>Agrupar las IPs por su red sirve para ver si detrás de muchas direcciones hay <b>unas pocas redes</b> o si el reparto está disperso. Las cifras de abajo lo dicen.</p>")
        w(lista([
            "<b>%s IPs</b> repartidas en <b>%s redes /24 distintas</b>"
            % (miles(n_ips), miles(n_redes)),
            "Una media de <b>%s IPs por red</b>"
            % ("%.2f" % (n_ips / float(n_redes))).replace(".", ","),
            "<b>La red más poblada</b> aporta %s: el %s%% del total"
            % (cuantos(len(mayor["ips"]), "IP", "IPs"),
               ("%.1f" % (100.0 * len(mayor["ips"]) / max(1, n_ips)))
               .replace(".", ",")),
            ("<b>%s</b> %s fuera: %s IPv6, y ahí un /24 no significa nada"
             % (cuantos(otras, "IP", "IPs"),
                "queda" if otras == 1 else "quedan",
                "es" if otras == 1 else "son")) if otras else "",
        ]))
        w('<p class="pie">La tabla va de las redes con más direcciones a las que menos tienen. Mira la columna de órdenes para saber si además teclean algo o solo tocan y se van, la misma distinción que se hace en &quot;Cuánto duran&quot;.</p>')
        w(tabla(["Red", "IPs", "País", "Sesiones", "Órdenes",
                 "Conexiones (Dionaea)", "Baneadas"],
                [[mono(r), miles(len(d["ips"])),
                  " ".join(bandera(c) + "&nbsp;" + c
                           for c in sorted(d["paises"])[:3]) or "-",
                  miles(d["ses"]), miles(d["cmd"]), miles(d["dio"]),
                  miles(d["ban"])]
                 for r, d in sorted(redes.items(),
                                    key=lambda kv: (-len(kv[1]["ips"]),
                                                    -kv[1]["cmd"]))[:args.top]],
                numericas=(1, 3, 4, 5, 6)))

    # LAS QUE TOCARON LOS DOS SENUELOS. Esta pregunta solo se puede hacer
    # porque los dos senuelos estan en DIRECCIONES PUBLICAS DISTINTAS
    # (apartado 3.2.7 del README): uno en la del senuelo Linux y otro en la
    # del Windows. Una IP que aparece en los dos no ha ido a por un
    # servicio: ha barrido el rango del proveedor. Con los dos senuelos en
    # la misma IP este apartado no existiria, porque cualquiera que tocara
    # un puerto estaria tocando "los dos".
    ambos = sorted(vistas_ip & ips_dio,
                   key=lambda i: -(porip.get(i, {}).get("cmd", 0)
                                   + conn_ip_dio.get(i, 0)))
    if ambos:
        w("<h3>Las que tocaron los dos señuelos</h3>")
        w("<p><b>%s</b> de las %s %s en los <b>dos</b> señuelos: "
          "el %s%% del total. Los dos escuchan en <b>direcciones públicas distintas</b> (una para el Linux y otra para el Windows, a propósito, porque un mismo host con SSH de Debian y SMB de Windows sería sospechoso). Quien aparece en los dos no buscaba un servicio concreto: ha recorrido el rango entero del proveedor.</p>"
          % (cuantos(len(ambos), "IP", "IPs"), miles(len(ips_todas)),
             "aparece" if len(ambos) == 1 else "aparecen",
             ("%.1f" % (100.0 * len(ambos) / max(1, len(ips_todas))))
             .replace(".", ",")))
        w(tabla(["IP", "País", "Sesiones (Cowrie)", "Órdenes",
                 "Conexiones (Dionaea)", "Estado"],
                [[mono(i), geo.etiqueta(i) or "-",
                  miles(porip.get(i, {}).get("ses", 0)),
                  miles(porip.get(i, {}).get("cmd", 0)),
                  miles(conn_ip_dio.get(i, 0)),
                  ", ".join(x for x in (
                      "baneada" if i in baneadas else "",
                      "denunciada" if i in denunciadas else "") if x)
                  or "-"]
                 for i in ambos[:args.top]],
                numericas=(2, 3, 4)))

    if baneadas:
        w("<h3>IPs baneadas</h3>")
        w('<p>En total <b>%s</b>, según la memoria del bot. Se cruzan aquí '
          'con lo que hicieron: una IP baneada que no había tecleado nada entró por el baneo automático de repetición, no por lo que hizo en la sesión.</p>' % miles(len(baneadas)))
        conact = [ip for ip in baneadas if ip in porip]
        # SIN TARJETAS AQUI. Cuatro rectangulos iguales para cuatro cifras
        # que no son del mismo tipo es el mismo error que tenia el resumen:
        # dos son un reparto del total y las otras dos no. En lista se leen
        # igual de rapido y no fingen una simetria que no hay.
        w(lista([
            "<b>%s baneadas</b> en total, según la memoria del bot"
            % miles(len(baneadas)),
            "<b>%s</b> con actividad en este registro; <b>%s</b> %s de antes"
            % (miles(len(conact)), miles(len(baneadas) - len(conact)),
               "es" if len(baneadas) - len(conact) == 1 else "son"),
            # El total de denunciadas, que NO es un subconjunto de las
            # baneadas: se denuncia mucho mas de lo que se banea. Sin
            # decirlo, "74 baneadas" y "7.564 denunciadas" en la misma
            # lista se leen como si lo segundo saliera de lo primero.
            "<b>%s</b> a AbuseIPDB en total, que es otra cosa: no %s por qué "
            "estar entre las baneadas"
            % (cuantos(len(denunciadas), "IP denunciada", "IPs denunciadas"),
               "tiene" if len(denunciadas) == 1 else "tienen"),
        ]))

        # DE QUIEN PARTIO CADA BANEO. La memoria del bot guarda "banned" como
        # una lista plana: quien lo sabe es el COMENTARIO de nftables, que el
        # guion de baneo escribe distinto segun sea automatico o a mano. Si el
        # respaldo no trae el volcado no se inventa un reparto: se dice que
        # falta y como arreglarlo, que es lo mismo que se hace con cualquier
        # otra fuente que no aparece.
        orig = orig_ban
        if orig:
            man = sorted(ip for ip in baneadas if orig.get(ip) == "manual")
            aut = sorted(ip for ip in baneadas if orig.get(ip) == "auto")
            desc = sorted(ip for ip in baneadas
                          if orig.get(ip) == "desconocido")
            sinreg = sorted(ip for ip in baneadas if ip not in orig)
            w("<h3>Quién ordenó cada baneo</h3>")
            w(lista([
                ("<b>%s</b>, %s por el vigilante al repetirse la IP"
                 % (cuantos(len(aut), "automático", "automáticos"),
                    "puesto" if len(aut) == 1 else "puestos"))
                if aut else "",
                ("<b>%s a mano</b>, desde el botón de Telegram"
                 % miles(len(man))) if man else "",
                ("<b>%s con la etiqueta antigua</b>, de origen desconocido: "
                 "%s de antes de que se separaran las etiquetas automática "
                 "y manual" % (miles(len(desc)),
                               "es" if len(desc) == 1 else "son"))
                if desc else "",
                ("<b>%s que el bot recuerda pero ya no %s en el "
                 "cortafuegos</b>: %s"
                 % (miles(len(sinreg)),
                    "está" if len(sinreg) == 1 else "están",
                    "o caducó, o se quitó a mano" if len(sinreg) == 1
                    else "o caducaron, o se quitaron a mano"))
                if sinreg else "",
            ]))
            if man:
                w('<p class="pie">Las puestas a mano, una a una: %s</p>'
                  % ", ".join(mono(ip) for ip in man[:args.top]))
        else:
            w('<div class="aviso"><b>No se puede decir cuáles se banearon a '
              'mano y cuáles automáticamente.</b> Ese dato no está en la memoria del bot (ahí <code>banned</code> es solo una lista), sino en el <b>comentario de cada elemento en nftables</b>, que el '
              'script de baneo escribe distinto en cada caso. Este respaldo no '
              'trae el volcado del cortafuegos. Se arregla añadiéndolo: '
              '<code>nft list ruleset &gt; nftables-ruleset.txt</code> junto '
              'al resto, y este apartado se rellena solo.</div>')
        filas = []
        for ip in sorted(conact,
                         key=lambda x: -porip[x]["cmd"])[:args.top]:
            d = porip[ip]
            filas.append([mono(ip), geo.etiqueta(ip) or "-",
                          miles(d["ses"]), miles(d["cmd"]),
                          fecha(d["primera"]),
                          "sí" if ip in denunciadas else "no"])
        w(tabla(["IP", "País", "Sesiones", "Órdenes", "Primera vez",
                 "Denunciada"], filas, numericas=(2, 3)))

    # ============================================== 5. credenciales
    w("<h2>5. Credenciales probadas</h2>")
    cred_mal = collections.Counter()
    cred_ok = collections.Counter()
    usuarios = collections.Counter()
    for s in sesiones.values():
        for c in s.creds_mal:
            cred_mal[c] += 1
            usuarios[c.split(":", 1)[0]] += 1
        for c in s.creds_ok:
            cred_ok[c] += 1
            usuarios[c.split(":", 1)[0]] += 1
    w("<h3>Las que funcionaron</h3>")
    w("<p>O sea, las que pusimos nosotros en <code>userdb</code>.</p>")
    w(tabla(["Usuario:clave", "Veces"],
            [[mono(recorta(c, 44)), miles(n)] for c, n in
             cred_ok.most_common(args.top)], numericas=(1,)))
    # QUE HICIERON LOS QUE ACERTARON. Es la pregunta que justifica haber
    # sembrado credenciales a proposito, y no se contestaba en ningun sitio.
    # La respuesta del respaldo real es que la mayoria NO hace nada: entra,
    # comprueba que la clave vale, y se va. Eso separa al que recolecta
    # credenciales para venderlas del que viene a usar la maquina.
    con_ok = [s_ for s_ in sesiones.values() if s_.creds_ok]
    if con_ok:
        teclearon = [s_ for s_ in con_ok if s_.ordenes]
        w("<h3>Qué hicieron los que acertaron</h3>")
        w(lista([
            "<b>%s</b> %s con una credencial buena"
            % (cuantos(len(con_ok), "sesión", "sesiones"),
               "entró" if len(con_ok) == 1 else "entraron"),
            que_hicieron(len(con_ok), len(teclearon)),
        ]))
        w('<p class="pie">Entrar y no hacer nada <b>no indica un fallo del señuelo</b>. Es lo habitual en quien solo quiere saber si la clave vale, para apuntarla o venderla. Quien viene a usar la máquina se '
          'queda y teclea.</p>')
        por_cred = collections.defaultdict(
            lambda: {"ses": 0, "tec": 0, "cmd": 0, "ips": set()})
        for s_ in con_ok:
            for c in set(s_.creds_ok):
                d = por_cred[c]
                d["ses"] += 1
                d["cmd"] += len(s_.ordenes)
                if s_.ordenes:
                    d["tec"] += 1
                if s_.ip:
                    d["ips"].add(s_.ip)
        w(tabla(["Credencial", "Sesiones", "Teclearon algo", "Órdenes",
                 "IPs distintas"],
                [[mono(c), miles(d["ses"]), miles(d["tec"]), miles(d["cmd"]),
                  miles(len(d["ips"]))]
                 for c, d in sorted(por_cred.items(),
                                    key=lambda kv: -kv[1]["ses"])],
                numericas=(1, 2, 3, 4)))

    w("<h3>Las más intentadas sin éxito</h3>")
    w("<p>Es el diccionario de contraseñas que traen los atacantes.</p>")
    w(tabla(["Usuario:clave", "Veces"],
            [[mono(recorta(c, 44)), miles(n)] for c, n in
             cred_mal.most_common(args.top)], numericas=(1,)))
    w("<h3>Usuarios más buscados</h3>")
    w(tabla(["Usuario", "Veces"],
            [[mono(recorta(u, 32)), miles(n)] for u, n in
             usuarios.most_common(args.top)], numericas=(1,)))

    # ============================================== 6. malware
    w("<h2>6. Malware capturado</h2>")
    w("<p>Los dos señuelos juntos. El <b>SHA-256 se calcula del fichero</b>, "
      "no se da por bueno el nombre: Cowrie y Dionaea nombran sus capturas "
      "por su hash, pero eso es una convención y un respaldo hecho en "
      "caliente puede dejar un fichero a medias con el nombre entero.</p>")

    # Cuantas veces se metio CADA binario, que es la pregunta util: una
    # muestra que llega mil veces desde trescientas IPs es una campana; una
    # que llega una vez es un experimento.
    veces_cow = collections.Counter()
    ips_cow = collections.defaultdict(set)
    primera_cow = {}
    urls_cow = collections.defaultdict(set)
    via_cow = collections.defaultdict(set)
    for s in sesiones.values():
        for sha, url, via in s.muestras:
            veces_cow[sha] += 1
            if s.ip:
                ips_cow[sha].add(s.ip)
            if url:
                urls_cow[sha].add(url)
            via_cow[sha].add(via)
            if s.inicio and (sha not in primera_cow
                             or s.inicio < primera_cow[sha]):
                primera_cow[sha] = s.inicio

    capturas = {n: r for n, r in ficheros_cow.items()
                if clase_fichero(n) == "captura"}
    todo = []
    total_files = len(capturas) + len(ficheros_dio)
    if total_files:
        paso("calculando el hash de %s (%.0f MB)..."
             % (cuantos(total_files, "captura", "capturas"),
                sum(os.path.getsize(r) for r in
                    list(capturas.values()) + list(ficheros_dio.values()))
                / 1048576.0), fin=True)

    dio_db = {}
    if f.dionaea_db:
        try:
            con = sqlite3.connect("file:%s?mode=ro" % f.dionaea_db[0], uri=True)
            for md5, ip, veces, url in con.execute(
                    "SELECT d.download_md5_hash, COALESCE(c.remote_host,''), "
                    "COUNT(*), COALESCE(MIN(d.download_url),'') "
                    "FROM downloads d LEFT JOIN connections c "
                    "ON c.connection=d.connection "
                    "GROUP BY d.download_md5_hash, COALESCE(c.remote_host,'')"):
                e = dio_db.setdefault((md5 or "").lower(),
                                      {"ips": set(), "veces": 0, "url": ""})
                if ip:
                    e["ips"].add(ip)
                e["veces"] += veces
                if url and not e["url"]:
                    e["url"] = url
            con.close()
        except sqlite3.Error:
            pass

    hechos = 0
    descuadran = []
    ilegibles = []
    nomuestra = []
    for senuelo, mapa in (("Cowrie", capturas), ("Dionaea", ficheros_dio)):
        for nombre, ruta in sorted(mapa.items()):
            hechos += 1
            if hechos % 50 == 0:
                paso("  %s/%s   " % (miles(hechos), miles(total_files)))
            sha, md5 = hashes_de(ruta)
            if not sha:
                ilegibles.append((senuelo, nombre))
                continue
            if _RE_SHA.match(nombre) and sha != nombre:
                descuadran.append((senuelo, nombre))
            tipo = tipo_de(ruta)
            if tipo not in MUESTRA:
                nomuestra.append((senuelo, nombre, tipo,
                                  os.path.getsize(ruta)))
                continue
            if senuelo == "Cowrie":
                veces = veces_cow.get(sha, 0)
                quien = ips_cow.get(sha, set())
                url = sorted(urls_cow.get(sha, set()))[:1]
                prim = primera_cow.get(sha)
            else:
                meta = dio_db.get(md5, {})
                veces = meta.get("veces", 0)
                quien = meta.get("ips", set())
                url = [meta["url"]] if meta.get("url") else []
                prim = None
            todo.append({
                "sha": sha, "md5": md5, "tam": os.path.getsize(ruta),
                "senuelo": senuelo, "veces": veces, "ips": quien,
                "url": url[0] if url else "", "primera": prim,
                "pub": sha in publicadas or md5 in publicadas,
                "tipo": tipo,
            })
    if total_files:
        paso("  %s   " % cuantos(hechos, "captura comprobada",
                                 "capturas comprobadas"), fin=True)

    if nomuestra:
        tam_nm = sum(x[3] for x in nomuestra)
        tipos = collections.Counter(x[2] for x in nomuestra)
        w('<div class="aviso"><b>%s: no %s.</b> %s %s. Se ha mirado el '
          'contenido, no el nombre.</div>'
          % (cuantos(len(nomuestra), "fichero apartado", "ficheros apartados"),
             "es una muestra" if len(nomuestra) == 1 else "son muestras",
             "Ocupa" if len(nomuestra) == 1 else "Suman", tamano(tam_nm)))
        w(tabla(["Qué era", "Ficheros", "Qué significa"],
                [[{"vacio": "vacío"}.get(t, t), miles(n),
                  {"artefacto": "Líneas de syslog: es el "
                                "<code>/var/log/auth.log</code> que el propio "
                                "señuelo genera en cada sesión y persiste con "
                                "<code>Artifact()</code>, que escribe en este "
                                "mismo directorio. <b>Salida nuestra, no "
                                "captura</b>",
                   "texto": "Texto plano sin formato reconocible",
                   "vacio": "Cero bytes",
                   "ilegible": "No se pudo leer"}.get(t, "")]
                 for t, n in tipos.most_common()], numericas=(1,)))

    por_senuelo = collections.Counter(m["senuelo"] for m in todo)
    w(tarjetas([
        (miles(len(todo)), "binarios distintos"),
        (miles(por_senuelo.get("Cowrie", 0)), "de Cowrie"),
        (miles(por_senuelo.get("Dionaea", 0)), "de Dionaea"),
        ("%.0f MB" % (sum(m["tam"] for m in todo) / 1048576.0), "en total"),
        (miles(sum(m["veces"] for m in todo)), "entregas registradas"),
        (miles(sum(1 for m in todo if m["pub"])), "ya publicados"),
    ]))

    w("<h3>Los más entregados</h3>")
    w("<p>Ordenados por <b>cuántas veces</b> se entregó el mismo binario. Una muestra que llega cientos de veces desde decenas de IPs es una campaña; una que llega una sola vez suele ser una prueba.</p>")
    filas = []
    for m in sorted(todo, key=lambda x: (-x["veces"], -x["tam"]))[:args.top]:
        filas.append([mono(m["sha"][:20] + "…"), mono(m["md5"][:12]),
                      m["senuelo"], m["tipo"], miles(m["tam"]),
                      miles(m["veces"]),
                      miles(len(m["ips"])),
                      esc(recorta(m["url"], 34)) if m["url"] else "-",
                      "sí" if m["pub"] else "no"])
    w(tabla(["SHA-256 (calculado)", "MD5", "Señuelo", "Tipo", "Bytes",
             "Entregas", "IPs distintas", "URL", "Publicado"], filas,
            numericas=(4, 5, 6)))

    # Muchas muestras de tamano casi identico son el mismo bicho recompilado.
    tam_grupo = collections.Counter(m["tam"] // 1024 for m in todo)
    repes = [(k, v) for k, v in tam_grupo.most_common(8) if v > 1]
    if repes:
        w("<h3>Agrupados por tamaño</h3>")
        w("<p>Decenas de binarios distintos que pesan casi lo mismo suelen "
          "ser <b>el mismo programa recompilado</b> con variaciones de unos "
          "bytes. Por eso el número de muestras distintas engaña si se lee como número de familias.</p>")
        w(tabla(["Tamaño aproximado", "Binarios distintos"],
                [["%s KB" % miles(k), miles(v)] for k, v in repes],
                numericas=(1,)))
        # NO "CASI LO MISMO": EXACTAMENTE LO MISMO, AL BYTE. La tabla de
        # arriba agrupa por KB y eso ya insinua la idea, pero deja la puerta
        # a "bueno, se parecen". Si 269 ficheros con SHA-256 distinto pesan
        # los mismos 5.298.176 bytes, no se parecen: es el mismo programa
        # recompilado, y el numero de muestras distintas mide variantes, no
        # familias. Es la diferencia entre contar ficheros y analizarlos.
        exacto = collections.Counter(m["tam"] for m in todo)
        tam0, n0 = exacto.most_common(1)[0]
        if n0 > 1:
            w('<p class="pie"><b>%s de los %s binarios distintos '
              '(%s%%) pesan exactamente %s bytes</b>, no aproximadamente: el mismo '
              'número al byte, con %s hashes distintos. Contarlos como %s '
              'muestras distintas es correcto; leerlos como %s programas '
              'distintos, no.</p>'
              % (miles(n0), miles(len(todo)),
                 ("%.1f" % (100.0 * n0 / len(todo))).replace(".", ","),
                 miles(tam0), miles(n0), miles(len(todo)), miles(len(todo))))

    # QUIEN SIRVE EL MALWARE, Y ADEMAS ATACA. La URL de origen de cada
    # muestra y la lista de atacantes estaban en dos tablas distintas y
    # nadie las cruzaba. Una IP que ataca por su cuenta y ademas sirve el
    # binario a otras decenas no es una victima reutilizada: es
    # infraestructura del que manda.
    servidores = collections.defaultdict(
        lambda: {"muestras": set(), "entregas": 0, "clientes": set()})
    for m in todo:
        anfitrion = re.search(r"^[a-z]+://([^/:]+)", m["url"] or "")
        ip_srv = anfitrion.group(1) if anfitrion else ""
        if ip_srv and ip_srv in ips_todas:
            d = servidores[ip_srv]
            d["muestras"].add(m["sha"])
            d["entregas"] += m["veces"]
            d["clientes"].update(m["ips"])
    if servidores:
        w("<h3>Quién sirve el malware, y además ataca</h3>")
        w("<p>La <b>URL de origen</b> de una muestra dice de dónde se la "
          "bajó el señuelo. Estas direcciones aparecen ahí <b>y</b> en la "
          "lista de atacantes: se conectaron ellas mismas y, además, "
          "sirvieron el binario a otras. Eso apunta a la infraestructura de quien dirige el ataque, más que a una máquina infectada que alguien usa de paso.</p>")
        w(tabla(["IP que sirve", "País", "Muestras", "Entregas",
                 "IPs en cuyas sesiones se descargó", "Su propia actividad"],
                [[mono(i), geo.etiqueta(i) or "-",
                  miles(len(d["muestras"])), miles(d["entregas"]),
                  miles(len(d["clientes"])),
                  # De su propia actividad se ensena la que tenga: una
                  # IP puede servir el binario y haber tocado solo el
                  # senuelo Windows, y ahi no hay sesiones ni ordenes que
                  # contar. Poner "0 sesiones" en ese caso se lee como
                  # "entro y no hizo nada", que es otra cosa.
                  " · ".join(x for x in (
                      plural(porip.get(i, {}).get("ses", 0),
                             "sesión", "sesiones"),
                      plural(porip.get(i, {}).get("cmd", 0),
                             "orden", "órdenes"),
                      plural(conn_ip_dio.get(i, 0), "conexión a Dionaea",
                             "conexiones a Dionaea")) if x) or "-"]
                 for i, d in sorted(servidores.items(),
                                    key=lambda kv: -kv[1]["entregas"])],
                numericas=(2, 3, 4)))

    huerfanos = [sha for sha in veces_cow if sha not in
                 {m["sha"] for m in todo}]
    if huerfanos:
        w('<div class="aviso"><b>%s que el log menciona y cuyo fichero no '
          'está</b> en el respaldo. Sin el fichero no se %s ni publicar.</div>'
          % (cuantos(len(huerfanos), "muestra", "muestras"),
             "puede analizar" if len(huerfanos) == 1 else "pueden analizar"))
    sin_evento = [m for m in todo
                  if m["senuelo"] == "Cowrie" and m["veces"] == 0]
    if sin_evento:
        uno = len(sin_evento) == 1
        w('<div class="aviso"><b>%s de Cowrie en disco que el log '
          'no referencia</b> con ningún evento de descarga o subida. %s '
          'arriba porque el fichero existe y su hash está calculado, pero '
          '<b>no se sabe por qué vía %s</b>: eso hay que averiguarlo, no '
          'suponerlo.</div>'
          % (cuantos(len(sin_evento), "captura", "capturas"),
             "Está contada" if uno else "Están contadas",
             "entró" if uno else "entraron"))
    if descuadran:
        uno = len(descuadran) == 1
        w('<div class="aviso malo"><b>%s cuyo SHA-256 no coincide '
          'con su nombre.</b> El respaldo %s trae %s o a medias. No '
          '%s ni para analizar ni para publicar.</div>'
          % (cuantos(len(descuadran), "fichero", "ficheros"),
             "lo" if uno else "los", "corrupto" if uno else "corruptos",
             "sirve" if uno else "sirven"))
    if ilegibles:
        w('<div class="aviso malo"><b>%s que no se %s podido '
          'leer.</b> %s</div>'
          % (cuantos(len(ilegibles), "fichero", "ficheros"),
             "ha" if len(ilegibles) == 1 else "han",
             esc(", ".join("%s/%s" % (s, n[:24]) for s, n in ilegibles[:6]))))

    # ============================================== 7. TTPs
    w("<h2>7. TTPs</h2>")
    ttps, malas = lee_ttp(args.ttp)
    if malas:
        w('<div class="aviso malo">Problemas leyendo <code>ttp.tsv</code>: %s'
          '</div>' % esc("; ".join(malas)))
    w("<p>La conducta y los recuentos son <b>observados</b>. La columna "
      "ATT&amp;CK es <b>inferida</b>: es nuestra lectura de esa conducta, y "
      "sale de <code>ANALISIS/ttp.tsv</code>.</p>")
    cuenta = collections.defaultdict(
        lambda: {"veces": 0, "ips": set(), "ejemplos": collections.Counter()})
    for s in sesiones.values():
        for c in s.ordenes:
            # LA ENTRADA BINARIA TAMPOCO CUENTA COMO TECNICA. Se dice mas
            # abajo ---"no cuentan como tecnica ni como orden sin mapear"---
            # y tiene que ser verdad: un patron corto como "sh" casa dentro
            # de cualquier chorro de bytes, y entonces una tecnica saldria
            # inflada con ruido de negociacion de telnet.
            if es_binaria(c):
                continue
            for tid, nombre, rx, _n in ttps:
                if rx.search(c):
                    d = cuenta[(tid, nombre)]
                    d["veces"] += 1
                    if s.ip:
                        d["ips"].add(s.ip)
                    d["ejemplos"][normaliza(c)] += 1
    for tid, nombre, rx, _n in ttps:
        if rx.pattern == "^__LOGIN_FALLIDO__$" and n_mal:
            d = cuenta[(tid, nombre)]
            d["veces"] = n_mal
            d["ips"] = {s.ip for s in sesiones.values() if s.creds_mal and s.ip}
        if rx.pattern == "^__LOGIN_EXITOSO__$" and n_ok:
            d = cuenta[(tid, nombre)]
            d["veces"] = n_ok
            d["ips"] = {s.ip for s in sesiones.values() if s.creds_ok and s.ip}
    filas = []
    for (tid, nombre), d in sorted(cuenta.items(),
                                   key=lambda kv: (-len(kv[1]["ips"]),
                                                   -kv[1]["veces"])):
        ej = d["ejemplos"].most_common(1)
        filas.append([esc(nombre), miles(d["veces"]), miles(len(d["ips"])),
                      mono(recorta(ej[0][0], 46)) if ej else "-",
                      mono(tid)])
    w(tabla(["Conducta observada", "Veces", "IPs", "Ejemplo",
             "ATT&CK (inferido)"], filas, numericas=(1, 2)))

    # LA ENTRADA BINARIA VA APARTE, Y NO ES UNA ORDEN. Por el telnet entra
    # negociacion IAC y carga cruda, y Cowrie la anota en "input" igual que
    # una linea tecleada. Mezcladas en esta tabla, las primeras filas eran
    # un rombo de interrogacion repetido miles de veces: ocupaban el sitio
    # de lo que esta tabla existe para ensenar ---lo que falta por mapear---
    # y encima parecian un fallo del informe.
    sintecnica = collections.Counter()
    binarias = collections.Counter()
    for s in sesiones.values():
        for c in s.ordenes:
            if es_binaria(c):
                binarias[normaliza(c)] += 1
            elif not any(rx.search(c) for _t, _n, rx, _x in ttps):
                sintecnica[normaliza(c)] += 1
    if sintecnica:
        w("<h3>Órdenes sin técnica asignada</h3>")
        w("<p>No casan con ninguna fila de <code>ttp.tsv</code>. Merecen una "
          "mirada: o son ruido, o son una técnica que falta por añadir. Esta "
          "tabla es la lista de tareas de la tabla de técnicas.</p>")
        w(tabla(["Orden", "Veces"],
                [[mono(recorta(c, 74)), miles(n)]
                 for c, n in sintecnica.most_common(args.top)],
                numericas=(1,)))
    if binarias:
        w('<div class="aviso"><b>%s%s no %s: son bytes.</b> %s por Telnet (negociación IAC y carga cruda) y Cowrie %s anota en el mismo campo que una línea '
          'tecleada, así que aquí no cuentan como técnica ni como orden sin '
          'mapear. Los bytes de control se escriben en su forma '
          '<code>\\x00</code>; el rombo <code>&#xfffd;</code> <b>no se puede '
          'deshacer</b>: lo escribe Cowrie al decodificar los bytes del '
          'atacante antes de anotarlos, así que cuando el informe lee el '
          'registro el byte original ya no existe. Esa información se pierde en la captura, no en este informe.</div>'
          % (cuantos(sum(binarias.values()), "entrada", "entradas"),
             (" (%s)" % cuantos(len(binarias), "distinta", "distintas"))
             if len(binarias) != sum(binarias.values()) else "",
             "es una orden" if sum(binarias.values()) == 1 else "son órdenes",
             "Llega" if sum(binarias.values()) == 1 else "Llegan",
             "la" if sum(binarias.values()) == 1 else "las"))

    # LO QUE NO SE HA VISTO. En analisis forense la ausencia informa tanto
    # como la presencia, y ademas se puede MEDIR: ttp.tsv es la lista de
    # conductas que este informe busca, asi que las que se quedan a cero
    # son exactamente "lo que se buscó y no apareció". Sin este apartado,
    # quien busque eso tiene que deducir la ausencia de que no sale, y eso
    # no se distingue de que no se haya mirado.
    sin_ver = [(tid, nombre) for tid, nombre, _rx, _n in ttps
               if cuenta.get((tid, nombre), {}).get("veces", 0) == 0]
    if sin_ver:
        w("<h3>Lo que no se ha visto</h3>")
        w("<p>Estas conductas <b>se buscaron y no aparecieron</b> ni una "
          "vez. No es lo mismo que no haberlas mirado: <code>ttp.tsv</code> "
          "es la lista de lo que este informe sabe reconocer, y estas son "
          "las filas que se quedaron a cero.</p>")
        w(tabla(["Conducta que no aparece", "ATT&CK"],
                [[esc(nombre), mono(tid)] for tid, nombre in sin_ver]))
        w('<p class="pie">Que no aparezca no prueba que no ocurriera, solo que <b>no dejó rastro reconocible</b> en lo que este señuelo '
          'puede ver. Un Cowrie no observa movimiento lateral ni '
          'persistencia real porque no hay a dónde moverse ni dónde '
          'quedarse.</p>')

    # ============================================== 8. dionaea
    w("<h2>8. Dionaea: qué se toca por el lado Windows</h2>")
    if f.dionaea_db:
        try:
            con = sqlite3.connect("file:%s?mode=ro" % f.dionaea_db[0], uri=True)
            filas = [[esc(p or "-"), puerto, miles(n), miles(m)]
                     for p, puerto, n, m in con.execute(
                         "SELECT connection_protocol, local_port, COUNT(*), "
                         "COUNT(DISTINCT remote_host) FROM connections "
                         "WHERE connection_type='accept' "
                         "GROUP BY connection_protocol, local_port "
                         "ORDER BY COUNT(*) DESC")]
            w(tabla(["Servicio", "Puerto", "Conexiones", "IPs"], filas,
                    numericas=(1, 2, 3)))
            filas = [[mono(ip), geo.etiqueta(ip) or "-", miles(n)]
                     for ip, n in con.execute(
                         "SELECT remote_host, COUNT(*) FROM connections "
                         "WHERE connection_type='accept' GROUP BY remote_host "
                         "ORDER BY COUNT(*) DESC LIMIT %d" % args.top)]
            w("<h3>Quién más insiste</h3>")
            w(tabla(["IP", "País", "Conexiones"], filas, numericas=(2,)))
            con.close()
        except sqlite3.Error as exc:
            w('<p class="nota">No se pudo leer la base de Dionaea: %s</p>'
              % esc(exc))
    else:
        w('<p class="nota">No hay base de Dionaea en el respaldo.</p>')

    # ============================================== 9. inferido
    # ============================================== 9. conclusiones
    #
    # SOLO SI ALGUIEN LAS HA ESCRITO. Antes salia siempre, con seis
    # preguntas sin contestar, y un informe que se ensena con una lista de
    # deberes al final parece a medio hacer. La herramienta sigue sin
    # interpretar nada: esto lo trae un fichero escrito a mano
    # (--conclusiones), y si no lo hay, el apartado no existe.
    if args.conclusiones:
        with open(args.conclusiones, encoding="utf-8") as fh:
            propio = fh.read().strip()
        w("<h2>9. INFERIDO: conclusiones</h2>")
        w('<div class="aviso"><b>Esta sección no la genera la herramienta.</b> '
          'La ha escrito a mano quien firma el informe. Lo de arriba son '
          'hechos contados; lo de aquí es interpretación.</div>')
        if args.conclusiones.lower().endswith((".html", ".htm")):
            w(propio)
        else:
            for parrafo in re.split(r"\n\s*\n", propio):
                w("<p>%s</p>" % esc(parrafo.strip()))

    o.extend(anexo)

    w('<footer>Generado por <code>ANALISIS/analisis.py</code> sobre '
      '%s líneas de registro. Ninguna muestra se ha ejecutado.</footer>'
      % miles(lineas))

    # EL CUERPO SE ARMA ANTES QUE LA HOJA, Y NO EN LA MISMA EXPRESION.
    # con_indice() es quien llena CSS_IX, y Python evalua los argumentos de
    # izquierda a derecha: con las dos cosas dentro del mismo %, el join de
    # la hoja corria PRIMERO y se llevaba una lista todavia vacia. El
    # informe salia entero y con su indice, y lo unico que faltaba era el
    # resaltado del apartado al que se salta ---un fallo que no se ve
    # leyendo el marcado, porque el marcado estaba bien---.
    cuerpo = "\n".join(o)
    if args.anonimizar:
        vps = [ip for ip in (args.ip_vps or []) + ips_del_senuelo(f)
               if not es_nuestra(ip)]
        cuerpo, hecho = anonimiza(cuerpo, geo, vps)
        aviso = ('<div class="aviso ok"><b>Informe anonimizado.</b> Cada IP '
                 'de internet se ha cambiado por una etiqueta con su país '
                 '(<code>&lt;IP-PAÍS-NNN&gt;</code>): la misma IP lleva la '
                 'misma etiqueta en todo el informe, y el número no dice '
                 'nada más. Las del señuelo van como <code>[IP VPS]</code>. '
                 'Sin rutas locales%s.</div>'
                 % (" y sin el cuerpo de %s"
                    % cuantos(hecho["claves"], "clave privada",
                              "claves privadas") if hecho["claves"] else ""))
        cuerpo = cuerpo.replace("<!--anonimizado-->", aviso, 1)
        paso("anonimizado: %s, %s, %s del señuelo y %s"
             % (cuantos(hecho["ips"], "IP", "IPs"),
                cuantos(hecho["redes"], "red", "redes"),
                cuantos(hecho["vps"], "IP", "IPs"),
                cuantos(hecho["claves"], "clave privada", "claves privadas")),
             fin=True)
    cuerpo = con_indice(cuerpo.replace("<!--anonimizado-->\n", ""))
    hoja = "\n".join(CSS_CONM + [css_globos()] + CSS_IX)
    # EL DIA VA EN EL TITULO DE LA PESTANA. El informe se regenera sobre
    # respaldos cada vez mas largos, y sin la fecha todas las pestanas se
    # llaman igual y no se distingue una tirada de otra. Es el ultimo dia
    # con datos, que es "hasta cuando" llega este informe.
    dia_doc = max(marcas).date().isoformat() if marcas else "?"
    return ("<!doctype html><html lang=\"es\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,"
            "initial-scale=1\"><title>Análisis del señuelo (%s)</title>"
            "<style>%s\n%s</style></head><body><main>%s</main></body></html>"
            % (dia_doc, ESTILO, hoja, cuerpo))


class _Ayuda(argparse.HelpFormatter):
    """La ayuda en castellano: "uso:" y no "usage:"."""

    def add_usage(self, usage, actions, groups, prefix=None):
        return super().add_usage(usage, actions, groups, prefix or "uso: ")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description="Informe del respaldo del señuelo, sin tocar la VPS.",
        formatter_class=_Ayuda, add_help=False)
    p._optionals.title = "opciones"
    p.add_argument("-h", "--help", action="help",
                   help="enseña esta ayuda y sale")
    p.add_argument("--respaldo", required=True,
                   help="directorio del respaldo ya descomprimido")
    p.add_argument("--salida", default=None,
                   help="fichero de salida (por defecto "
                        "analisis-senuelo-FECHA.html en el directorio actual)")
    p.add_argument("--ttp", default=os.path.join(AQUI, "ttp.tsv"),
                   help="tabla de técnicas (por defecto ANALISIS/ttp.tsv)")
    p.add_argument("--geoip", default=None,
                   help="directorio con las tablas de países ya generadas")
    p.add_argument("--tz", default="Europe/Kyiv",
                   help="huso en que escribe Cowrie (por defecto Europe/Kyiv)")
    p.add_argument("--top", type=int, default=25,
                   help="cuántas filas por tabla (por defecto 25)")
    p.add_argument("--detalle", type=int, default=10,
                   help="de cuántos guiones se enseña el desglose (por defecto 10)")
    p.add_argument("--ips-por-guion", type=int, default=15,
                   help="cuántas IPs se listan por guion (por defecto 15)")
    p.add_argument("--paises", type=int, default=24,
                   help="cuántos países entran en el círculo (por defecto 24)")
    p.add_argument("--ordenes", type=int, default=40,
                   help="cuántas órdenes se enseñan por guion (por defecto 40)")
    anon = p.add_mutually_exclusive_group()
    anon.add_argument("--anonimizar", dest="anonimizar", action="store_true",
                      default=None,
                      help="cambia las IPs por <IP-PAÍS-NNN>, quita las "
                           "rutas locales y las claves privadas (si no se "
                           "dice ni esto ni lo contrario, se pregunta)")
    anon.add_argument("--sin-anonimizar", dest="anonimizar",
                      action="store_false",
                      help="deja las IPs y las rutas tal cual")
    p.add_argument("--ip-vps", action="extend", nargs="+", metavar="IP",
                   help="IPs del señuelo, que salen como [IP VPS]; vale "
                        "$(hostname -I) tal cual, las privadas se ignoran "
                        "(las de Dionaea se sacan solas)")
    p.add_argument("--conclusiones", default=None, metavar="FICHERO",
                   help="texto escrito a mano para el apartado 9 (.html tal "
                        "cual; cualquier otro, como texto con párrafos "
                        "separados por una línea en blanco)")
    a = p.parse_args(argv)

    if not os.path.isdir(a.respaldo):
        print("no existe el directorio %s" % a.respaldo, file=sys.stderr)
        return 2
    if a.conclusiones and not os.path.isfile(a.conclusiones):
        print("no existe el fichero %s" % a.conclusiones, file=sys.stderr)
        return 2

    # SI NO SE DICE, SE PREGUNTA, Y LA RESPUESTA POR DEFECTO ES SI. Un
    # informe con las IPs en claro es el que no se puede ensenar, y el
    # olvido tiene que caer del lado seguro. Sin nadie delante (una tarea
    # programada, la suite) no hay a quien preguntar: se anonimiza.
    if a.anonimizar is None:
        if sys.stdin.isatty():
            while True:
                # EOFError: en Windows el dispositivo nulo dice ser una
                # terminal, y input() se encuentra el fichero vacio. Es lo
                # mismo que no tener a nadie delante.
                try:
                    r = input("¿Anonimizar el informe (IPs, rutas y claves "
                              "privadas)? [S/n] ").strip().lower()
                except EOFError:
                    print("", file=sys.stderr)
                    a.anonimizar = True
                    break
                if r in ("", "s", "si", "sí", "y", "yes"):
                    a.anonimizar = True
                    break
                if r in ("n", "no"):
                    a.anonimizar = False
                    break
                print("responde s o n (Intro es sí)")
        else:
            a.anonimizar = True
            print("sin --anonimizar ni --sin-anonimizar y sin nadie a quien "
                  "preguntar: se anonimiza", file=sys.stderr)

    texto = informe(a)
    salida = a.salida or ("analisis-senuelo-%s%s.html"
                          % (datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                             "-anonimizado" if a.anonimizar else ""))
    with open(salida, "w", encoding="utf-8") as fh:
        fh.write(texto)
    print("escrito %s (%.0f KB)"
          % (salida, len(texto.encode("utf-8")) / 1024.0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
