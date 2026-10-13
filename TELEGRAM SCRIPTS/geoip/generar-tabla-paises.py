#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
generar-tabla-paises.py
Construye la tabla de "que rango de IP es de que pais" que usan las alertas.

    sudo /opt/dirtyland/geoip/generar-tabla-paises.py           en la VPS, por cron
    python3 generar-tabla-paises.py --salida ./TELEGRAM\\ SCRIPTS/geoip
    python3 generar-tabla-paises.py --comprobar                 solo mira si toca
    python3 generar-tabla-paises.py --nombres --salida ...      los nombres, aparte

DOS FUENTES, PORQUE SON DOS PREGUNTAS DISTINTAS.

  UBICACION  db-ip.com (base "IP to Country Lite"). Donde ESTA la maquina,
             estimado con medidas de red. Es lo que responde tambien
             AbuseIPDB, y por tanto lo que espera quien lee una bandera.

  REGISTRO   Los cinco RIR, que publican cada rango asignado y su pais. Dice
             QUIEN es el titular del bloque y donde se dio de alta.

Coinciden en el 92% de las IP. Donde discrepan es en la nube y en los rangos
ALQUILADOS ---un intermediario alquila bloques a titulares de medio mundo y
los anuncia desde su centro de datos--- que es justo el perfil de la
infraestructura desde la que atacan a un senuelo.

Por eso se guardan las dos y el aviso las ensena las dos CUANDO NO COINCIDEN:
esa discrepancia no es ruido, es la senal de que el rango esta alquilado.

Las dos son publicas y se bajan sin cuenta ni clave, asi que esto no consume
cuota de nada. La de db-ip es CC-BY: pide atribucion, y esta puesta en el
README.

POR QUE NO SE CONSULTA EN CALIENTE. Preguntarle a una API por cada IP que
aparece en una alerta gasta cuota que hace falta para denunciar, mete una
espera en el camino del aviso, y ata el senuelo a un tercero. Con la tabla en
disco, una busqueda son 18 saltos de fichero: 0,018 ms y cero memoria.

QUE PAIS ES. El del REGISTRO del rango, no el de la maquina. Un atacante
detras de un VPS holandes sale de Paises Bajos. Para un senuelo es justo lo
que interesa ---dice de que infraestructura viene--- pero no puede leerse como
"el atacante esta en ese pais", y por eso las alertas no lo dicen asi.

FALLA HACIA EL LADO RUIDOSO. Si una descarga falla, si el fichero llega a
medias o si la tabla resultante es sospechosamente pequena, NO se toca la
tabla que ya hay y se sale con codigo distinto de cero. Una tabla vieja da
banderas algo desfasadas; una tabla vacia deja de dar banderas y nadie se
entera. Con --avisar, ademas lo cuenta por Telegram.
"""
from __future__ import annotations

import argparse
import gzip
import ipaddress
import os
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

FUENTES = {
    "apnic": "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
    "ripencc": "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
    "arin": "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "afrinic": "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
    "lacnic": "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
}

# db-ip publica un fichero por mes. A primeros puede no estar el del mes en
# curso todavia, asi que se prueba tambien el anterior antes de rendirse.
DBIP = "https://download.db-ip.com/free/dbip-country-lite-%s.csv.gz"

# db-ip devuelve 403 al agente por defecto de urllib. Se identifica el
# proyecto, que ademas es lo correcto al bajar de un servidor ajeno: quien
# mire su log ve quien es y puede quejarse si molestamos.
AGENTE = "dirtyland-geoip/1.0 (+tabla de paises para un honeypot)"

# Puerta para las pruebas, la misma idea que el --test de los demas
# vigilantes. Con PAISES_FUENTE_BASE apuntando a otro sitio ---un file:// que
# no existe, por ejemplo--- se ejercita el camino del fallo sin bajar los 45
# MB de verdad. Es la unica forma de ver como queda el aviso de "no se pudo
# regenerar" sin esperar a que se caiga un RIR.
_BASE = os.environ.get("PAISES_FUENTE_BASE")

# La otra mitad de esa puerta. Un fichero delegado ronda el mega y el CSV de
# db-ip pasa de los diez, asi que menos que eso significa pagina de error o
# descarga cortada. Al ensayar se sirven fuentes de juguete, que son de unos
# pocos kilobytes, y sin poder bajar ese listón no se llegaria nunca a los
# avisos siguientes: el fallo saltaria aqui y siempre seria el mismo.
MINIMO_BYTES_RIR = int(os.environ.get("PAISES_MINIMO_RIR", "500000"))
MINIMO_BYTES_DBIP = int(os.environ.get("PAISES_MINIMO_DBIP", "1000000"))
if _BASE:
    FUENTES = {n: _BASE + "/" + n for n in FUENTES}
    DBIP = _BASE + "/dbip-%s.csv.gz"


def _abrir(url: str, espera: int):
    pet = urllib.request.Request(url, headers={"User-Agent": AGENTE})
    return urllib.request.urlopen(pet, timeout=espera)

SALIDA = "/opt/dirtyland/geoip"
ALERTA = os.environ.get("ALERTA", "/opt/dirtyland/monitor/send-alert.sh")

# Ancho FIJO de cada registro, que es lo que permite buscar con seek() sin
# leer el fichero entero. Si se cambia aqui hay que cambiarlo en paises.py:
# la prueba comprueba que los dos digan lo mismo.
ANCHO_V4 = 14      # 10 digitos + espacio + 2 letras + salto
ANCHO_V6 = 20      # 16 hex     + espacio + 2 letras + salto

# Por debajo de esto la tabla esta rota, venga de donde venga. Se cuentan los
# rangos YA FUSIONADOS, que hoy son unos 142.000 y 68.000 ---no los 261.000 y
# 70.000 de los ficheros en crudo, que es un numero distinto y facil de
# confundir---. El margen es amplio a proposito: esto no esta para detectar
# que falten unos cuantos rangos, sino para que una descarga rota no sustituya
# la tabla buena por una tabla vacia.
MINIMO_V4 = 100_000
MINIMO_V6 = 50_000

# Cada cuanto conviene regenerarla. No es una caducidad dura: una tabla de
# hace meses sigue acertando en la inmensa mayoria de las IP.
DIAS_FRESCA = 15


# ---------------------------------------------------------------------------
# Los NOMBRES son otra cosa y se generan aparte, con --nombres, porque salen
# del paquete `iso-codes` de Debian (con sus traducciones) y ese paquete no
# esta en la VPS ni tiene por que estarlo. El fichero resultante viaja en el
# repositorio: los nombres de los paises no cambian de un mes para otro, asi
# que el cron no tiene que rehacerlo nunca.
#
# Se generan y no se teclean por lo de siempre: 249 nombres escritos a mano
# son 249 oportunidades de colar una errata que nadie va a revisar.
ISO_JSON = "/usr/share/iso-codes/json/iso_3166-1.json"

# Lo que iso-codes da en su forma oficial y en una notificacion del movil se
# lee fatal. Se queda el nombre de uso corriente. (En SX, ademas, la propia
# traduccion trae una errata: "zona holandsea".)
NOMBRE_CORTO = {
    "BO": "Bolivia", "BQ": "Caribe Neerlandes", "CD": "Rep. Dem. del Congo",
    "CF": "Rep. Centroafricana", "FK": "Islas Malvinas", "FM": "Micronesia",
    "GS": "Georgias del Sur", "IO": "Terr. Britanico del Indico",
    "IR": "Iran", "KM": "Comoras", "KP": "Corea del Norte",
    "KR": "Corea del Sur", "LA": "Laos", "MD": "Moldavia",
    "MF": "San Martin", "MP": "Marianas del Norte", "PS": "Palestina",
    "RU": "Rusia", "SH": "Santa Elena", "SX": "Sint Maarten", "SY": "Siria",
    "TF": "Terr. Australes Franceses", "TW": "Taiwan", "TZ": "Tanzania",
    "UM": "Islas Menores de EE.UU.", "VA": "Vaticano",
    "VC": "San Vicente y Granadinas", "VE": "Venezuela",
    "VG": "Islas Virgenes Britanicas", "VI": "Islas Virgenes de EE.UU.",
}

# Codigos que los RIR usan y que NO estan en la ISO 3166-1, asi que iso-codes
# no los trae. "EU" lo pone RIPE en los rangos que no asigna a un pais
# concreto. Si algun dia aparece otro, la prueba lo canta ---hay una que
# compara los codigos de la tabla con los de nombres.txt--- y se anade aqui.
FUERA_DE_LA_ISO = {
    "EU": "Union Europea",
    "AP": "Asia-Pacifico",
}


def generar_nombres(destino: str) -> int:
    """CC -> nombre en espanol, de iso-codes. Solo en nuestro equipo."""
    import gettext
    import json
    import unicodedata
    try:
        datos = json.load(open(ISO_JSON, encoding="utf-8"))
        tr = gettext.translation("iso_3166-1", "/usr/share/locale",
                                 languages=["es"])
    except (OSError, ValueError) as exc:
        print(f"hace falta el paquete iso-codes: {exc}", file=sys.stderr)
        print("  sudo apt install -y iso-codes", file=sys.stderr)
        return 2

    todos = {p["alpha_2"]: tr.gettext(p["name"]) for p in datos["3166-1"]}
    todos.update(FUERA_DE_LA_ISO)
    lineas = []
    for cc in sorted(todos):
        nombre = NOMBRE_CORTO.get(cc) or todos[cc]
        # Sin tildes: el resto de los scripts del proyecto escriben en ASCII
        # para no depender del locale con el que arranque cron, y una tilde
        # partida se ve peor que no tenerla.
        nombre = "".join(c for c in unicodedata.normalize("NFD", nombre)
                         if unicodedata.category(c) != "Mn")
        lineas.append(f"{cc} {nombre}")
    escribir(destino, "nombres.txt",
             "# CC ISO 3166-1 -> nombre en espanol.\n"
             "# Generado con: generar-tabla-paises.py --nombres\n"
             "# Fuente: paquete iso-codes de Debian. No se edita a mano.\n"
             + "\n".join(lineas) + "\n")
    print("%d paises escritos en %s/nombres.txt" % (len(lineas), destino))
    return 0


def paso(texto: str, fin: str = "\n") -> None:
    """Una linea de "voy por aqui", con flush.

    NO es adorno. Esto baja unos 45 MB de seis servidores distintos y antes no
    escribia una sola linea hasta terminar: no habia forma de distinguir "va
    lento" de "se ha colgado", y hubo que preguntarlo.

    Y hay un motivo peor. Se ejecuta por SSH a traves del proxy SOCKS5 de
    Mullvad, donde un canal que se queda callado acaba cortado con un "broken
    pipe" ---o sea que el silencio no solo confundia, tumbaba la sesion---. Con
    esto el canal tiene trafico cada pocos segundos.

    El flush es obligatorio: sin el, Python guarda la salida en un buffer
    cuando no habla con un terminal y las lineas saldrian todas juntas al
    final, que es igual que no tenerlas. En el cron va con >/dev/null, asi que
    ahi no molesta.
    """
    print(texto, end=fin, flush=True)


def descargar(nombre: str, url: str) -> str:
    paso("  %-10s bajando... " % nombre, fin="")
    try:
        with _abrir(url, 120) as r:
            datos = r.read()
    except (urllib.error.URLError, OSError, ValueError) as exc:
        paso("FALLO")
        raise RuntimeError(f"{nombre}: no se pudo descargar ({exc})") from exc
    paso("%.1f MB" % (len(datos) / 1048576))
    # Un fichero delegado ronda el mega como minimo. Menos que eso es una
    # pagina de error, una redireccion o una descarga cortada.
    if len(datos) < MINIMO_BYTES_RIR:
        raise RuntimeError(f"{nombre}: solo {len(datos)} bytes, viene a medias")
    return datos.decode("utf-8", "replace")


def descargar_dbip() -> bytes:
    """El CSV de db-ip del mes, o el del mes pasado si aun no esta."""
    hoy = datetime.now(timezone.utc)
    meses = [hoy.strftime("%Y-%m")]
    anterior = hoy.replace(day=1) - timedelta(days=1)
    meses.append(anterior.strftime("%Y-%m"))
    ultimo = ""
    for mes in meses:
        paso("  %-10s bajando %s... " % ("db-ip", mes), fin="")
        try:
            with _abrir(DBIP % mes, 180) as r:
                datos = r.read()
        except (urllib.error.URLError, OSError, ValueError) as exc:
            paso("no esta")
            ultimo = f"{mes}: {exc}"
            continue
        if len(datos) < MINIMO_BYTES_DBIP:
            paso("viene a medias")
            ultimo = f"{mes}: solo {len(datos)} bytes"
            continue
        paso("%.1f MB" % (len(datos) / 1048576))
        return datos
    raise RuntimeError(f"db-ip: no se pudo descargar ({ultimo})")


def rangos_dbip(datos: bytes, familia: str) -> list[list]:
    """[inicio, fin, pais] del CSV de db-ip. Formato: inicio,fin,CC."""
    salida = []
    quiere4 = familia == "ipv4"
    for linea in gzip.decompress(datos).decode("utf-8", "replace").splitlines():
        campos = linea.split(",")
        if len(campos) != 3:
            continue
        cc = campos[2].strip().upper()
        # ZZ es "sin determinar" en db-ip: es un hueco, no un pais.
        if len(cc) != 2 or not cc.isalpha() or cc == "ZZ":
            continue
        try:
            a = ipaddress.ip_address(campos[0])
            b = ipaddress.ip_address(campos[1])
        except ValueError:
            continue
        if (a.version == 4) != quiere4:
            continue
        if quiere4:
            salida.append([int(a), int(b), cc])
        else:
            salida.append([int(a) >> 64, int(b) >> 64, cc])
    salida.sort()
    return _fusionar(_sin_solapes(salida))


def _fusionar(rs: list[list]) -> list[list]:
    """Pega los contiguos del mismo pais. Ahorra casi la mitad de la tabla."""
    fus: list[list] = []
    for ini, fin, cc in rs:
        if fus and fus[-1][2] == cc and ini <= fus[-1][1] + 1:
            fus[-1][1] = max(fus[-1][1], fin)
        else:
            fus.append([ini, fin, cc])
    return fus


def rangos(textos: dict[str, str], familia: str) -> list[list]:
    """[inicio, fin, pais] de cada rango asignado, ordenados y fusionados."""
    crudos = []
    for nombre, texto in textos.items():
        for linea in texto.splitlines():
            if not linea or linea.startswith("#") or "|" not in linea:
                continue
            campos = linea.split("|")
            # registro|cc|tipo|inicio|valor|fecha|estado[|extensiones]
            if len(campos) < 7 or campos[2] != familia:
                continue
            # "available" y "reserved" no son de nadie todavia; solo cuentan
            # las que estan en manos de alguien.
            if campos[6] not in ("allocated", "assigned"):
                continue
            cc = campos[1].upper()
            if len(cc) != 2 or not cc.isalpha():
                continue
            try:
                if familia == "ipv4":
                    # OJO: en ipv4 el quinto campo es un NUMERO DE
                    # DIRECCIONES, no una longitud de prefijo.
                    ini = int(ipaddress.IPv4Address(campos[3]))
                    crudos.append([ini, ini + int(campos[4]) - 1, cc])
                else:
                    red = ipaddress.IPv6Network(f"{campos[3]}/{campos[4]}",
                                                strict=False)
                    # Se guarda el /64: para saber el pais sobra, y hace que
                    # el numero quepa en 16 hex en vez de 32.
                    crudos.append([int(red.network_address) >> 64,
                                   int(red.broadcast_address) >> 64, cc])
            except (ValueError, ipaddress.AddressValueError):
                continue

    crudos.sort()
    antes = _cubierto(crudos)
    crudos = _sin_solapes(crudos)
    despues = _cubierto(crudos)
    # EL CINTURON. Resolver solapes no puede PERDER direcciones: si la version
    # de antes hubiera tenido esto, el hueco de trece paises no habria llegado
    # nunca al repositorio. Una tabla con agujeros no da error en ninguna
    # parte: simplemente hay IP que se quedan sin bandera y nadie se entera.
    if antes != despues:
        raise RuntimeError(
            "resolver los solapes de %s ha cambiado la cobertura: %d "
            "direcciones antes, %d despues (%+d). La tabla tendria agujeros."
            % (familia, antes, despues, despues - antes))

    return _fusionar(crudos)


def _sin_solapes(crudos: list[list]) -> list[list]:
    """Deja los rangos sin pisarse, SIN perder ni una direccion.

    Los RIR se pisan de vez en cuando: el mismo bloque aparece dos veces con
    paises distintos, o uno pequeno vive dentro de otro. Es raro ---un punado
    entre 261.000--- pero hay que resolverlo, porque la busqueda binaria vive
    de que la tabla este estrictamente ordenada: con dos lineas empezando en
    el mismo numero, cual gana depende de por donde caiga el salto.

    LA VERSION ANTERIOR PERDIA RANGOS, y de la peor manera: llevaba un
    `fin_anterior` como MAXIMO CORRIDO, asi que en cuanto aparecia un bloque
    grande se descartaba todo lo que viniera detras con un final menor ---
    aunque no se pisaran con nada--- y en la tabla salia un HUECO donde habia
    trece paises. Una IP de esa zona se quedaba sin bandera y nada lo decia.

    Ahora se trabaja por RACIMOS: se agrupan los rangos que de verdad se
    tocan entre si, y solo dentro de cada racimo ---que casi siempre tiene un
    solo elemento--- se decide quien manda en cada trozo. Gana el rango MAS
    PEQUENO que cubre ese trozo, que es la asignacion mas concreta.
    """
    salida: list[list] = []
    racimo: list[list] = []
    tope = -1

    def cerrar():
        if not racimo:
            return
        if len(racimo) == 1:
            salida.append(racimo[0])
            return
        # Dentro del racimo: se corta por todos los bordes y a cada trozo se
        # le asigna el rango mas pequeno que lo cubre.
        bordes = sorted({b for ini, fin, _ in racimo for b in (ini, fin + 1)})
        for a, b in zip(bordes, bordes[1:]):
            mejor = None
            for ini, fin, cc in racimo:
                if ini <= a and b - 1 <= fin:
                    if mejor is None or (fin - ini) < mejor[0]:
                        mejor = (fin - ini, cc)
            if mejor is not None:
                salida.append([a, b - 1, mejor[1]])

    for ini, fin, cc in crudos:
        if racimo and ini > tope:
            cerrar()
            racimo = []
        racimo.append([ini, fin, cc])
        tope = max(tope, fin)
    cerrar()
    salida.sort()
    return salida


def _cubierto(rangos: list[list]) -> int:
    """Cuantas direcciones cubre una lista de rangos, sin contar dos veces."""
    total = 0
    fin_ant = -1
    for ini, fin, _cc in sorted(rangos):
        if fin <= fin_ant:
            continue
        total += fin - max(ini, fin_ant + 1) + 1
        fin_ant = fin
    return total


def tabla(fusionados: list[list], ancho: int, hexa: bool) -> str:
    """El texto final: una linea por corte, todas del mismo largo.

    Se guarda solo el INICIO de cada tramo, no el final: el final del tramo es
    el inicio del siguiente. Los huecos ---direcciones que no son de nadie---
    llevan "??" para que buscar dentro de uno no devuelva el pais del tramo
    anterior.
    """
    lineas = []
    anterior = -1
    for ini, fin, cc in fusionados:
        if ini > anterior + 1:
            lineas.append(_num(anterior + 1, ancho, hexa) + " ??")
        lineas.append(_num(ini, ancho, hexa) + " " + cc)
        anterior = fin
    # La marca de hueco del final solo si CABE. Si el ultimo tramo llega al
    # tope del espacio ---en IPv6 pasa: los /64 se acaban en 2^64-1--- el
    # "anterior + 1" necesitaria un digito mas y esa linea romperia el ancho
    # fijo, que es de lo que vive la busqueda por seek(). Y no hace falta: si
    # no hay nada detras, no hay hueco que marcar.
    tope = (16 if hexa else 10) ** (ancho - 4)
    if anterior + 1 < tope:
        lineas.append(_num(anterior + 1, ancho, hexa) + " ??")
    return "\n".join(lineas) + "\n"


def _num(valor: int, ancho: int, hexa: bool) -> str:
    return ("%0*x" if hexa else "%0*d") % (ancho - 4, valor)


def escribir(destino: str, nombre: str, contenido: str) -> None:
    """Deja el fichero de una pieza o no lo deja: nunca a medias.

    Se escribe al lado y se renombra, que en el mismo sistema de ficheros es
    atomico. Importa mas de lo normal porque el contenedor de Cowrie lee esta
    carpeta MONTADA: si se escribiera encima, habria un instante con la tabla
    partida y las busquedas de ese instante darian cualquier cosa.
    """
    tmp = os.path.join(destino, nombre + ".tmp")
    # newline="\n" EXPLICITO, porque estos ficheros son registros de ancho fijo
    # (ANCHO_V4 = 14 bytes contando el salto) y de eso vive la busqueda por
    # seek() de paises.py. Con la traduccion automatica de saltos, un registro
    # mediria 15 y CADA consulta caeria en mitad de una linea, devolviendo dos
    # caracteres cualesquiera con toda la pinta de ser un pais.
    #
    # En la VPS no cambia nada ---alli "\n" ya es "\n"--- y por eso no habia
    # mordido nunca. Va escrito de todas formas: el ancho fijo es un contrato
    # entre este fichero y paises.py, y un contrato no se deja al criterio del
    # sistema operativo en el que se ejecute. La suite tropezo con esto mismo.
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(contenido)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, os.path.join(destino, nombre))


def avisar(texto: str) -> None:
    """Lo cuenta por el bot del ANFITRION, si esta puesto."""
    if not os.access(ALERTA, os.X_OK):
        return
    try:
        subprocess.run([ALERTA, texto], timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        pass


def dias_desde(destino: str) -> float | None:
    sello = os.path.join(destino, "generada.txt")
    try:
        with open(sello, encoding="utf-8") as fh:
            for linea in fh:
                if linea.startswith("fecha "):
                    cuando = datetime.fromisoformat(linea.split(None, 1)[1].strip())
                    return (datetime.now(timezone.utc) - cuando).total_seconds() / 86400
    except (OSError, ValueError):
        return None
    return None


def main() -> int:
    p = argparse.ArgumentParser(description="Tabla de paises por rango de IP")
    p.add_argument("--salida", default=SALIDA, metavar="DIR")
    p.add_argument("--avisar", action="store_true",
                   help="cuenta el fallo por Telegram (para el cron)")
    p.add_argument("--comprobar", action="store_true",
                   help="solo dice cuantos dias tiene la tabla")
    p.add_argument("--nombres", action="store_true",
                   help="regenera nombres.txt (necesita iso-codes; no es cosa del cron)")
    a = p.parse_args()

    if a.nombres:
        return generar_nombres(a.salida)

    if a.comprobar:
        dias = dias_desde(a.salida)
        if dias is None:
            print("no hay tabla, o no tiene sello de fecha")
            return 1
        print("la tabla tiene %.0f dias (se regenera cada %d)" % (dias, DIAS_FRESCA))
        return 0 if dias <= DIAS_FRESCA * 2 else 1

    if not os.path.isdir(a.salida):
        print(f"no existe {a.salida}", file=sys.stderr)
        return 2

    textos = {}
    try:
        paso("bajando las fuentes (unos 45 MB; los de afrinic y lacnic van "
             "lentos):")
        for nombre, url in FUENTES.items():
            textos[nombre] = descargar(nombre, url)
        crudo_dbip = descargar_dbip()
        # Lo de despues tampoco es instantaneo: son ~330.000 rangos que hay
        # que ordenar, recortar solapes y fusionar. Sin esta linea, el rato
        # entre la ultima descarga y el resumen final vuelve a parecer un
        # cuelgue, que es justo lo que veniamos a quitar.
        paso("montando las tablas...")
    except RuntimeError as exc:
        # NO se toca lo que ya hay. Una tabla de hace un mes sigue sirviendo;
        # media tabla, no.
        print(f"ERROR: {exc}", file=sys.stderr)
        print("no se ha tocado la tabla anterior", file=sys.stderr)
        if a.avisar:
            avisar("⚠️ <b>Tabla de paises</b>\nNo se pudo regenerar: "
                   f"{exc}\nSigue usandose la anterior.")
        return 1

    try:
        tablas = {
            # El nombre dice QUE responde cada una, que es lo que hay que
            # tener claro al leerlas: donde esta la maquina, o quien registro
            # el bloque.
            "ubicacion-v4.txt": (rangos_dbip(crudo_dbip, "ipv4"), ANCHO_V4, False),
            "ubicacion-v6.txt": (rangos_dbip(crudo_dbip, "ipv6"), ANCHO_V6, True),
            "registro-v4.txt": (rangos(textos, "ipv4"), ANCHO_V4, False),
            "registro-v6.txt": (rangos(textos, "ipv6"), ANCHO_V6, True),
        }
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        print("no se ha tocado la tabla anterior", file=sys.stderr)
        if a.avisar:
            avisar("⚠️ <b>Tabla de paises</b>\nEl generador se nego a "
                   f"escribir: {exc}")
        return 1
    for nombre, (rs, _ancho, _hexa) in tablas.items():
        minimo = MINIMO_V4 if nombre.endswith("v4.txt") else MINIMO_V6
        if len(rs) < minimo:
            print(f"ERROR: {nombre} sale con {len(rs)} rangos y se esperaban "
                  f"al menos {minimo}", file=sys.stderr)
            if a.avisar:
                avisar("⚠️ <b>Tabla de paises</b>\nLos datos llegaron "
                       "incompletos. Sigue usandose la anterior.")
            return 1

    textos_tabla = {}
    for nombre, (rs, ancho, hexa) in tablas.items():
        t = tabla(rs, ancho, hexa)
        # Si esto no cuadra, seek() apuntaria en medio de un registro y la
        # busqueda devolveria basura en vez de fallar.
        if len(t) % ancho:
            print(f"ERROR: {nombre} no es de ancho fijo", file=sys.stderr)
            return 1
        textos_tabla[nombre] = (t, ancho)

    for nombre, (t, _ancho) in textos_tabla.items():
        escribir(a.salida, nombre, t)
    escribir(a.salida, "generada.txt",
             "# Lo escribe generar-tabla-paises.py. No se edita a mano.\n"
             "fecha %s\n" % datetime.now(timezone.utc).replace(
                 microsecond=0).isoformat()
             + "fuentes db-ip %s\n" % " ".join(sorted(FUENTES))
             + "".join("tramos_%s %d\n" % (n.replace(".txt", ""), len(t) // an)
                       for n, (t, an) in sorted(textos_tabla.items())))
    print("tabla de paises en %s:" % a.salida)
    for n, (t, an) in sorted(textos_tabla.items()):
        print("  %-18s %7d tramos" % (n, len(t) // an))
    return 0


if __name__ == "__main__":
    sys.exit(main())
