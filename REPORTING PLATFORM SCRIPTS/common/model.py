# SPDX-License-Identifier: GPL-2.0-or-later
"""
Modelo de evento normalizado: el contrato entre collectors y reporters.

Los collectors saben de honeypots y no saben nada de plataformas.
Los reporters saben de plataformas y no saben nada de honeypots.
Este fichero es lo unico que ambos comparten, y por eso vive en common/ y no
en collectors/: si viviera alli, los reporters tendrian que importar del
paquete de collectors y la separacion se rompeia por el propio import.

Cuatro tipos de observacion, que son los que las plataformas saben consumir:

    AttackerIP  -> AbuseIPDB
    Sample      -> VirusTotal, y despues MalwareBazaar
    PayloadURL  -> URLhaus
    C2Indicator -> ThreatFox
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

# Origen del evento. Los reporters lo usan solo para etiquetar, nunca para
# decidir logica: si un reporter necesita un "if source == cowrie", es senal
# de que la abstraccion esta mal puesta.
SOURCE_COWRIE = "cowrie"
SOURCE_DIONAEA = "dionaea"


@dataclass
class AttackerIP:
    """Una IP que ha atacado, con la evidencia que justifica reportarla."""

    ip: str
    source: str
    first_seen: datetime
    last_seen: datetime
    # Evidencia. handshake_ok es condicion NECESARIA para reportar a AbuseIPDB:
    # su politica prohibe expresamente reportar SYN floods y UDP, donde el
    # origen puede estar falsificado.
    handshake_ok: bool = False
    login_failures: int = 0
    login_successes: int = 0
    commands: int = 0
    ports: set[int] = field(default_factory=set)
    source_ports: set[int] = field(default_factory=set)
    protocols: set[str] = field(default_factory=set)
    sqli_evidence: bool = False
    # Texto ya saneado por el collector. Nunca datos crudos del atacante.
    note: str = ""


@dataclass
class HostDistribucion:
    """Una IP que SIRVIO un binario malicioso. Destino: AbuseIPDB.

    No es un AttackerIP y por eso no reutiliza esa clase: la evidencia es de
    otra naturaleza. De un atacante tenemos su apreton de manos TCP, asi que su
    direccion no puede ir falsificada. De un servidor de distribucion no
    tenemos ninguna conexion entrante: lo que tenemos es que **nos bajamos de
    el un fichero** y ese fichero resulto ser malware confirmado.

    Esa es la unica evidencia que vale, y por eso se exige la muestra: si se
    denunciara por ver la direccion escrita en un comando, bastaria que un
    atacante teclease `wget http://<victima>/x` en el senuelo para que
    acusaramos a un tercero inocente.
    """

    ip: str
    url: str                        # de donde se bajo, tal cual se observo
    sha256: str                     # la muestra, que es la prueba
    seen_at: datetime
    source: str
    familia: str | None = None
    motores: int = 0                # cuantos motores la marcan en VirusTotal
    puerto: int | None = None


@dataclass
class Sample:
    """Un binario capturado en disco."""

    sha256: str
    path: Path
    size: int
    source: str
    seen_at: datetime
    # De donde salio, si se sabe. Es la clave de "campana" de la capa 4 de
    # unicidad, y ademas lo que se reporta a URLhaus.
    download_url: str | None = None
    download_host: str | None = None
    src_ip: str | None = None
    # Protocolo de la sesion que trajo la muestra ("ssh" o "telnet"), si el
    # log lo dijo. Sirve para no publicar "SSH/Telnet" cuando sabemos cual de
    # los dos fue. None = no consta, y entonces se dice lo generico.
    protocol: str | None = None

    @property
    def elf_machine(self) -> str | None:
        """Arquitectura del ELF (campo e_machine de la cabecera).

        Es la pieza que distingue un binario legitimamente distinto de un caso
        de hash busting: un mips y un arm de la misma campana son ficheros
        diferentes de verdad; dos del mismo e_machine que solo cambian en el
        relleno, no. Devuelve None si no es un ELF.
        """
        return elf_machine_of(self.path)


@dataclass
class PayloadURL:
    """URL desde la que se sirvio un binario. Destino: URLhaus."""

    url: str
    source: str
    seen_at: datetime
    sha256: str | None = None       # binario que sirvio, si lo capturamos
    src_ip: str | None = None


@dataclass
class C2Indicator:
    """Infraestructura de mando y control. Destino: ThreatFox."""

    ioc: str                        # "ip:port", dominio o URL
    ioc_type: str                   # ip:port | domain | url
    source: str
    seen_at: datetime
    threat_type: str = "payload_delivery"
    malware: str | None = None      # nombre de familia, cuando se conoce
    sha256: str | None = None       # muestra asociada, si la hay
    reference: str | None = None


# --------------------------------------------------------------------------
# Lectura de la cabecera ELF
# --------------------------------------------------------------------------
# Solo los valores de e_machine que aparecen en botnets IoT. El resto se
# devuelve como "em-<numero>": preferimos un identificador feo pero exacto a
# inventarnos un nombre.
_ELF_MACHINES = {
    0x02: "sparc", 0x03: "x86", 0x08: "mips", 0x14: "ppc", 0x15: "ppc64",
    0x16: "s390", 0x28: "arm", 0x2A: "superh", 0x32: "ia64", 0x3E: "x86_64",
    0xB7: "aarch64", 0xF3: "riscv", 0x5E: "m32r", 0x4C: "m32c",
}


def elf_machine_of(path: Path | str) -> str | None:
    """Devuelve la arquitectura de un ELF, o None si el fichero no lo es."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(20)
    except OSError:
        return None
    if len(head) < 20 or head[:4] != b"\x7fELF":
        return None
    little = head[5] == 1
    machine = struct.unpack_from("<H" if little else ">H", head, 18)[0]
    return _ELF_MACHINES.get(machine, f"em-{machine}")


# --- Como se nombra el servicio que capturo una muestra ---------------------
#
# Un solo sitio para los dos honeypots y para las tres plataformas que lo
# publican (AbuseIPDB por su lado, con los puertos del atacante). Antes cada
# reporter llevaba su etiqueta escrita y decia "SMB/RPC/MSSQL" o "SSH/Telnet"
# en TODAS las muestras, pasara lo que pasara: en la mitad de los casos era
# falso, y es un texto que queda publicado para siempre.
#
# El articulo va en la tabla y no fijo delante: "an SSH" y "an SMB" se leen
# bien porque esas siglas empiezan por sonido vocalico; "an Telnet" no lo
# escribe nadie.
SERVICIO_DE_PUERTO = {22: "ssh", 23: "telnet", 135: "rpc", 445: "smb",
                      1433: "mssql"}

SERVICIO_NOMBRE = {
    "ssh": ("an", "SSH"),
    "telnet": ("a", "Telnet"),
    "smb": ("an", "SMB"),
    "mssql": ("an", "MSSQL"),   # "em-ese-cu-ele": empieza por vocal
    "rpc": ("an", "RPC"),
}

# Lo que se dice cuando el registro NO permite saber el servicio concreto. Es
# cierto ---el senuelo sirve esos--- y solo se usa como ultimo recurso.
SERVICIO_GENERICO = {
    SOURCE_COWRIE: ("an", "SSH/Telnet"),
    SOURCE_DIONAEA: ("an", "SMB/RPC/MSSQL"),
}


def servicio_de(sample) -> tuple[str, str]:
    """(articulo, nombre) del servicio por el que llego la muestra."""
    clave = (getattr(sample, "protocol", None) or "").lower()
    if clave in SERVICIO_NOMBRE:
        return SERVICIO_NOMBRE[clave]
    return SERVICIO_GENERICO.get(sample.source, ("a", "network"))


# No es el nombre de una campana, es la ausencia de una. Se compara contra
# esta constante en vez de contra la cadena suelta para que nadie la escriba
# de memoria en otro sitio y deje de coincidir.
SIN_CAMPANA = "sin-campana"


# Ficheros que no son un payload y no tienen nada que hacer en VirusTotal.
# El limite es deliberadamente bajo: por encima de esto ya puede haber un
# dropper de verdad, y ante la duda se deja pasar y que decidan las puertas.
ARTEFACTO_MAX_BYTES = 512

# Comienzos de una linea de authorized_keys. Es el caso que lo motivo: el
# atacante instala su clave publica con un echo y Cowrie guarda lo escrito
# como si fuera una muestra capturada.
_CLAVES_SSH = (b"ssh-rsa ", b"ssh-ed25519 ", b"ssh-dss ", b"ecdsa-sha2-",
               b"sk-ssh-ed25519", b"sk-ecdsa-sha2-")

# Cabeceras de cosas que SI son ejecutables o contenedores de codigo.
_FIRMAS_PAYLOAD = (b"\x7fELF", b"MZ", b"#!", b"\xca\xfe\xba\xbe",
                   b"\xcf\xfa\xed\xfe", b"PK\x03\x04", b"\x1f\x8b",
                   b"BZh", b"\xfd7zXZ", b"\x7fCGC")


def artefacto_inocuo(path: Path | str, size: int) -> str | None:
    """Devuelve por que este fichero NO es una muestra, o None si podria serlo.

    Existe por un caso real: el atacante escribe su clave publica con
        echo "ssh-rsa AAAA..." > ~/.ssh/authorized_keys
    y Cowrie guarda lo escrito como fichero capturado. Eso llegaba a la cola
    como una muestra mas, y si VirusTotal no lo conocia se le subia como
    "primera aparicion". No es malware: es un fichero de texto con una clave
    publica. Ensuciar su base con eso no aporta nada y gasta cuota.

    Publicarlo nunca fue posible --- la puerta de 12 motores lo rechaza, y de
    hecho lo rechazaba ---, asi que esto no anade seguridad frente a un baneo:
    evita ruido y consultas inutiles. Se aplica ANTES de preguntar a
    VirusTotal, que es donde se ahorra la cuota.

    Es deliberadamente timido. Solo descarta lo que es claramente inofensivo:
    claves SSH, y texto plano diminuto sin ninguna cabecera ejecutable. Un
    script con shebang, cualquier ELF o PE, y cualquier cosa por encima de
    ARTEFACTO_MAX_BYTES siguen su camino normal.
    """
    try:
        with open(path, "rb") as fh:
            cabeza = fh.read(4096)
    except OSError:
        return None                      # ante la duda, que siga

    if any(cabeza.startswith(f) for f in _FIRMAS_PAYLOAD):
        return None

    limpio = cabeza.lstrip()
    if any(limpio.startswith(k) for k in _CLAVES_SSH):
        return "es una clave SSH publica, no un binario"
    # authorized_keys con opciones delante: command="...",no-pty ssh-rsa AAAA
    if any(k in cabeza for k in _CLAVES_SSH) and b"\n" not in cabeza.strip():
        return "es una linea de authorized_keys, no un binario"

    if size > ARTEFACTO_MAX_BYTES:
        return None
    if b"\x00" in cabeza:
        return None                      # tiene binario dentro: que lo miren
    try:
        cabeza.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return (f"texto plano de {size} bytes sin cabecera ejecutable ni shebang")


def campaign_host(sample: Sample) -> str:
    """De donde vino la muestra: la "campana" a efectos de unicidad.

    Existe como funcion, y no como una expresion escrita en cada sitio, porque
    esto se calcula en dos momentos distintos: al recoger la muestra (para
    guardarlo) y al decidir si se publica (para buscarlo). Escrito dos veces,
    basta con que difieran en un detalle para que la busqueda no encuentre
    nunca lo guardado y la comprobacion quede muerta sin dar ningun error.

    Si no conocemos el host de descarga (habitual en Dionaea, donde el binario
    llega por SMB y no por una URL) se usa la IP de origen. Y si tampoco la
    hay, se devuelve SIN_CAMPANA, que NO es una campana: es la ausencia de
    ella. Quien lo reciba tiene que tratarlo como "no se sabe", no como un
    grupo mas --- meter en el mismo saco muestras de atacantes distintos no es
    conservador, es sacar una conclusion falsa.
    """
    return sample.download_host or sample.src_ip or SIN_CAMPANA


def campaign_key(sample: Sample, family: str | None) -> str:
    """Clave de la capa 4 de unicidad: (familia, campana, arquitectura).

    Se sube una sola muestra por clave. La capa 5, la de rafaga, NO usa esta
    clave sino solo el host y la arquitectura: cuando se recoge la muestra
    todavia no hay veredicto y por tanto no se conoce la familia.
    """
    return (f"{family or 'sin-familia'}|{campaign_host(sample)}"
            f"|{sample.elf_machine or 'no-elf'}")
