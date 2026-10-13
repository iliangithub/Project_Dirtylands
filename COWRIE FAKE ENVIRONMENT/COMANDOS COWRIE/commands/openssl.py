# SPDX-License-Identifier: BSD-3-Clause
#
# openssl emulado.
#
# No estaba, y eso era una CONTRADICCION, no una falta. La maquina falsa tiene
# openssl instalado: no porque build-dirtyland-fs.sh lo pida, sino porque
# ca-certificates lo arrastra como dependencia. Medido en el mismo Debian 13
# del que sale el pickle: /usr/bin/openssl existe (1103304 bytes) y dpkg lo
# lista como openssl 3.5.7-1~deb13u2. Asi que "ls -l /usr/bin/openssl" lo
# ensenaba, "which openssl" lo encontraba, "dpkg -l" lo declaraba... y
# teclearlo contestaba "command not found". Tres piezas diciendo que si y una
# diciendo que no.
#
# Todo lo de aqui esta MEDIDO contra OpenSSL 3.5.7 en un debian:trixie, no
# recordado. Lo que NO se emula esta escrito al final del fichero y en
# el 3.4.2.8 del README; nada de aqui inventa una salida.
from __future__ import annotations

import base64
import hashlib
import math
import os
import random

from cowrie.shell.command import HoneyPotCommand

commands = {}

# Lo exporta build-dirtyland-fs.sh desde el MISMO contenedor del que sale el
# pickle, igual que dpkg-packages.tsv (apartado 3.4.2.9). Si el fichero no
# esta ---por ejemplo con un pickle generado antes de que esto existiera---
# se usan las constantes de abajo, pero el NUMERO de version se saca siempre
# de la tabla de dpkg: es el unico dato que otra pieza del senuelo tambien
# publica, y son los dos que no pueden discrepar.
RUTA_VERSION = "/opt/openssl-version.txt"

VERSION_POR_DEFECTO = "3.5.7-1~deb13u2"
FECHA_POR_DEFECTO = "9 Jun 2026"
CONSTRUIDO_POR_DEFECTO = "Sun Aug 23 15:26:22 2026 UTC"

# La linea CPUINFO de "openssl version -a" sale del procesador de VERDAD.
# Por eso NO se exporta del contenedor de construccion: eso meteria en el
# senuelo las capacidades de la CPU de quien lo genero, que es exactamente el
# rastro que sanitize-pickle.py existe para borrar. Este valor es fijo y
# describe al Intel Core i5-12400 que declara nuestro /proc/cpuinfo: Alder
# Lake con AES y SHA-NI, con AVX2 y SIN AVX-512, que es lo que dice la lista
# de flags de sanitize-pickle.py.
CPUINFO = ("OPENSSL_ia32cap=0x7ffaf3bfffebffff:0x18c007ac239c27ab:"
           "0x0000000000000000:0x0000000000000000:0x0000000000000000")

COMPILADOR = (
    "gcc -fPIC -pthread -m64 -Wa,--noexecstack -Wall -fzero-call-used-regs="
    "used-gpr -Wa,--noexecstack -g -O2 -Werror=implicit-function-declaration"
    " -ffile-prefix-map=/build/reproducible-path/openssl-%s=. "
    "-fstack-protector-strong -fstack-clash-protection -Wformat "
    "-Werror=format-security -fcf-protection -DOPENSSL_USE_NODELETE "
    "-DL_ENDIAN -DOPENSSL_PIC -DOPENSSL_BUILDING_OPENSSL -DZLIB -DZSTD "
    "-DNDEBUG -Wdate-time -D_FORTIFY_SOURCE=2"
)

DIRECTORIOS = [
    'OPENSSLDIR: "/usr/lib/ssl"',
    'ENGINESDIR: "/usr/lib/x86_64-linux-gnu/engines-3"',
    'MODULESDIR: "/usr/lib/x86_64-linux-gnu/ossl-modules"',
]

# --- Los tres listados que imprime "openssl help" ---------------------------
#
# Sacados del help de verdad, no escritos a mano: se leyeron sus lineas y se
# partieron en columnas de 18. La comprobacion de que el ancho es 18 se hizo
# sobre TODAS las lineas, no sobre una.
ESTANDAR = [
    "asn1parse", "ca", "ciphers", "cmp",
    "cms", "crl", "crl2pkcs7", "dgst",
    "dhparam", "dsa", "dsaparam", "ec",
    "ecparam", "enc", "engine", "errstr",
    "fipsinstall", "gendsa", "genpkey", "genrsa",
    "help", "info", "kdf", "list",
    "mac", "nseq", "ocsp", "passwd",
    "pkcs12", "pkcs7", "pkcs8", "pkey",
    "pkeyparam", "pkeyutl", "prime", "rand",
    "rehash", "req", "rsa", "rsautl",
    "s_client", "s_server", "s_time", "sess_id",
    "skeyutl", "smime", "speed", "spkac",
    "srp", "storeutl", "ts", "verify",
    "version", "x509",
]

DIGESTS = [
    "blake2b512", "blake2s256", "md4", "md5",
    "rmd160", "sha1", "sha224", "sha256",
    "sha3-224", "sha3-256", "sha3-384", "sha3-512",
    "sha384", "sha512", "sha512-224", "sha512-256",
    "shake128", "shake256", "sm3",
]

CIFRADOS = [
    "aes-128-cbc", "aes-128-ecb", "aes-192-cbc", "aes-192-ecb",
    "aes-256-cbc", "aes-256-ecb", "aria-128-cbc", "aria-128-cfb",
    "aria-128-cfb1", "aria-128-cfb8", "aria-128-ctr", "aria-128-ecb",
    "aria-128-ofb", "aria-192-cbc", "aria-192-cfb", "aria-192-cfb1",
    "aria-192-cfb8", "aria-192-ctr", "aria-192-ecb", "aria-192-ofb",
    "aria-256-cbc", "aria-256-cfb", "aria-256-cfb1", "aria-256-cfb8",
    "aria-256-ctr", "aria-256-ecb", "aria-256-ofb", "base64",
    "bf", "bf-cbc", "bf-cfb", "bf-ecb",
    "bf-ofb", "camellia-128-cbc", "camellia-128-ecb", "camellia-192-cbc",
    "camellia-192-ecb", "camellia-256-cbc", "camellia-256-ecb", "cast",
    "cast-cbc", "cast5-cbc", "cast5-cfb", "cast5-ecb",
    "cast5-ofb", "des", "des-cbc", "des-cfb",
    "des-ecb", "des-ede", "des-ede-cbc", "des-ede-cfb",
    "des-ede-ofb", "des-ede3", "des-ede3-cbc", "des-ede3-cfb",
    "des-ede3-ofb", "des-ofb", "des3", "desx",
    "rc2", "rc2-40-cbc", "rc2-64-cbc", "rc2-cbc",
    "rc2-cfb", "rc2-ecb", "rc2-ofb", "rc4",
    "rc4-40", "seed", "seed-cbc", "seed-cfb",
    "seed-ecb", "seed-ofb", "sm4-cbc", "sm4-cfb",
    "sm4-ctr", "sm4-ecb", "sm4-ofb", "zlib",
    "zstd",
]

CIPHERS = (
    "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_"
    "GCM_SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SH"
    "A384:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECD"
    "HE-RSA-CHACHA20-POLY1305:DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-A"
    "ES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-"
    "SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:DHE-RSA"
    "-AES256-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256"
    ":DHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-S"
    "HA:DHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SH"
    "A:DHE-RSA-AES128-SHA:RSA-PSK-AES256-GCM-SHA384:DHE-PSK-AES256-GC"
    "M-SHA384:RSA-PSK-CHACHA20-POLY1305:DHE-PSK-CHACHA20-POLY1305:ECD"
    "HE-PSK-CHACHA20-POLY1305:AES256-GCM-SHA384:PSK-AES256-GCM-SHA384"
    ":PSK-CHACHA20-POLY1305:RSA-PSK-AES128-GCM-SHA256:DHE-PSK-AES128-"
    "GCM-SHA256:AES128-GCM-SHA256:PSK-AES128-GCM-SHA256:AES256-SHA256"
    ":AES128-SHA256:ECDHE-PSK-AES256-CBC-SHA384:ECDHE-PSK-AES256-CBC-"
    "SHA:SRP-RSA-AES-256-CBC-SHA:SRP-AES-256-CBC-SHA:RSA-PSK-AES256-C"
    "BC-SHA384:DHE-PSK-AES256-CBC-SHA384:RSA-PSK-AES256-CBC-SHA:DHE-P"
    "SK-AES256-CBC-SHA:AES256-SHA:PSK-AES256-CBC-SHA384:PSK-AES256-CB"
    "C-SHA:ECDHE-PSK-AES128-CBC-SHA256:ECDHE-PSK-AES128-CBC-SHA:SRP-R"
    "SA-AES-128-CBC-SHA:SRP-AES-128-CBC-SHA:RSA-PSK-AES128-CBC-SHA256"
    ":DHE-PSK-AES128-CBC-SHA256:RSA-PSK-AES128-CBC-SHA:DHE-PSK-AES128"
    "-CBC-SHA:AES128-SHA:PSK-AES128-CBC-SHA256:PSK-AES128-CBC-SHA"
)

ANCHO_COLUMNA = 18
POR_FILA = 4


def columnas(nombres):
    """Los listados de openssl: cuatro por fila, 18 columnas cada uno.

    Ojo: el ultimo de cada fila TAMBIEN se rellena, o sea que las lineas
    acaban en espacios. Copiar eso importa: un "openssl help | cat -A" ensena
    esos espacios, y quitarlos seria un delator gratis.
    """
    filas = []
    for i in range(0, len(nombres), POR_FILA):
        filas.append("".join(n.ljust(ANCHO_COLUMNA)
                             for n in nombres[i:i + POR_FILA]))
    return "\n".join(filas) + "\n"


def texto_ayuda():
    return ("help:\n\nStandard commands\n%s\nMessage Digest commands "
            "(see the `dgst' command for more details)\n%s\nCipher commands "
            "(see the `enc' command for more details)\n%s\n"
            % (columnas(ESTANDAR), columnas(DIGESTS), columnas(CIFRADOS)))


# --- Resumenes --------------------------------------------------------------
#
# openssl NO se refiere a los algoritmos por el nombre de la opcion: "-sha256"
# se anuncia como "SHA2-256" y "-rmd160" como "RIPEMD-160". Medidos uno a uno.
NOMBRES_DIGEST = {
    "md5": "MD5", "sha1": "SHA1", "sha224": "SHA2-224",
    "sha256": "SHA2-256", "sha384": "SHA2-384", "sha512": "SHA2-512",
    "sha512-224": "SHA2-512/224", "sha512-256": "SHA2-512/256",
    "sha3-224": "SHA3-224", "sha3-256": "SHA3-256",
    "sha3-384": "SHA3-384", "sha3-512": "SHA3-512",
    "blake2b512": "BLAKE2B-512", "blake2s256": "BLAKE2S-256",
    "rmd160": "RIPEMD-160", "ripemd160": "RIPEMD-160", "sm3": "SM3",
}

# El nombre que hashlib entiende para cada uno.
HASHLIB_DIGEST = {
    "md5": "md5", "sha1": "sha1", "sha224": "sha224", "sha256": "sha256",
    "sha384": "sha384", "sha512": "sha512",
    "sha512-224": "sha512_224", "sha512-256": "sha512_256",
    "sha3-224": "sha3_224", "sha3-256": "sha3_256",
    "sha3-384": "sha3_384", "sha3-512": "sha3_512",
    "rmd160": "ripemd160", "ripemd160": "ripemd160", "sm3": "sm3",
}


def resume(alg, datos):
    """Devuelve el hexadecimal, o None si el algoritmo no esta disponible.

    Un openssl de Debian tampoco los tiene todos: "-md4" contesta "Error
    setting digest" porque el proveedor legacy no se carga. Devolver None y
    dar ese mismo mensaje es lo que hace la maquina de verdad, asi que aqui
    un algoritmo que le falte a hashlib se comporta igual que uno que le
    falte a openssl.
    """
    if alg == "blake2b512":
        return hashlib.blake2b(datos, digest_size=64).hexdigest()
    if alg == "blake2s256":
        return hashlib.blake2s(datos, digest_size=32).hexdigest()
    nombre = HASHLIB_DIGEST.get(alg)
    if not nombre:
        return None
    try:
        return hashlib.new(nombre, datos).hexdigest()
    except Exception:                                          # noqa: BLE001
        return None


# --- "openssl passwd": los hashes de /etc/shadow ----------------------------
#
# Se calculan de verdad. Un atacante usa esto para fabricarse una linea de
# shadow, y a veces la comprueba: devolver algo con la forma correcta pero mal
# calculado se cae en cuanto alguien verifica el hash contra la contrasena.
#
# Van escritos aqui a mano porque el modulo "crypt" de Python desaparecio en
# 3.13 y este codigo tiene que seguir funcionando cuando la imagen de Cowrie
# actualice. Los tres algoritmos estan comprobados contra el openssl real.
ALFABETO = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _a64(valor, cuantos):
    """La base64 propia de crypt(3): otro alfabeto y al reves que la normal."""
    salida = []
    for _ in range(cuantos):
        salida.append(ALFABETO[valor & 0x3F])
        valor >>= 6
    return "".join(salida)


def _md5crypt(clave, sal, magia=b"$1$"):
    # md5crypt CORTA la sal a 8. Medido: con sal "0123456789ab" el openssl
    # real devuelve "$1$01234567$...", no la sal entera.
    sal = sal[:8]
    ctx = hashlib.md5(clave + magia + sal)
    alterno = hashlib.md5(clave + sal + clave).digest()
    i = len(clave)
    while i > 0:
        ctx.update(alterno[:16] if i > 16 else alterno[:i])
        i -= 16
    i = len(clave)
    while i:
        ctx.update(b"\0" if i & 1 else clave[:1])
        i >>= 1
    final = ctx.digest()
    for i in range(1000):
        c = hashlib.md5()
        c.update(clave if i & 1 else final)
        if i % 3:
            c.update(sal)
        if i % 7:
            c.update(clave)
        c.update(final if i & 1 else clave)
        final = c.digest()
    orden = ((0, 6, 12), (1, 7, 13), (2, 8, 14), (3, 9, 15), (4, 10, 5))
    texto = "".join(_a64((final[a] << 16) | (final[b] << 8) | final[c], 4)
                    for a, b, c in orden)
    texto += _a64(final[11], 2)
    return "%s%s$%s" % (magia.decode(), sal.decode("latin-1"), texto)


def _shacrypt(clave, sal, bits, rondas=5000):
    """sha256-crypt y sha512-crypt, que solo se diferencian en el tamano."""
    sal = sal[:16]
    if bits == 512:
        crea, largo = hashlib.sha512, 64
        orden = [(0, 21, 42), (22, 43, 1), (44, 2, 23), (3, 24, 45),
                 (25, 46, 4), (47, 5, 26), (6, 27, 48), (28, 49, 7),
                 (50, 8, 29), (9, 30, 51), (31, 52, 10), (53, 11, 32),
                 (12, 33, 54), (34, 55, 13), (56, 14, 35), (15, 36, 57),
                 (37, 58, 16), (59, 17, 38), (18, 39, 60), (40, 61, 19),
                 (62, 20, 41)]
        ultimo, magia = (63,), "$6$"
    else:
        crea, largo = hashlib.sha256, 32
        orden = [(0, 10, 20), (21, 1, 11), (12, 22, 2), (3, 13, 23),
                 (24, 4, 14), (15, 25, 5), (6, 16, 26), (27, 7, 17),
                 (18, 28, 8), (9, 19, 29)]
        ultimo, magia = (31, 30), "$5$"

    b = crea(clave + sal + clave).digest()
    ctx = crea(clave + sal)
    i = len(clave)
    while i > largo:
        ctx.update(b)
        i -= largo
    ctx.update(b[:i])
    i = len(clave)
    while i:
        ctx.update(b if i & 1 else clave)
        i >>= 1
    a = ctx.digest()

    ctx = crea()
    for _ in range(len(clave)):
        ctx.update(clave)
    p = ctx.digest()
    p = p * (len(clave) // largo) + p[:len(clave) % largo]

    ctx = crea()
    for _ in range(16 + a[0]):
        ctx.update(sal)
    s = ctx.digest()
    s = s * (len(sal) // largo) + s[:len(sal) % largo]

    for i in range(rondas):
        ctx = crea()
        ctx.update(p if i & 1 else a)
        if i % 3:
            ctx.update(s)
        if i % 7:
            ctx.update(p)
        ctx.update(a if i & 1 else p)
        a = ctx.digest()

    texto = "".join(_a64((a[x] << 16) | (a[y] << 8) | a[z], 4)
                    for x, y, z in orden)
    if len(ultimo) == 1:
        texto += _a64(a[ultimo[0]], 2)
    else:
        texto += _a64((a[ultimo[0]] << 8) | a[ultimo[1]], 3)
    cab = magia if rondas == 5000 else "%srounds=%d$" % (magia, rondas)
    return "%s%s$%s" % (cab, sal.decode("latin-1"), texto)


def sal_aleatoria(cuantos):
    return "".join(random.choice(ALFABETO) for _ in range(cuantos))


# --- "openssl genrsa": la clave se genera de VERDAD -------------------------
#
# Es el unico subcomando estandar cuya llamada normal ---"openssl genrsa
# 2048"--- termina bien y produce algo. Devolver una clave fija seria un
# delator inmediato: dos ejecuciones darian la misma. Y devolver relleno con
# pinta de PEM se cae en cuanto alguien la usa.
#
# Asi que se genera. Dos primos con Miller-Rabin y el DER a mano: son unas
# 0.3 decimas para 2048 bits, del mismo orden que tarda el binario real. La
# comprobacion de que sale bien no es mirar el texto, es dar la clave al
# openssl de verdad y que la acepte.
OID_RSA = bytes([0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
                 0x01, 0x01, 0x01, 0x05, 0x00])


def _der_largo(n):
    if n < 0x80:
        return bytes([n])
    cuerpo = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(cuerpo)]) + cuerpo


def _der_entero(valor):
    crudo = valor.to_bytes((valor.bit_length() + 8) // 8 or 1, "big")
    return b"\x02" + _der_largo(len(crudo)) + crudo


def _der_secuencia(partes):
    cuerpo = b"".join(partes)
    return b"\x30" + _der_largo(len(cuerpo)) + cuerpo


def _primo_de(bits):
    while True:
        candidato = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if es_primo(candidato):
            return candidato


def clave_rsa(bits=2048, e=65537):
    """Devuelve el PEM PKCS#8, que es lo que saca un openssl 3."""
    while True:
        p = _primo_de(bits // 2)
        q = _primo_de(bits - bits // 2)
        if p == q:
            continue
        lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
        if math.gcd(e, lam) != 1:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        break
    if p < q:
        p, q = q, p
    d = pow(e, -1, lam)
    interna = _der_secuencia([
        _der_entero(0), _der_entero(n), _der_entero(e), _der_entero(d),
        _der_entero(p), _der_entero(q), _der_entero(d % (p - 1)),
        _der_entero(d % (q - 1)), _der_entero(pow(q, -1, p)),
    ])
    envuelta = _der_secuencia([
        _der_entero(0), OID_RSA,
        b"\x04" + _der_largo(len(interna)) + interna,
    ])
    texto = base64.b64encode(envuelta).decode()
    cuerpo = "".join(texto[i:i + 64] + "\n" for i in range(0, len(texto), 64))
    return ("-----BEGIN PRIVATE KEY-----\n%s"
            "-----END PRIVATE KEY-----\n" % cuerpo)


def es_primo(n):
    """Miller-Rabin con las bases que lo hacen exacto hasta 3.3e24.

    openssl usa una prueba probabilistica; para los numeros que alguien va a
    teclear a mano, esta da siempre la misma respuesta que aquella.
    """
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


# --- Los subcomandos que NO se emulan ---------------------------------------
#
# Estan en el listado de "help", asi que negarlos con "Invalid command" seria
# contradecir a nuestra propia ayuda. Y no se pueden hacer de verdad: casi
# todos piden claves, certificados o TLS. Lo que se hace es contestar lo que
# contesta el openssl REAL cuando se le llama sin darle con que trabajar, que
# es medido y es exactamente lo que ve un bot que teclea el subcomando a
# secas. Si el bot ADEMAS le pasa argumentos, esta respuesta se le queda
# corta: eso esta escrito en el 3.4.2.8 del README, no disimulado.
#
# Formato: subcomando -> (codigo de salida, salida normal, salida de error).
SIN_EMULAR = {
    "asn1parse": (1,
     '',
     'Error reading PEM file\n801726B4F57D0000:error:0480006C:PEM routines:ge'
     't_name:no start line:../crypto/pem/pem_lib.c:792:\n'),
    "ca": (1,
     '',
     'Using configuration from /usr/lib/ssl/openssl.cnf\nCould not open file '
     'or uri for loading CA private key from ./demoCA/private/cakey.pem: No s'
     'uch file or directory\n'),
    "cmp": (1,
     '',
     'Usage: openssl help cmp [options]\nValid options are:\n -help          '
     '        Display this summary\n -config val            Configuration fil'
     'e to use. "" = none. Default from env variable OPENSSL_CONF\n -section '
     'val           Section(s) in config file to get options from. "" = \'def'
     "ault'. Default 'cmp'\n -verbosity nonneg      Log level; 3=ERR, 4=WARN,"
     ' 6=INFO, 7=DEBUG, 8=TRACE. Default 6 = INFO\n\nGeneric message options:'
     '\n -cmd val               CMP request to send: ir/cr/kur/p10cr/rr/genm'
     '\n -infotype val          InfoType name for requesting specific info in'
     " genm, with specific support\n                        for 'caCerts' and"
     " 'rootCaCert'\n -profile val           Certificate profile name to plac"
     'e in generalInfo field of request PKIHeader\n -geninfo val           Co'
     'mma-separated list of OID and value to place in generalInfo PKIHeader\n'
     "                        of form <OID>:int:<n> or <OID>:str:<s>, e.g. '1"
     ".2.3.4:int:56789, id-kp:str:name'\n -template val          File to save"
     ' certTemplate received in genp of type certReqTemplate\n -keyspec val  '
     '         Optional file to save Key specification received in genp of ty'
     'pe certReqTemplate\n\nCertificate enrollment options:\n -newkey val    '
     '        Private or public key for the requested cert. Default: CSR key '
     'or client key\n -newkeypass val        New private key pass phrase sour'
     'ce\n -centralkeygen         Request central (server-side) key generatio'
     'n. Default is local generation\n -newkeyout val         File to save ce'
     'ntrally generated key, in PEM format\n -subject val           Distingui'
     'shed Name (DN) of subject to use in the requested cert template\n      '
     '                  For kur, default is subject of -csr arg or reference '
     'cert (see -oldcert)\n                        this default is used for i'
     'r and cr only if no Subject Alt Names are set\n -days nonneg           '
     'Requested validity time of the new certificate in number of days\n -req'
     'exts val           Name of config file section defining certificate req'
     'uest extensions.\n                        Augments or replaces any exte'
     'nsions contained CSR given with -csr\n -sans val              Subject A'
     'lt Names (IPADDR/DNS/URI) to add as (critical) cert req extension\n -sa'
     'n_nodefault         Do not take default SANs from reference certificate'
     ' (see -oldcert)\n -policies val          Name of config file section de'
     'fining policies certificate request extension\n -policy_oids val       '
     'Policy OID(s) to add as policies certificate request extension\n -polic'
     'y_oids_critical  Flag the policy OID(s) given with -policy_oids as crit'
     'ical\n -popo int              Proof-of-Possession (POPO) method to use '
     'for ir/cr/kur where\n                        -1 = NONE, 0 = RAVERIFIED,'
     ' 1 = SIGNATURE (default), 2 = KEYENC\n -csr val               PKCS#10 C'
     'SR file in PEM or DER format to convert or to use in p10cr\n -out_trust'
     'ed val       Certificates to trust when verifying newly enrolled certif'
     'icates\n -implicit_confirm      Request implicit confirmation of newly '
     'enrolled certificates\n -disable_confirm       Do not confirm newly enr'
     'olled certificate w/o requesting implicit\n                        conf'
     'irmation. WARNING: This leads to behavior violating RFC 9810\n -certout'
     ' val           File to save newly enrolled certificate\n -chainout val '
     '         File to save the chain of newly enrolled certificate\n\nCertif'
     'icate enrollment and revocation options:\n -oldcert val           Certi'
     'ficate to be updated (defaulting to -cert) or to be revoked in rr;\n   '
     '                     also used as reference (defaulting to -cert) for s'
     'ubject DN and SANs.\n                        Issuer is used as recipien'
     't unless -recipient, -srvcert, or -issuer given\n -issuer val          '
     '  DN of the issuer to place in the certificate template of ir/cr/kur/rr'
     ';\n                        also used as recipient if neither -recipient'
     ' nor -srvcert are given\n -serial val            Serial number of certi'
     'ficate to be revoked in revocation request (rr)\n -revreason int       '
     '  Reason code to include in revocation request (rr); possible values:\n'
     '                        0..6, 8..10 (see RFC5280, 5.3.1) or -1. Default'
     ' -1 = none included\n\nMessage transfer options:\n -server val         '
     '   [http[s]://]address[:port][/path] of CMP server. Default port 80 or '
     '443.\n                        address may be a DNS name or an IP addres'
     's; path can be overridden by -path\n -proxy val             [http[s]://'
     ']address[:port][/path] of HTTP(S) proxy to use; path is ignored\n -no_p'
     'roxy val          List of addresses of servers not to use HTTP(S) proxy'
     " for\n                        Default from environment variable 'no_pro"
     "xy', else 'NO_PROXY', else none\n -recipient val         DN of CA. Defa"
     'ult: subject of -srvcert, -issuer, issuer of -oldcert or -cert\n -path '
     'val              HTTP path (aka CMP alias) at the CMP server. Default f'
     'rom -server, else "/"\n -keep_alive nonneg     Persistent HTTP connecti'
     'ons. 0: no, 1 (the default): request, 2: require\n -msg_timeout nonneg '
     '   Number of seconds allowed per CMP message round trip, or 0 for infin'
     'ite\n -total_timeout nonneg  Overall time an enrollment incl. polling m'
     'ay take. Default 0 = infinite\n\nServer authentication options:\n -trus'
     'ted val           Certificates to use as trust anchors when verifying s'
     'igned CMP responses\n                        unless -srvcert is given\n'
     ' -untrusted val         Intermediate CA certs for chain construction fo'
     'r CMP/TLS/enrolled certs\n -srvcert val           Server cert to pin an'
     'd trust directly when verifying signed CMP responses\n -expect_sender v'
     'al     DN of expected sender of responses. Defaults to subject of -srvc'
     'ert, if any\n -ignore_keyusage       Ignore CMP signer cert key usage, '
     "else 'digitalSignature' must be allowed\n -unprotected_errors    Accept"
     ' missing or invalid protection of regular error messages and negative\n'
     '                        certificate responses (ip/cp/kup), revocation r'
     'esponses (rp), and PKIConf\n                        WARNING: This setti'
     'ng leads to behavior allowing violation of RFC 9810\n -no_cache_extrace'
     'rts   Do not keep certificates received in the extraCerts CMP message f'
     'ield\n -srvcertout val        File to save the server cert used and val'
     'idated for CMP response protection\n -extracertsout val     File to sav'
     'e extra certificates received in the extraCerts field\n -cacertsout val'
     '        File to save CA certs received in caPubs field or genp with id-'
     'it-caCerts\n -oldwithold val        Root CA certificate to request upda'
     'te for in genm of type rootCaCert\n -newwithnew val        File to save'
     ' NewWithNew cert received in genp of type rootCaKeyUpdate\n -newwithold'
     ' val        File to save NewWithOld cert received in genp of type rootC'
     'aKeyUpdate\n -oldwithnew val        File to save OldWithNew cert receiv'
     'ed in genp of type rootCaKeyUpdate\n -crlcert val           certificate'
     ' to request a CRL for in genm of type crlStatusList\n -oldcrl val      '
     '      CRL to request update for in genm of type crlStatusList\n -crlout'
     " val            File to save new CRL received in genp of type 'crls'\n"
     '\nClient authentication options:\n -ref val               Reference val'
     'ue to use as senderKID in case no -cert is given\n -secret val         '
     '   Prefer PBM (over signatures) for protecting msgs with given password'
     " source\n -cert val              Client's CMP signer certificate; its p"
     'ublic key must match the -key argument\n                        This al'
     'so used as default reference for subject DN and SANs.\n                '
     '        Any further certs included are appended to the untrusted certs'
     '\n -own_trusted val       Optional certs to verify chain building for o'
     'wn CMP signer cert\n -key val               CMP signer private key, not'
     ' used when -secret given\n -keypass val           Client private key (a'
     'nd cert and old cert) pass phrase source\n -digest val            Diges'
     't to use in message protection and POPO signatures. Default "sha256"\n '
     '-mac val               MAC algorithm to use in PBM-based message protec'
     'tion. Default "hmac-sha1"\n -extracerts val        Certificates to appe'
     'nd in extraCerts field of outgoing messages.\n                        T'
     'his can be used as the default CMP signer cert chain to include\n -unpr'
     'otected_requests  Send request messages without CMP-level protection\n'
     '\nCredentials format options:\n -certform val          Format (PEM or D'
     'ER) to use when saving a certificate to a file. Default PEM\n -crlform '
     'val           Format (PEM or DER) to use when saving a CRL to a file. D'
     'efault DER\n -keyform val           Format of the key input (ENGINE, ot'
     'her values ignored)\n -otherpass val         Pass phrase source potenti'
     'ally needed for loading certificates of others\n -engine val           '
     ' Use crypto engine with given identifier, possibly a hardware device.\n'
     '                        Engines may also be defined in OpenSSL config f'
     'ile engine section.\n\nProvider options:\n -provider-path val     Provi'
     "der load path (must be before 'provider' argument if required)\n -provi"
     'der val          Provider to load (can be specified multiple times)\n -'
     'provparam val         Set a provider key-value parameter\n -propquery v'
     'al         Property query used when fetching algorithms\n\nRandom state'
     ' options:\n -rand val              Load the given file(s) into the rand'
     'om number generator\n -writerand outfile     Write random data to the s'
     'pecified file\n\nTLS connection options:\n -tls_used              Enabl'
     'e using TLS (also when other TLS options are not set)\n -tls_cert val  '
     "        Client's TLS certificate. May include chain to be provided to T"
     "LS server\n -tls_key val           Private key for the client's TLS cer"
     "tificate\n -tls_keypass val       Pass phrase source for the client's p"
     'rivate TLS key (and TLS cert)\n -tls_extra val         Extra certificat'
     'es to provide to TLS server during TLS handshake\n -tls_trusted val    '
     '   Trusted certificates to use for verifying the TLS server certificate'
     ';\n                        this implies hostname validation\n -tls_host'
     ' val          Address to be checked (rather than -server) during TLS ho'
     'stname validation\n\nClient-side debugging options:\n -batch           '
     '      Do not interactively prompt for input when a password is required'
     ' etc.\n -repeat +int           Invoke the transaction the given positiv'
     'e number of times. Default 1\n -reqin val             Take sequence of '
     'CMP requests to send to server from file(s)\n -reqin_new_tid         Us'
     'e fresh transactionID for CMP requests read from -reqin\n -reqout val  '
     '          Save sequence of CMP requests created by the client to file(s'
     ')\n -reqout_only val       Save first CMP request created by the client'
     ' to file and exit\n -rspin val             Process sequence of CMP resp'
     'onses provided in file(s), skipping server\n -rspout val            Sav'
     'e sequence of actually used CMP responses to file(s)\n -use_mock_srv   '
     '       Use internal mock server at API level, bypassing socket-based HT'
     'TP\n\nMock server options:\n -port val              Act as HTTP-based m'
     'ock server listening on given port\n -max_msgs nonneg       max number '
     'of messages handled by HTTP mock server. Default: 0 = unlimited\n -srv_'
     'ref val           Reference value to use as senderKID of server in case'
     ' no -srv_cert is given\n -srv_secret val        Password source for ser'
     'ver authentication with a pre-shared key (secret)\n -srv_cert val      '
     '    Certificate of the server\n -srv_key val           Private key used'
     ' by the server for signing messages\n -srv_keypass val       Server pri'
     'vate key (and cert) pass phrase source\n -srv_trusted val       Trusted'
     ' certificates for client authentication\n -srv_untrusted val     Interm'
     'ediate certs that may be useful for verifying CMP protection\n -ref_cer'
     't val          Certificate to be expected for rr and any oldCertID in k'
     'ur messages\n -rsp_cert val          Certificate to be returned as mock'
     ' enrollment result\n -rsp_key val           Private key for the certifi'
     'cate to be returned as mock enrollment result\n                        '
     'Key to be returned for central key pair generation\n -rsp_keypass val  '
     '     Response private key (and cert) pass phrase source\n -rsp_crl val '
     '          CRL to be returned in genp of type crls\n -rsp_extracerts val'
     '    Extra certificates to be included in mock certification responses\n'
     ' -rsp_capubs val        CA certificates to be included in mock ip respo'
     'nse\n -rsp_newwithnew val    New root CA certificate to include in genp'
     ' of type rootCaKeyUpdate\n -rsp_newwithold val    NewWithOld transition'
     ' cert to include in genp of type rootCaKeyUpdate\n -rsp_oldwithnew val '
     '   OldWithNew transition cert to include in genp of type rootCaKeyUpdat'
     'e\n -poll_count nonneg     Number of times the client must poll before '
     'receiving a certificate\n -check_after nonneg    The check_after value '
     '(time to wait) to include in poll response\n -grant_implicitconf    Gra'
     'nt implicit confirmation of newly enrolled certificate\n -pkistatus non'
     'neg      PKIStatus to be included in server response. Possible values: '
     '0..6\n -failure nonneg        A single failure info bit number to inclu'
     'de in server response, 0..26\n -failurebits nonneg    Number representi'
     'ng failure bits to include in server response, 0..2^27 - 1\n -statusstr'
     'ing val      Status string to be included in server response\n -send_er'
     'ror            Force server to reply with error message\n -send_unprote'
     'cted      Send response messages without CMP-level protection\n -send_u'
     'nprot_err       In case of negative responses, server shall send unprot'
     'ected error messages,\n                        certificate responses (i'
     'p/cp/kup), and revocation responses (rp).\n                        WARN'
     'ING: This setting leads to behavior violating RFC 9810\n -accept_unprot'
     'ected    Accept missing or invalid protection of requests\n -accept_unp'
     'rot_err     Accept unprotected error messages from client\n -accept_rav'
     'erified     Accept RAVERIFIED as proof-of-possession (POPO)\n\nValidati'
     'on options:\n -policy val            adds policy to the acceptable poli'
     'cy set\n -purpose val           certificate chain purpose\n -verify_nam'
     'e val       verification policy name\n -verify_depth int      chain dep'
     'th limit\n -auth_level int        chain authentication security level\n'
     ' -attime intmax         verification epoch time\n -verify_hostname val '
     '  expected peer hostname\n -verify_email val      expected peer email\n'
     ' -verify_ip val         expected peer IP address\n -ignore_critical    '
     '   permit unhandled critical extensions\n -issuer_checks         (depre'
     'cated)\n -crl_check             check leaf certificate revocation\n -cr'
     'l_check_all         check full chain revocation\n -policy_check        '
     '  perform rfc5280 policy checks\n -explicit_policy       set policy var'
     'iable require-explicit-policy\n -inhibit_any           set policy varia'
     'ble inhibit-any-policy\n -inhibit_map           set policy variable inh'
     'ibit-policy-mapping\n -x509_strict           disable certificate compat'
     'ibility work-arounds\n -extended_crl          enable extended CRL featu'
     'res\n -use_deltas            use delta CRLs\n -policy_print          pr'
     'int policy processing diagnostics\n -check_ss_sig          check root C'
     'A self-signatures\n -trusted_first         search trust store first (de'
     'fault)\n -suiteB_128_only       Suite B 128-bit-only mode\n -suiteB_128'
     '            Suite B 128-bit mode allowing 192-bit algorithms\n -suiteB_'
     '192            Suite B 192-bit-only mode\n -partial_chain         accep'
     't chains anchored by intermediate trust-store CAs\n -no_alt_chains     '
     '    (deprecated)\n -no_check_time         ignore certificate validity t'
     'ime\n -allow_proxy_certs     allow the use of proxy certificates\n'),
    "cms": (1,
     '',
     'No operation option (-encrypt|-decrypt|-sign|-verify|...) specified.\nc'
     'ms: Use -help for summary.\n'),
    "crl": (1,
     '',
     'Could not find CRL from <stdin>\n'),
    "crl2pkcs7": (1,
     '',
     'unable to load CRL\n8047B904A07A0000:error:0480006C:PEM routines:get_na'
     'me:no start line:../crypto/pem/pem_lib.c:792:Expecting: X509 CRL\n'),
    "dhparam": (1,
     '',
     'Error, unable to load parameters\n8017310AB07E0000:error:1E08010C:DECOD'
     'ER routines:OSSL_DECODER_from_bio:unsupported:../crypto/encode_decode/d'
     'ecoder_lib.c:104:No supported data to decode. Input type: PEM\n'),
    "dsa": (1,
     '',
     'read DSA key\nCould not find private key from <stdin>\nunable to load Key\n'),
    "dsaparam": (1,
     '',
     'Could not find key parameters of DSA parameters from <stdin>\n'),
    "ec": (1,
     '',
     'read EC key\nCould not find private key from <stdin>\nunable to load Key\n'),
    "ecparam": (1,
     '',
     'Unable to load parameters from <NULL>\n'),
    "engine": (0,
     '(dynamic) Dynamic engine loading support\n',
     ''),
    "fipsinstall": (1,
     '',
     'fipsinstall: Use -help for summary.\n'),
    "gendsa": (1,
     '',
     'gendsa: Missing argument: params file\ngendsa: Use -help for summary.\n'),
    "genpkey": (1,
     '',
     'genpkey: Use -help for summary.\n'),
    "info": (1,
     '',
     'info: No items chosen\ninfo: Use -help for summary.\n'),
    "kdf": (1,
     '',
     'kdf: Use -help for summary.\n'),
    "mac": (1,
     '',
     'mac: Missing argument: MAC name\nmac: Use -help for summary.\n'),
    "nseq": (1,
     '',
     'nseq: Error reading sequence file <NULL>\n80F7820277720000:error:048000'
     '6C:PEM routines:get_name:no start line:../crypto/pem/pem_lib.c:792:Expe'
     'cting: CERTIFICATE\n'),
    "ocsp": (1,
     '',
     'ocsp: Use -help for summary.\n'),
    "pkcs12": (1,
     '',
     '80E720F587760000:error:0680008E:asn1 encoding routines:asn1_d2i_read_bi'
     'o:not enough data:../crypto/asn1/a_d2i_fp.c:142:\n'),
    "pkcs7": (1,
     '',
     'unable to load PKCS7 object\n80B78D43F6700000:error:0480006C:PEM routin'
     'es:get_name:no start line:../crypto/pem/pem_lib.c:792:Expecting: PKCS7\n'),
    "pkcs8": (1,
     '',
     'Error reading key\n80E769E3E2770000:error:0480006C:PEM routines:get_nam'
     'e:no start line:../crypto/pem/pem_lib.c:792:Expecting: ENCRYPTED PRIVAT'
     'E KEY\n'),
    "pkey": (1,
     '',
     'Could not find private key of key from <stdin>\n'),
    "pkeyparam": (1,
     '',
     'Error reading parameters\n801730349E750000:error:1E08010C:DECODER routi'
     'nes:OSSL_DECODER_from_bio:unsupported:../crypto/encode_decode/decoder_l'
     'ib.c:104:No supported data to decode. Input type: PEM\n'),
    "pkeyutl": (1,
     '',
     'pkeyutl: no private key given (-inkey parameter).\npkeyutl: Use -help f'
     'or summary.\n'),
    "rehash": (0,
     '',
     ''),
    "req": (1,
     '',
     '80673852937C0000:error:0680008E:asn1 encoding routines:asn1_d2i_read_bi'
     'o:not enough data:../crypto/asn1/a_d2i_fp.c:142:\nerror: unable to load'
     " X509 request from file '<NULL>'\n"),
    "rsa": (1,
     '',
     'Could not find private key from <stdin>\n'),
    "rsautl": (1,
     '',
     "The command rsautl was deprecated in version 3.0. Use 'pkeyutl' instead"
     '.\nNo filename or uri specified for loading\n private key\n'),
    "s_server": (1,
     '',
     'Could not open file or uri for loading server certificate private key f'
     'rom server.pem: No such file or directory\n'),
    "s_time": (1,
     'Collecting connection statistics for 30 seconds\n',
     'ERROR\n80670874DE780000:error:8000006F:system library:BIO_connect:Conne'
     'ction refused:../crypto/bio/bio_sock2.c:183:calling connect()\n80670874'
     'DE780000:error:10000067:BIO routines:BIO_connect:connect error:../crypt'
     'o/bio/bio_sock2.c:185:\n80670874DE780000:error:8000006F:system library:'
     'conn_state:Connection refused:../crypto/bio/bss_conn.c:215:calling conn'
     'ect(localhost, 4433)\n80670874DE780000:error:10000067:BIO routines:conn'
     '_state:connect error:../crypto/bio/bss_conn.c:259:\n'),
    "sess_id": (1,
     '',
     'unable to load SSL_SESSION\n80A7312FA3770000:error:0480006C:PEM routine'
     's:get_name:no start line:../crypto/pem/pem_lib.c:792:Expecting: SSL SES'
     'SION PARAMETERS\n'),
    "skeyutl": (1,
     '',
     'Either -skeymgmt -or -cipher option should be specified\n'),
    "smime": (0,
     '',
     'No operation (-encrypt|-sign|...) specified\nsmime: Use -help for summa'
     'ry.\n'),
    "spkac": (1,
     '',
     'Can\'t find SPKAC called "SPKAC"\n80A717F7AC780000:error:0700006C:confi'
     'guration file routines:NCONF_get_string:no value:../crypto/conf/conf_li'
     'b.c:316:group=default name=SPKAC\n'),
    "srp": (1,
     '',
     'Exactly one of the options -add, -delete, -modify -list must be specifi'
     'ed.\nsrp: Use -help for summary.\n'),
    "storeutl": (1,
     '',
     'storeutl: Missing argument: URI\nstoreutl: Use -help for summary.\n'),
    "ts": (1,
     '',
     'ts: Must give one of -query, -reply, or -verify\nts: Use -help for summ'
     'ary.\n'),
    "verify": (2,
     '',
     'Could not find certificate file from <stdin>\n'),
    "x509": (1,
     '',
     'Could not find certificate from <stdin>\n'),
}


# --- Otras piezas sueltas ---------------------------------------------------

# Lo que contesta "openssl ciphers" sin argumentos. Es una lista fija que
# depende de la version compilada, no del sistema, asi que va copiada tal cual.
CIPHERS_POR_DEFECTO = (
    "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_"
    "SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-"
    "RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-"
    "POLY1305:DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-"
    "RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-"
    "SHA384:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA256:ECDHE-ECDSA-AES128-"
    "SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-"
    "SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:"
    "ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA:RSA-PSK-AES256-GCM-SHA384:DHE-"
    "PSK-AES256-GCM-SHA384:RSA-PSK-CHACHA20-POLY1305:DHE-PSK-CHACHA20-"
    "POLY1305:ECDHE-PSK-CHACHA20-POLY1305:AES256-GCM-SHA384:PSK-AES256-GCM-"
    "SHA384:PSK-CHACHA20-POLY1305:RSA-PSK-AES128-GCM-SHA256:DHE-PSK-AES128-"
    "GCM-SHA256:AES128-GCM-SHA256:PSK-AES128-GCM-SHA256:AES256-SHA256:AES128-"
    "SHA256:ECDHE-PSK-AES256-CBC-SHA384:ECDHE-PSK-AES256-CBC-SHA:SRP-RSA-AES-"
    "256-CBC-SHA:SRP-AES-256-CBC-SHA:RSA-PSK-AES256-CBC-SHA384:DHE-PSK-"
    "AES256-CBC-SHA384:RSA-PSK-AES256-CBC-SHA:DHE-PSK-AES256-CBC-SHA:AES256-"
    "SHA:PSK-AES256-CBC-SHA384:PSK-AES256-CBC-SHA:ECDHE-PSK-AES128-CBC-"
    "SHA256:ECDHE-PSK-AES128-CBC-SHA:SRP-RSA-AES-128-CBC-SHA:SRP-AES-128-CBC-"
    "SHA:RSA-PSK-AES128-CBC-SHA256:DHE-PSK-AES128-CBC-SHA256:RSA-PSK-AES128-"
    "CBC-SHA:DHE-PSK-AES128-CBC-SHA:AES128-SHA:PSK-AES128-CBC-SHA256:PSK-"
    "AES128-CBC-SHA"
)

# Los dos listados de "openssl list" NO son los de "help": el de resumenes se
# deja fuera md4, y el de cifrados se deja fuera base64, los bf-*, los cast-*,
# los des sueltos, desx, los rc2/rc4, los seed-* y zlib/zstd. Son los que el
# proveedor por defecto tiene cargados, no los que el binario sabe nombrar.
# Medidos aparte, uno por uno; derivarlos de la lista de "help" daba mal.
LISTA_DIGESTS = [
    "blake2b512", "blake2s256", "md5", "rmd160",
    "sha1", "sha224", "sha256", "sha3-224",
    "sha3-256", "sha3-384", "sha3-512", "sha384",
    "sha512", "sha512-224", "sha512-256", "shake128",
    "shake256", "sm3",
]

LISTA_CIFRADOS = [
    "aes-128-cbc", "aes-128-ecb", "aes-192-cbc", "aes-192-ecb",
    "aes-256-cbc", "aes-256-ecb", "aria-128-cbc", "aria-128-cfb",
    "aria-128-cfb1", "aria-128-cfb8", "aria-128-ctr", "aria-128-ecb",
    "aria-128-ofb", "aria-192-cbc", "aria-192-cfb", "aria-192-cfb1",
    "aria-192-cfb8", "aria-192-ctr", "aria-192-ecb", "aria-192-ofb",
    "aria-256-cbc", "aria-256-cfb", "aria-256-cfb1", "aria-256-cfb8",
    "aria-256-ctr", "aria-256-ecb", "aria-256-ofb", "camellia-128-cbc",
    "camellia-128-ecb", "camellia-192-cbc", "camellia-192-ecb", "camellia-256-cbc",
    "camellia-256-ecb", "des-ede", "des-ede-cbc", "des-ede-cfb",
    "des-ede-ofb", "des-ede3", "des-ede3-cbc", "des-ede3-cfb",
    "des-ede3-ofb", "des3", "sm4-cbc", "sm4-cfb",
    "sm4-ctr", "sm4-ecb", "sm4-ofb",
]


# La linea que openssl anade cuando el proveedor no sabe servir un algoritmo.
FALLO_FETCH = ("%s:error:0308010C:digital envelope routines:"
               "inner_evp_generic_fetch:unsupported:../crypto/evp/"
               "evp_fetch.c:376:Global default library context, "
               "Algorithm (%s), Properties (%s)\n")

# El numero interno con el que openssl nombra cada algoritmo en ese mensaje.
NUMERO_ALGORITMO = {"md4": 98}

# Hasta donde se genera una clave sin bloquear el reactor. Ver _genrsa.
TOPE_RSA = 4096


def etiqueta_error():
    """El numero largo con el que openssl 3 encabeza cada linea de error.

    Es un identificador por hilo y por error, distinto en cada ejecucion.
    Muestras reales: 809772205D790000, 80F75332D9770000, 801726B4F57D0000.
    Siempre empieza por 80 y acaba en 0000; lo de en medio cambia. Fijarlo
    seria un delator: dos errores seguidos saldrian con el mismo numero.
    """
    medio = "".join(random.choice("0123456789ABCDEF") for _ in range(10))
    return "80%s0000" % medio


class Command_openssl(HoneyPotCommand):
    """openssl. Lo que no se emula, no se inventa: ver el final del fichero."""

    def _etiqueta(self):
        """La etiqueta es una por EJECUCION, no una por linea.

        Las dos o tres lineas que suelta un mismo error llevan todas el mismo
        numero; si cada linea trajera el suyo, un error de dos lineas se
        delataria solo.
        """
        if getattr(self, "_tag", None) is None:
            self._tag = etiqueta_error()
        return self._tag

    def _error(self, texto):
        self.errorWrite(texto)
        self.exit_code = 1

    def _uso(self, sub, opcion):
        self._error("%s: Unknown option: %s\n%s: Use -help for summary.\n"
                    % (sub, opcion, sub))

    # --- entrada ------------------------------------------------------------
    def _entrada(self, opciones):
        """Los bytes sobre los que trabajar: -in fichero, o lo que venga por
        la tuberia. Sin ninguna de las dos cosas openssl leeria del terminal;
        aqui eso es una sesion colgada, asi que se toma como fin de fichero,
        que es lo que ve un bot que no escribe nada."""
        ruta = opciones.get("-in")
        if ruta is not None:
            entera = self.fs.resolve_path(ruta, self.protocol.cwd)
            try:
                return self.fs.file_contents(entera)
            except Exception:                                  # noqa: BLE001
                self._error(
                    'Can\'t open "%s" for reading, No such file or directory\n'
                    "%s:error:80000002:system library:BIO_new_file:No such "
                    "file or directory:../crypto/bio/bss_file.c:67:calling "
                    "fopen(%s, rb)\n"
                    "%s:error:10000080:BIO routines:BIO_new_file:no such "
                    "file:../crypto/bio/bss_file.c:75:\n"
                    % (ruta, self._etiqueta(), ruta, self._etiqueta()))
                return None
        return self.input_data or b""

    # --- version ------------------------------------------------------------
    def _datos_version(self):
        """La version sale SIEMPRE de la tabla de dpkg, aunque el resto de
        lineas vengan del fichero exportado o de las constantes: es el unico
        dato que otra pieza del senuelo tambien publica."""
        version = VERSION_POR_DEFECTO
        try:
            from cowrie.commands.dpkg import datos_de, leer_paquetes
            version, _arch = datos_de(leer_paquetes(), "openssl",
                                      por_defecto=(VERSION_POR_DEFECTO,
                                                   "amd64"))
        except Exception:                                      # noqa: BLE001
            pass
        upstream = version.split(":")[-1].split("-")[0]

        fecha, construido = FECHA_POR_DEFECTO, CONSTRUIDO_POR_DEFECTO
        try:
            with open(RUTA_VERSION, encoding="utf-8", errors="replace") as f:
                lineas = f.read().split("\n")
            for linea in lineas:
                if linea.startswith("OpenSSL ") and " (Library:" in linea:
                    partes = linea.split(" ", 2)
                    fecha = partes[2].split(" (Library:")[0]
                elif linea.startswith("built on: "):
                    construido = linea[len("built on: "):]
        except Exception:                                      # noqa: BLE001
            pass
        return upstream, fecha, construido

    def _version(self, args):
        upstream, fecha, construido = self._datos_version()
        cabecera = ("OpenSSL %s %s (Library: OpenSSL %s %s)"
                    % (upstream, fecha, upstream, fecha))
        piezas = {
            "-b": "built on: %s" % construido,
            "-p": "platform: debian-amd64",
            "-o": "options:  bn(64,64)",
            "-f": "compiler: %s" % (COMPILADOR % upstream),
            "-d": DIRECTORIOS[0],
            "-e": DIRECTORIOS[1],
            "-m": DIRECTORIOS[2],
            "-r": "Seeding source: os-specific",
            "-c": "CPUINFO: %s" % CPUINFO,
        }
        if not args or args == ["-v"]:
            self.write(cabecera + "\n")
            return
        if "-a" in args:
            self.write("\n".join([cabecera] + [piezas[k] for k in
                                               ("-b", "-p", "-o", "-f")]
                                 + DIRECTORIOS
                                 + [piezas["-r"], piezas["-c"]]) + "\n")
            return
        salida = []
        for a in args:
            if a == "-v":
                salida.append(cabecera)
            elif a in piezas:
                salida.append(piezas[a])
            else:
                self._uso("version", a)
                return
        self.write("\n".join(salida) + "\n")

    # --- resumenes ----------------------------------------------------------
    def _dgst(self, alg, args):
        opciones, sueltos = {}, []
        i = 0
        while i < len(args):
            a = args[i]
            if a in ("-in", "-out"):
                if i + 1 >= len(args):
                    self._uso("dgst", a)
                    return
                opciones[a] = args[i + 1]
                i += 2
                continue
            if a.startswith("-"):
                nombre = a[1:]
                if nombre in NOMBRES_DIGEST or nombre in ("shake128",
                                                          "shake256", "md4"):
                    alg = nombre
                elif nombre in ("hex", "r"):
                    pass
                else:
                    # Aqui NO vale el mensaje de opcion desconocida de los
                    # demas: dgst dice "Unknown option or message digest" y
                    # nombra el algoritmo SIN el guion. Y suelta detras la
                    # linea del proveedor que no supo servirlo. Medido.
                    self._error("dgst: Unknown option or message digest: %s\n"
                                "dgst: Use -help for summary.\n" % nombre
                                + FALLO_FETCH % (self._etiqueta(),
                                                 "%s : 0" % nombre, "<null>"))
                    return
            else:
                sueltos.append(a)
            i += 1

        # shake128 y shake256 fallan mudos: rc 1 y ni una letra por ninguna de
        # las dos salidas. Medido, por raro que parezca.
        if alg in ("shake128", "shake256"):
            self.exit_code = 1
            return
        # Sin "-alg", dgst usa sha256 pero lo anuncia "SHA256", no "SHA2-256".
        real = alg or "sha256"
        etiqueta = NOMBRES_DIGEST.get(alg, "SHA256")

        # Un openssl de Debian tampoco los tiene todos: md4 esta compilado
        # pero el proveedor legacy no se carga, asi que falla al pedirlo. Un
        # algoritmo que le falte a hashlib acaba dando exactamente esto.
        if alg == "md4" or resume(real, b"") is None:
            self._error("Error setting digest\n"
                        + FALLO_FETCH % (self._etiqueta(),
                                         "%s : %d"
                                         % (real.upper(),
                                            NUMERO_ALGORITMO.get(real, 0)), "")
                        + "%s:error:03000086:digital envelope routines:"
                        "evp_md_init_internal:initialization error:"
                        "../crypto/evp/digest.c:271:\n" % self._etiqueta())
            return

        if sueltos:
            for nombre in sueltos:
                ruta = self.fs.resolve_path(nombre, self.protocol.cwd)
                try:
                    datos = self.fs.file_contents(ruta)
                except Exception:                              # noqa: BLE001
                    self._error(
                        "%s: No such file or directory\n"
                        "%s:error:80000002:system library:file_ctrl:No such "
                        "file or directory:../crypto/bio/bss_file.c:299:"
                        "calling fopen(%s, r)\n"
                        "%s:error:10080002:BIO routines:file_ctrl:system lib:"
                        "../crypto/bio/bss_file.c:302:\n"
                        % (nombre, self._etiqueta(), nombre,
                           self._etiqueta()))
                    continue
                self.write("%s(%s)= %s\n"
                           % (etiqueta, nombre, resume(real, datos)))
            return
        datos = self._entrada(opciones)
        if datos is None:
            return
        self.write("%s(stdin)= %s\n" % (etiqueta, resume(real, datos)))

    # --- enc / base64 -------------------------------------------------------
    def _enc(self, cifrado, args):
        opciones, descifra, una_linea, base64_ = {}, False, False, False
        i = 0
        while i < len(args):
            a = args[i]
            if a in ("-in", "-out", "-k", "-kfile", "-pass", "-K", "-iv",
                     "-S", "-md", "-iter"):
                if i + 1 >= len(args):
                    self._uso("enc", a)
                    return
                opciones[a] = args[i + 1]
                i += 2
                continue
            if a == "-d":
                descifra = True
            elif a == "-A":
                una_linea = True
            elif a in ("-a", "-base64"):
                base64_ = True
            elif a in ("-e", "-p", "-P", "-nopad", "-salt", "-nosalt",
                       "-pbkdf2", "-none"):
                pass
            elif a.startswith("-") and a[1:] in CIFRADOS:
                cifrado = a[1:]
            elif a.startswith("-"):
                self._uso("enc", a)
                return
            i += 1

        datos = self._entrada(opciones)
        if datos is None:
            return

        # Un cifrado de verdad no se puede hacer aqui: la biblioteca estandar
        # de Python no trae AES y no vamos a meter una dependencia en Cowrie
        # por esto. Lo que si se hace es FALLAR como falla el openssl real,
        # que es lo que ve cualquiera cuya clave no sirve.
        if cifrado not in (None, "base64"):
            if descifra:
                self._error("bad decrypt\n" if datos[:8] == b"Salted__"
                            else "bad magic number\n")
                if datos[:8] == b"Salted__":
                    self.errorWrite(
                        "%s:error:1C800064:Provider routines:"
                        "ossl_cipher_unpadblock:bad decrypt:../providers/"
                        "implementations/ciphers/ciphercommon_block.c:107:\n"
                        % self._etiqueta())
                return
            if "-pbkdf2" not in args and "-iter" not in opciones:
                self.errorWrite("*** WARNING : deprecated key derivation "
                                "used.\nUsing -iter or -pbkdf2 would be "
                                "better.\n")
            self.writeBytes(b"Salted__" + os.urandom(8)
                            + os.urandom(((len(datos) // 16) + 1) * 16))
            return

        if not base64_ and cifrado != "base64":
            return
        if descifra:
            # openssl NO descifra la ultima linea si no acaba en salto. Con
            # una sola linea sin salto la salida es vacia entera, no parcial.
            # Medido con una linea y con dos.
            if not datos.endswith(b"\n"):
                return
            limpio = b"".join(datos.split())
            try:
                self.writeBytes(base64.b64decode(limpio + b"=" *
                                                 (-len(limpio) % 4)))
            except Exception:                                  # noqa: BLE001
                pass
            return
        texto = base64.b64encode(datos).decode()
        if una_linea:
            self.write(texto)
            return
        self.write("".join(texto[i:i + 64] + "\n"
                           for i in range(0, len(texto), 64)) or "\n")

    # --- rand ---------------------------------------------------------------
    def _rand(self, args):
        formato, cuantos = None, None
        for a in args:
            if a in ("-hex", "-base64"):
                formato = a
            elif a.startswith("-") and not a[1:].isdigit():
                self._uso("rand", a)
                return
            elif a.startswith("-"):
                self._uso("rand", a)
                return
            elif a.isdigit():
                cuantos = int(a)
        # Sin numero no protesta: saca cero bytes y sale con bien. Pero un
        # numero que SEA cero (o negativo) si es un error. Medido las dos.
        if cuantos is not None and cuantos <= 0:
            self._error("rand: Use -help for summary.\n")
            return
        crudo = os.urandom(cuantos or 0)
        if formato == "-hex":
            self.write(crudo.hex() + "\n")
        elif formato == "-base64":
            self.write(base64.b64encode(crudo).decode() + "\n")
        else:
            self.writeBytes(crudo)

    # --- passwd -------------------------------------------------------------
    def _passwd(self, args):
        modo, sal, claves = "-1", None, []
        i = 0
        while i < len(args):
            a = args[i]
            if a == "-salt":
                if i + 1 >= len(args):
                    self._uso("passwd", a)
                    return
                sal = args[i + 1]
                i += 2
                continue
            if a in ("-1", "-5", "-6", "-apr1", "-aixmd5"):
                modo = a
            elif a in ("-noverify", "-quiet", "-table", "-reverse", "-stdin"):
                pass
            elif a.startswith("-"):
                self._uso("passwd", a)
                return
            else:
                claves.append(a)
            i += 1
        if not claves:
            # Sin contrasena openssl la PIDE por el terminal. Aqui no hay a
            # quien preguntar sin colgar la sesion, asi que se corta como si
            # no hubiera nada que leer.
            self._error("Password: \n")
            return
        for clave in claves:
            if modo in ("-5", "-6") and not clave:
                # Medido: con la contrasena vacia estos dos contestan <NULL>,
                # mientras que -1 y -apr1 si la calculan.
                self.write("<NULL>\n")
                continue
            usada = (sal if sal is not None
                     else sal_aleatoria(8 if modo in ("-1", "-apr1") else 16))
            if modo == "-1":
                self.write(_md5crypt(clave.encode(), usada.encode()) + "\n")
            elif modo == "-apr1":
                self.write(_md5crypt(clave.encode(), usada.encode(),
                                     b"$apr1$") + "\n")
            elif modo == "-5":
                self.write(_shacrypt(clave.encode(), usada.encode(), 256)
                           + "\n")
            else:
                self.write(_shacrypt(clave.encode(), usada.encode(), 512)
                           + "\n")

    # --- sueltos ------------------------------------------------------------
    def _prime(self, args):
        numeros = [a for a in args if not a.startswith("-")]
        if not numeros:
            self._error("Missing number (s) to check\n"
                        "prime: Use -help for summary.\n")
            return
        for n in numeros:
            try:
                valor = int(n, 0)
            except ValueError:
                self._error("Not a valid number: %s\n" % n)
                return
            self.write("%X (%d) is %sprime\n"
                       % (valor, valor, "" if es_primo(valor) else "not "))

    def _errstr(self, args):
        for codigo in args:
            try:
                valor = int(codigo, 16)
            except ValueError:
                self._error("Error code %s is not a valid number\n" % codigo)
                return
            # openssl 3 ya no guarda el nombre de la funcion: por eso el campo
            # de en medio sale vacio.
            self.write("error:%08X:lib(%d)::reason(%d)\n"
                       % (valor, (valor >> 23) & 0xFF, valor & 0x3FFFF))

    def _s_client(self, args):
        # No hay TLS aqui: emular un saludo y una cadena de certificados
        # obligaria a inventarse el certificado del sitio al que llama el
        # atacante, y eso si es un delator. Se contesta lo que contesta un
        # openssl cuyo destino no acepta la conexion, que es lo mismo que ve
        # cualquiera cuyo servidor esta caido.
        self._error(
            "%s:error:8000006F:system library:BIO_connect:Connection refused:"
            "../crypto/bio/bio_sock2.c:183:calling connect()\n"
            "%s:error:10000067:BIO routines:BIO_connect:connect error:"
            "../crypto/bio/bio_sock2.c:185:\nconnect:errno=111\n"
            % (self._etiqueta(), self._etiqueta()))

    def _speed(self, args):
        """El unico subcomando que se deja sin contestar, y a proposito.

        Un "openssl speed" de verdad tarda VEINTICINCO MINUTOS: recorre cada
        algoritmo por seis tamanos de bloque a tres segundos cada uno, y
        luego las firmas RSA, DSA y ECDSA a diez. Medido de reloj, no
        supuesto: se dejo correr y a los diez minutos aun iba por las DSA.

        Copiarlo pide una tabla de cientos de cifras que ademas describen el
        rendimiento del ordenador donde se midieron, o sea el mismo rastro
        del anfitrion que la linea CPUINFO. Y nadie ataca tecleando "speed".

        Asi que no se inventa nada: se sale sin decir nada. Esta escrito en
        el 3.4.2.8 del README como lo que es.
        """
        self.exit_code = 1

    def _genrsa(self, args):
        bits = 2048
        for a in args:
            if a in ("-out", "-passout", "-primes"):
                continue
            if a.startswith("-"):
                # genrsa tampoco usa el mensaje de siempre: dice "Unknown
                # option or cipher" porque el argumento suelto podria ser el
                # cifrado con el que proteger la clave. Medido.
                self._error("genrsa: Unknown option or cipher: %s\n" % a[1:]
                            + FALLO_FETCH % (self._etiqueta(),
                                             "%s : 0" % a[1:], "<null>"))
                return
            if a.isdigit():
                bits = int(a)
        if bits < 512:
            self._error("Error setting RSA length\n"
                        "%s:error:1C8000AB:Provider routines:"
                        "rsa_gen_set_params:key size too small:../providers/"
                        "implementations/keymgmt/rsa_kmgmt.c:509:\n"
                        % self._etiqueta())
            return
        if bits > TOPE_RSA:
            # De 4096 para arriba generar en Python puro pasa de decimas a
            # decenas de segundos, y esto corre en el mismo hilo que atiende
            # a TODAS las sesiones: colgarlo un minuto por un tamano que
            # nadie pide sale mas caro que no contestar. Escrito en
            # el 3.4.2.8 del README.
            self.exit_code = 1
            return
        self.write(clave_rsa(bits))

    def _list(self, args):
        if "-digest-commands" in args:
            self.write(columnas(LISTA_DIGESTS) + "\n")
        elif "-cipher-commands" in args:
            self.write(columnas(LISTA_CIFRADOS) + "\n")
        else:
            self._error("list: Use -help for summary.\n")

    # --- reparto ------------------------------------------------------------
    def call(self):
        args = list(self.args)
        # Sin argumentos, un openssl 3 ya NO abre el prompt "OpenSSL>" que
        # abrian las series 1.x: imprime la ayuda y sale. Comprobado con
        # pseudo-terminal, que es donde habria salido el prompt si existiera.
        if not args or args[0] == "help":
            # Por la salida de ERROR, no por la normal: "openssl help > f"
            # deja el fichero vacio y la ayuda en pantalla. Medido.
            self.errorWrite(texto_ayuda())
            return
        sub, resto = args[0], args[1:]

        if sub == "version":
            self._version(resto)
        elif sub == "dgst":
            self._dgst(None, resto)
        elif sub in DIGESTS:
            self._dgst(sub, resto)
        elif sub == "enc":
            self._enc(None, resto)
        elif sub == "base64":
            self._enc("base64", resto)
        elif sub in CIFRADOS:
            self._enc(sub, resto)
        elif sub == "rand":
            self._rand(resto)
        elif sub == "passwd":
            self._passwd(resto)
        elif sub == "prime":
            self._prime(resto)
        elif sub == "errstr":
            self._errstr(resto)
        elif sub == "ciphers":
            self.write(CIPHERS_POR_DEFECTO + "\n")
        elif sub == "list":
            self._list(resto)
        elif sub == "s_client":
            self._s_client(resto)
        elif sub == "genrsa":
            self._genrsa(resto)
        elif sub == "speed":
            self._speed(resto)
        elif sub in SIN_EMULAR:
            codigo, salida, error = SIN_EMULAR[sub]
            if salida:
                self.write(salida)
            if error:
                self.errorWrite(error)
            self.exit_code = codigo
        else:
            self.errorWrite("Invalid command '%s'; type \"help\" for a "
                            "list.\n" % sub)
            self.exit_code = 1


commands["openssl"] = Command_openssl
commands["/usr/bin/openssl"] = Command_openssl
