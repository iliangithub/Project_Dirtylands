#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
test_auditd_watch.py --- leer el log de auditd sin inventarse el formato.

    python3 "TELEGRAM SCRIPTS/tests/test_auditd_watch.py"

LA MUESTRA ES REAL. muestras/audit-real.log es salida literal de auditd 4.0.2
de la propia VPS, pegada tal cual: no esta escrita a mano a partir de la
documentacion. Importa, porque el formato tiene tres trampas que leyendo un
manual no se aciertan, y las tres se comprueban aqui:

  - Los campos interpretados se pegan al anterior SIN ESPACIO:
    `key="dirtyland-exec"ARCH=x86_64`.
  - Los argumentos vienen en HEXADECIMAL cuando llevan caracteres especiales.
  - Un evento son varias lineas unidas por su numero de serie, y NO tienen por
    que venir seguidas.
"""

from __future__ import annotations

import importlib.util
import io
import os
import sys

AQUI = os.path.dirname(os.path.abspath(__file__))
MUESTRA = os.path.join(AQUI, "muestras", "audit-real.log")

spec = importlib.util.spec_from_file_location(
    "vigilante", os.path.join(AQUI, "..", "auditd-watch.py"))
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)

OK = 0
MAL = 0


def comprueba(que, esperado, obtenido):
    global OK, MAL
    if esperado == obtenido:
        OK += 1
        print("  ok    %s" % que)
    else:
        MAL += 1
        print("  FALLO %s\n          esperaba <%s>\n          obtuvo   <%s>"
              % (que, esperado, obtenido))


# SIN LA MUESTRA NO HAY SUITE, y hasta ahora eso se veia de la peor forma
# posible: un traceback de FileNotFoundError. La lista del apartado 3.7.10
# ensena solo la ULTIMA linea de cada suite y manda el error a /dev/null, asi
# que de esta salia un hueco en blanco ---ni un "ok", ni un "fallos", nada--- y
# leyendo esa lista parecia un formato raro y no una suite muerta.
#
# Y la muestra no esta en el repositorio: la traga el "*.log" del .gitignore, o
# sea que nunca se llego a comitear. Se arregla poniendo el fichero (la regla
# del .gitignore ya tiene su excepcion), no escribiendo una muestra a mano:
# el valor de esta suite es que el formato lo dicta auditd de verdad y no lo
# que uno deduce del manual. Una muestra inventada la pondria verde sin probar
# nada, que es peor que tenerla roja.
if not os.path.isfile(MUESTRA):
    print()
    print("NO SE PUEDE PROBAR: falta la muestra que tiene que ir en")
    print("  %s" % MUESTRA)
    print("Es salida literal de auditd 4.0.2 de la VPS; se saca de alli con")
    print("  sudo tail -200 /var/log/audit/audit.log")
    print("y se guarda en esa ruta. No vale escribirla a mano: el formato tiene")
    print("tres trampas que solo trae la salida de verdad.")
    sys.exit(1)

lineas = io.open(MUESTRA, encoding="utf-8").readlines()
evs = v.eventos(lineas)
ordenes = [e["orden"] for e in evs]

print()
print("Contra una salida REAL de auditd")
comprueba("saca los seis programas ejecutados", 6, len(evs))
comprueba("y en el orden en que ocurrieron",
          ["wc -l", "python3 -c import os; os.system('whoami')",
           "sh -c -- whoami", "whoami",
           "sudo tail -60 /var/log/audit/audit.log",
           "tail -60 /var/log/audit/audit.log"],
          ordenes)

print()
print("Las tres trampas del formato")
# 1. Hexadecimal. Si no se descifra, el argumento sale como un churro de
#    digitos y justo lo que interesa leer ---que hizo el intruso--- es
#    ilegible.
comprueba("descifra los argumentos en hexadecimal", True,
          "import os; os.system('whoami')" in ordenes[1])
# 2. Campos pegados sin espacio: key="dirtyland-exec"ARCH=x86_64. Partiendo
#    por espacios, "exe" y "key" salen mal.
comprueba("no se traga los campos pegados sin espacio",
          "/usr/bin/python3.13", evs[1]["exe"])
comprueba("y la clave de la regla se lee entera",
          "dirtyland-exec", evs[0]["clave"])
# 3. Un evento son varias lineas, y en la muestra hay una de OTRO evento
#    (USER_END) intercalada entre medias.
comprueba("junta las lineas de un evento aunque vengan intercaladas",
          "/home/user", evs[0]["cwd"])

print()
print("Quien lo ejecuto, que es la mitad del valor")
# El auid es quien se AUTENTICO; el uid, como que usuario acabo corriendo. La
# diferencia entre los dos es exactamente lo que el registro del shell no veia:
# "user como root" es alguien que hizo sudo su.
comprueba("distingue quien se autentico", "user", evs[0]["quien"])
comprueba("de con que usuario acabo corriendo", "root", evs[0]["como"])
comprueba("y cuando no hay salto, los dos coinciden", ("user", "user"),
          (evs[1]["quien"], evs[1]["como"]))

texto = v.formatear(evs)
# LA CONVENCION DE TODA LA VIDA: $ tu usuario, # root. La primera version
# ponia una cabecera por cada cambio de usuario o terminal, y como un "sudo X"
# genera DOS eventos ---el sudo en tu terminal y la orden ya como root en
# otra--- el aviso salia con mas cabeceras que ordenes. Ilegible en un movil.
# LA MARCA VA FUERA DEL <code>: ese bloque esta para copiar y pegar la orden,
# y con el "#" dentro se copiaba tambien el "#".
comprueba("lo ejecutado como root se marca con #", True,
          "<b>#</b> <code>wc -l</code>" in texto)
comprueba("y el bloque de copiar lleva la orden y nada mas", 0,
          texto.count("<code>#") + texto.count("<code>$"))
# Ojo: el "whoami" de la muestra ya no sale suelto, y es correcto ---lo lanzo
# el python3 y queda plegado dentro de el---. Se mira una que si es raiz.
# Las DOS marcas, y las dos en negrita: una lista donde unas lineas empiezan
# con marca y otras no se lee peor que una donde todas empiezan igual.
comprueba("y lo del usuario con $", True,
          "<b>$</b> <code>sudo tail -60 /var/log/audit/audit.log</code>" in texto)
comprueba("las dos van en negrita", 3,
          texto.count("<b>$</b> <code>") + texto.count("<b>#</b> <code>"))
comprueba("con la leyenda, que si no las marcas no dicen nada", True,
          "<b>#</b> como root" in texto)
comprueba("y sin repetir una cabecera por linea", 0, texto.count("tty pts"))

print()
print("Quien avisa y de que maquina")
# Por el mismo chat llegan los avisos de los dos senuelos, y un aviso de
# ordenes ejecutadas se lee MUY distinto segun de donde venga: dentro de
# Cowrie es lo normal ---para eso esta--- y en el anfitrion es que hay alguien
# dentro de la maquina de verdad.
comprueba("el aviso dice que servicio lo manda", True,
          "[dirtyland-auditwatch]" in texto)
comprueba("y de que maquina habla", True, "Maquina VPS principal" in texto)
comprueba("y avisa de que NO son los senuelos", True,
          "NO son los senuelos" in texto)
comprueba("el encabezado va en negrita, que es lo que se ve sin abrir", True,
          texto.startswith("<b>["))

print()
print("Las tripas de una orden se pliegan, no se ensenan una a una")
#
# EL PROBLEMA REAL, con la salida del 2026-08-29: SEIS ordenes tecleadas
# salian como 32 lineas, porque auditd ensena cada execve y eso incluye lo que
# un programa lanza por dentro. Un solo "augenrules --load" son trece: el sh,
# un mktemp, un awk de doce lineas, un ls, un grep, cuatro cat, un cmp, un
# rm... El aviso era ilegible.
comprueba("las seis del ejemplo quedan en tres ordenes", 3, texto.count("<code>"))
comprueba("y se dice cuantos programas lanzo cada una", True, "(+2)" in texto)
# Y la leyenda del (+n) explicada, no insinuada: la primera version decia
# "programas que lanzo por dentro" y hubo que preguntar que significaba. Si
# hay que preguntar que dice una leyenda, la leyenda esta mal.
comprueba("con su leyenda, y explicada", True,
          "esa orden lanzo n programas mas por dentro" in texto)

def sintetico(filas):
    """filas = (marca, pid, ppid, uid, orden)"""
    lineas = []
    for i, (marca, pid, ppid, uid, orden) in enumerate(filas):
        lineas += ['type=SYSCALL msg=audit(%s:%d): ppid=%s pid=%s auid=1000 '
                   'uid=%s tty=pts2 ses=1 exe="/bin/x" '
                   'key="dirtyland-exec"ARCH=x86_64 AUID="user" UID="%s"\n'
                   % (marca, i, ppid, pid, uid, "root" if uid == "0" else "user"),
                   'type=EXECVE msg=audit(%s:%d): argc=1 a0="%s"\n' % (marca, i, orden),
                   'type=CWD msg=audit(%s:%d): cwd="/tmp"\n' % (marca, i)]
    return v.eventos(lineas)

# Por el arbol: los hijos inmediatos de una orden cuelgan de ella.
arbol = sintetico([("100.0", "901", "900", "1000", "sudo augenrules"),
                   ("100.01", "902", "901", "0", "sh /usr/sbin/augenrules"),
                   ("100.02", "903", "902", "0", "mktemp"),
                   ("100.03", "904", "902", "0", "awk")])
plegado = v.plegar(arbol)
comprueba("cuatro programas quedan en una orden", 1, len(plegado))
comprueba("con los otros tres contados dentro", 3, plegado[0]["dentro"])

# Y EL MATIZ QUE IMPORTA: el arbol solo no basta. Si se plegara todo
# descendiente, un "sudo su" se llevaria por delante TODO lo que se teclee
# luego en el shell de root, que es justo lo que mas interesa ver.
raiz = sintetico([("200.0", "910", "900", "1000", "sudo su"),
                  ("200.01", "911", "910", "0", "su"),
                  ("230.0", "912", "911", "0", "cat /etc/shadow")])
plegado = v.plegar(raiz)
comprueba("lo tecleado 30 s despues en el shell de root SI se ensena", 2,
          len(plegado))
comprueba("y es lo que se tecleo", "cat /etc/shadow", plegado[1]["orden"])

# El arbol tiene un hueco: sudo bifurca un proceso intermedio que no ejecuta
# nada, asi que es invisible aqui y el hijo aparece con un ppid desconocido.
# En la salida real, "sudo tail" tenia pid 432314 y el "tail" ppid 432316.
hueco = sintetico([("300.0", "920", "900", "1000", "sudo tail -60 /var/log/x"),
                   ("300.01", "922", "921", "0", "tail -60 /var/log/x")])
plegado = v.plegar(hueco)
comprueba("aun asi se reconoce por el texto", 1, len(plegado))
comprueba("y se deja la que se tecleo", True,
          plegado[0]["orden"].startswith("sudo "))

print()
print("Ni bucles ni secretos")
# EL 2026-08-29 EL TOKEN DEL BOT ACABO EN UN AVISO. send-alert.sh pasaba el
# token como argumento de curl, auditd registra los argumentos, y el aviso
# siguiente lo publicaba. Hubo que revocarlo.
#
# Ademas se citaba a si mismo: el aviso se manda con send-alert.sh, eso
# ejecuta curl con EL TEXTO DEL AVISO como argumento, y el siguiente lo metia
# dentro. Cada vuelta mas grande.
nuestro = []
for i, orden in enumerate(['bash /opt/dirtyland/monitor/send-alert.sh hola',
                           'curl -s https://api.telegram.org/bot1:x/sendMessage',
                           'logger -t dirtyland-cmd -p authpriv.notice -- cmd=ls']):
    nuestro += ['type=SYSCALL msg=audit(1.%d:%d): auid=1000 uid=1000 tty=pts0 '
                'ses=1 exe="/bin/x" key="dirtyland-exec"ARCH=x86_64\n' % (i, i),
                'type=EXECVE msg=audit(1.%d:%d): argc=1 a0="%s"\n' % (i, i, orden),
                'type=CWD msg=audit(1.%d:%d): cwd="/tmp"\n' % (i, i)]
comprueba("nuestro propio envio no se avisa", 0, len(v.eventos(nuestro)))

# Y la censura, como segunda linea: lo de arriba tapa lo que sabemos que lleva
# secretos, esto tapa lo que no. Un registro de ejecuciones recoge lo que
# alguien teclea, y ahi acaban claves tarde o temprano.
comprueba("un token de bot se tapa", "curl bot<CENSURADO>/x",
          v.censurar("curl bot1234567890:AAEejemploEjemploEjemploEjemplo-xyz/x"))
comprueba("una clave de API tambien", True,
          "<CENSURADO>" in v.censurar("prog --api_key=abcdef123456"))
comprueba("una cabecera de autorizacion", True,
          "<CENSURADO>" in v.censurar("curl -H 'Authorization: Bearer abc.def'"))
comprueba("y la contrasena pegada al -p de mysql", True,
          "<CENSURADO>" in v.censurar("mysql -uroot -psecreta123"))
# Lo que NO es un secreto no se toca: censurar de mas oculta lo que se venia a
# ver.
comprueba("un -p normal no se toca", "cp -p a b", v.censurar("cp -p a b"))
# CENSURAR DE MAS OCULTA LO QUE SE VENIA A VER. La primera version tapaba
# cualquier "-p" seguido de algo y se comia el "arts" de "run-parts": en un
# aviso real salio "run-p<CENSURADO> --list ...". Ahora el -p pegado solo se
# tapa en los clientes de base de datos, que es donde significa eso.
comprueba("y run-parts se queda entero",
          "run-parts --list --regex x /etc/profile.d",
          v.censurar("run-parts --list --regex x /etc/profile.d"))
comprueba("ni un tar -pxzf", "tar -pxzf x.tgz", v.censurar("tar -pxzf x.tgz"))

print()
print("Una orden de doce lineas no puede reventar el aviso")
# El guion de awk que lleva augenrules dentro ocupa doce lineas. Sin aplanar,
# el mensaje se vuelve un muro y no se distingue una orden de la siguiente.
comprueba("se aplana a una linea", "awk BEGIN { x = 1; }",
          v._una_linea("awk \nBEGIN {\n    x = 1;\n}"))
comprueba("y se recorta si sigue siendo larga", 41,
          len(v._una_linea("x" * 200, tope=40)))

print()
print("Lo que NO se ensena")
# unix_chkpwd lo lanza el PAM en cada sudo. No lo ha pedido nadie y sale
# siempre; dejarlo llenaria el aviso de ruido que no dice nada.
comprueba("el unix_chkpwd del PAM no sale", 0,
          len([o for o in ordenes if "unix_chkpwd" in o]))
# Un evento sin SYSCALL no dice quien ni desde donde, y sin EXECVE no tiene
# orden que ensenar. En la muestra hay uno de cada (el "id" cortado por el
# tail, y un USER_END).
comprueba("un evento incompleto se descarta en vez de salir a medias", 0,
          len([e for e in evs if not e.get("exe") or not e.get("orden")]))

print()
print("Un argumento partido en trozos")
# auditd parte los argumentos muy largos en aN[0], aN[1]... Sin juntarlos, una
# orden larga sale troceada y en desorden, que es peor que no verla: se lee
# mal y se saca la conclusion equivocada.
partido = ['type=SYSCALL msg=audit(1.1:9): auid=1000 uid=0 tty=pts0 ses=1 '
           'exe="/bin/sh" key="dirtyland-exec"ARCH=x86_64\n',
           'type=EXECVE msg=audit(1.1:9): argc=2 a0="sh" a1[0]=61 a1[1]=62 '
           'a1[2]=63\n',
           'type=CWD msg=audit(1.1:9): cwd="/tmp"\n']
comprueba("los trozos se juntan en orden", "sh abc",
          v.eventos(partido)[0]["orden"])

print()
print("Lo que escribe el atacante no puede romper el mensaje")
# El nombre del fichero y los argumentos los elige quien ataca. Un "<" suelto
# convierte el mensaje en un 400 de Telegram y se pierde el aviso entero.
malo = ['type=SYSCALL msg=audit(1.1:8): auid=1000 uid=0 tty=pts0 ses=1 '
        'exe="/bin/sh" key="dirtyland-exec"ARCH=x86_64\n',
        'type=EXECVE msg=audit(1.1:8): argc=2 a0="sh" a1="<b>&x</b>"\n',
        'type=CWD msg=audit(1.1:8): cwd="/tmp"\n']
salida = v.formatear(v.eventos(malo))
comprueba("se escapa el HTML de los argumentos", True,
          "&lt;b&gt;&amp;x&lt;/b&gt;" in salida)
comprueba("y no queda ninguna etiqueta suya suelta", 0,
          salida.count("<b>&x</b>"))

print()
print("Una rafaga no puede tumbar el aviso")
# Un solo "apt install" son cientos de execve. Un mensaje de cientos de lineas
# no se lee: se ignora. Y pasado el limite de Telegram, se pierde entero.
muchos = []
for i in range(200):
    muchos += ['type=SYSCALL msg=audit(1.%d:%d): auid=1000 uid=1000 tty=pts0 '
               'ses=1 exe="/bin/x" key="dirtyland-exec"ARCH=x86_64\n' % (i, i),
               'type=EXECVE msg=audit(1.%d:%d): argc=1 a0="orden%d"\n' % (i, i, i),
               'type=CWD msg=audit(1.%d:%d): cwd="/tmp"\n' % (i, i)]
evs_muchos = v.eventos(muchos)
salida = v.formatear(evs_muchos)
comprueba("se leen los 200", 200, len(evs_muchos))
comprueba("pero el aviso se recorta", v.MAX_LINEAS,
          salida.count("<code>"))
comprueba("diciendo cuantos faltan", True, "y 160 mas" in salida)
comprueba("y el total sale en la cabecera", True, "200 ordenes" in salida)

print()
print("Al reiniciarse NO se pierde lo de en medio")
#
# EL FALLO, visto el 2026-08-29: el vigilante saltaba al final del fichero al
# arrancar, asi que todo lo ocurrido mientras el servicio estuvo parado se
# perdia para siempre y sin dejar rastro. Se reinicio el servicio y las dos
# ordenes siguientes no llegaron nunca ---estaban en el registro, pero nadie
# las leyo---. Un vigilante que pierde lo que vigila justo cuando se le
# reinicia es peor que no tenerlo, porque uno cree que lo tiene.
import tempfile

def evento(n, orden):
    return ('type=SYSCALL msg=audit(1.%d:%d): ppid=1 pid=%d auid=1000 '
            'uid=1000 tty=pts0 ses=1 exe="/bin/x" '
            'key="dirtyland-exec"ARCH=x86_64 AUID="user" UID="user"\n'
            'type=EXECVE msg=audit(1.%d:%d): argc=1 a0="%s"\n'
            'type=CWD msg=audit(1.%d:%d): cwd="/tmp"\n'
            % (n, n, 100 + n, n, n, orden, n, n))

def vigilante(log, posicion):
    """Otra instancia del modulo, como si el servicio se reiniciara."""
    os.environ["AUDIT_LOG"] = log
    os.environ["AUDIT_POSICION"] = posicion
    sp = importlib.util.spec_from_file_location(
        "otra", os.path.join(AQUI, "..", "auditd-watch.py"))
    m = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(m)
    return m

tmp = tempfile.mkdtemp()
log = os.path.join(tmp, "audit.log")
posicion = os.path.join(tmp, "auditwatch.pos")
io.open(log, "w").write(evento(1, "antes de arrancar"))

v1 = vigilante(log, posicion)
g1 = v1.seguir(log)
for _ in range(4):
    next(g1)
# SE APUNTA YA, sin esperar a leer una linea: si no, un arranque en frio
# seguido de un reinicio vuelve a saltar al final y se pierde todo lo de en
# medio. O sea, el arreglo no arreglaba el primer reinicio, que es justo
# cuando paso.
comprueba("un arranque en frio ya deja apuntada la posicion", True,
          os.path.exists(posicion))
comprueba("y no reenvia el historico que ya habia", 0,
          len(v1.eventos([])))

with io.open(log, "a") as fh:
    fh.write(evento(2, "mientras estaba parado"))
    fh.write(evento(3, "y otra mas"))

v2 = vigilante(log, posicion)
g2 = v2.seguir(log)
recogidas = [x for x in (next(g2) for _ in range(12)) if x]
comprueba("tras reiniciar recupera lo de en medio",
          ["mientras estaba parado", "y otra mas"],
          [e["orden"] for e in v2.eventos(recogidas)])

# Si el fichero mengua es que lo han vaciado ---o rotado a uno nuevo---, y
# seguir desde el byte de antes se saltaria lo que haya ahora.
io.open(log, "w").write(evento(4, "despues de vaciarlo"))
v3 = vigilante(log, posicion)
g3 = v3.seguir(log)
recogidas = [x for x in (next(g3) for _ in range(8)) if x]
comprueba("y si lo vacian, no se salta lo nuevo",
          ["despues de vaciarlo"], [e["orden"] for e in v3.eventos(recogidas)])

import shutil
shutil.rmtree(tmp, ignore_errors=True)

print()
print("-------------------------------------")
print("ok: %d   fallos: %d" % (OK, MAL))
sys.exit(1 if MAL else 0)
