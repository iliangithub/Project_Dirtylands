#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
banco_shell_real.py
Pasa lineas por el SHELL DE VERDAD de Cowrie y compara con lo que hace bash.

    ./banco_shell_real.py            los casos de siempre
    ./banco_shell_real.py -v         ensena tambien los que salen bien

POR QUE EXISTE. Las pruebas de COMANDOS COWRIE/tests/ cargan cada modulo por
su cuenta con un sistema de ficheros fingido. Eso vale para comprobar lo que
IMPRIME un comando, y no vale para nada de lo que pasa ENTRE comandos: el
troceo de la linea, la redireccion, los parentesis, el directorio actual, la
expansion de variables. Todo eso vive en shell/honeypot.py y solo se ve con el
protocolo entero montado.

Durante meses eso se dio por imposible ---"no se pudo reproducir aqui", decia
el 3.4.2.8 del README--- y no lo era: la imagen cowrie/cowrie:3.0.10
que ya usa el despliegue trae dentro el paquete instalado y sus dos ayudantes
de prueba, fake_server y fake_transport. Con eso se instancia el protocolo de
verdad, con su fs.pickle, sin levantar ningun servicio ni tocar la VPS.

La primera vez que se ejecuto encontro cuatro cosas en un minuto, una de ellas
un fallo que impedia ARRANCAR al senuelo entero.

NO NECESITA RED: usa la imagen que ya esta descargada.
"""
from __future__ import annotations

import os
import subprocess
import sys

AQUI = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(AQUI)
PARCHES = os.path.join(REPO, "COWRIE FAKE ENVIRONMENT", "COMANDOS COWRIE")
IMAGEN = "cowrie/cowrie:3.0.10"

# LIMITES OBLIGATORIOS. Esto se ejecuta en un portatil ---un HP Victus con un
# i7-12700H y refrigeracion corta--- y sin limitar el contenedor la CPU se iba
# a 97 grados. No es un capricho de estilo: el banco se lanza muchas veces al
# dia.
#
#   --cpus=0.5          medio hilo. Sobra para lo unico que se hace aqui, que
#                       es ver si una orden se ejecuta o falla.
#   --cpuset-cpus=12-19 las CPU logicas 12 a 19 son los E-cores (3500 MHz):
#                       calientan mucho menos que los P-cores y dejan el
#                       escritorio libre.
#   --memory=512m       techo de memoria.
#   --rm                sin instancias paradas acumulandose.
LIMITES = ["--cpus=0.5", "--cpuset-cpus=12-19", "--memory=512m", "--rm"]

# Y POR TANDAS, por lo mismo. Con los 361 casos en un solo contenedor el
# proceso se pasa de los 512 MB y el nucleo lo mata: se ve como un rc=137 y
# una salida vacia, sin ningun error que lo explique. No es que se acumulen
# las sesiones ---probado a soltarlas y a llamar al recolector, y sigue---:
# es lo que ocupa montar el protocolo tantas veces. Cada tanda es un
# contenedor nuevo, asi que la memoria vuelve a cero.
POR_TANDA = 50

# (linea, lo que contesta un bash de verdad)
#
# Lo de la derecha NO esta escrito de memoria: sale de correr la misma linea
# con "bash -c" en un debian:trixie. Si se anade un caso, se mide primero.
CASOS = [
    ("echo hola", "hola"),

    # UNA TUBERIA PERDIA SU SALIDA si no era lo ultimo de la linea. protocol.pp
    # es una sola ranura y el comando siguiente la pisaba antes de vaciarla.
    ("echo a | cat", "a"),
    ("echo a | cat; echo b", "a\nb"),
    ("echo a | cat && echo b", "a\nb"),
    ("echo a | cat | cat; echo b", "a\nb"),
    ("echo a | cat; echo b; echo c", "a\nb\nc"),
    ("cat /etc/passwd | head -1; echo fin",
     "root:x:0:0:root:/root:/bin/bash\nfin"),
    ("echo hola | head -c 3; echo", "hol"),
    ("echo [test]", "[test]"),
    ("echo a[1]", "a[1]"),
    ("cd /root; (cd /tmp; pwd); pwd", "/tmp\n/root"),
    ("cd /root; (cd /tmp); pwd", "/root"),
    ("echo X > /tmp/f; (cat /tmp/f)", "X"),
    ("(echo dentro)", "dentro"),
    ("(false); echo rc=$?", "rc=1"),
    ("(noexiste); echo rc=$?", "-bash: noexiste: command not found\nrc=127"),
    ("echo uno && echo dos", "uno\ndos"),
    ("false || echo respaldo", "respaldo"),
    ("true && (echo si)", "si"),
    ('echo "cierra \\" dentro"', 'cierra " dentro'),
    ("echo hola # comentario", "hola"),
    ('echo "uno; dos"', "uno; dos"),

    # LA EXPANSION, QUE VA POR COMANDO Y NO POR LINEA. Antes del 2026-09-03
    # se expandia la linea entera antes de ejecutar nada, asi que una
    # asignacion no la veia lo que venia detras: de estos catorce fallaban
    # TRECE, incluido "cd $A", que es de lo mas tecleado que hay.
    ("A=uno; echo $A", "uno"),
    ("A=uno; echo fuera=$A", "fuera=uno"),
    ("A=uno; echo x${A}y", "xunoy"),
    ("A=uno; echo $A/sub", "uno/sub"),
    ("A=uno; echo [$A]", "[uno]"),
    ('A=uno; echo "$A"', "uno"),
    ("A=uno; B=dos; echo $A-$B", "uno-dos"),
    ("A=uno; A=dos; echo $A", "dos"),
    ("A=hola; echo $A | tr a-z A-Z", "HOLA"),
    ("A=/tmp; cd $A; pwd", "/tmp"),
    ("A=uno; (echo $A)", "uno"),
    ("A=uno; echo $A; echo $A", "uno\nuno"),
    ("A=1; B=$A; echo $B", "1"),
    ("echo $NOEXISTE", ""),
    ("echo $HOME/x", "/root/x"),
    ("echo uno; echo $?", "uno\n0"),

    # ARITMETICA. No estaba, y no fallaba callando: "$((" se parecia lo
    # bastante a "$(" como para que la sustitucion de ordenes se lo llevara y
    # acabara ejecutando "(2*3)" como si fuera un subshell.
    ("echo $((2*3))", "6"),
    ("echo $(( 1 + 1 ))", "2"),
    ("echo $(( (1+2)*3 ))", "9"),
    ("echo $((7/2))", "3"),
    ("echo $((-7/2))", "-3"),
    ("echo $((2**10))", "1024"),
    ("echo $((010))", "8"),
    ("echo $((0x10))", "16"),
    ("echo $((1<<4))", "16"),
    ("echo $((1>2))", "0"),
    ("echo $((1&&0))", "0"),
    ("echo $((NOEXISTE+1))", "1"),
    ("X=5; echo $((X*2))", "10"),
    ("A=3; B=$((A+1)); echo $B", "4"),
    ("echo pre$((1+1))post", "pre2post"),

    # BUCLES cuya lista sale de algo asignado en la MISMA linea.
    ('A="1 2"; for i in $A; do echo v$i; done', "v1\nv2"),
    ("N=3; for i in $(seq 1 $N); do echo i$i; done", "i1\ni2\ni3"),
    ("echo antes; for i in a b; do echo $i; done", "antes\na\nb"),
    # Y que no se parta lo que solo LO PARECE.
    ('echo "a; for b"', "a; for b"),
    # Y lo que va DETRAS del "done" tambien se ejecuta: las dos expresiones
    # pedian que la linea terminara ahi.
    ("for i in a b; do echo $i; done; echo fin", "a\nb\nfin"),
    ("A=1; while false; do echo x; done; echo fin", "fin"),
    ("while false; do echo x; done", ""),

    # ${VAR:-...} y compania. Solo se entendia "$VAR" y "${VAR}" a secas.
    ("echo ${NOEX:-def}", "def"),
    ("A=hola; echo ${A:-def}", "hola"),
    ("A=hola; echo ${A:+puesto}", "puesto"),
    ("echo ${NOEX:+puesto}", ""),
    ("A=hola; echo ${#A}", "4"),
    ("echo ${#NOEX}", "0"),
    ("F=a.tar.gz; echo ${F%.gz}", "a.tar"),
    ("F=a.tar.gz; echo ${F#a.}", "tar.gz"),
    # Y que la almohadilla DE VERDAD siga siendo un comentario.
    ("echo hola # comentario", "hola"),
    ('echo "a#b"', "a#b"),

    ("echo $0", "-bash"),

    # id ignoraba todas sus opciones: "id -u" es lo primero que teclea un
    # guion para saber si es root, y contestaba la linea entera.
    ("id -u", "0"),
    ("id -un", "root"),
    ("id -g", "0"),
    ("id -Gn", "root"),
    ("id noexiste", "id: 'noexiste': no such user"),
    # which escribia TODAS las coincidencias del PATH, no la primera.
    ("which sh", "/usr/bin/sh"),
    ("which -a sh", "/usr/bin/sh\n/bin/sh"),
    ("which noexiste; echo rc=$?", "rc=1"),

    # test y [ NO EVALUABAN NADA: devolvian 0 siempre, asi que cualquier
    # guion que preguntara algo tomaba siempre la rama del "si".
    ("[ -f /etc/passwd ]; echo rc=$?", "rc=0"),
    ("[ -f /noexiste ]; echo rc=$?", "rc=1"),
    ("[ -d /tmp ]; echo rc=$?", "rc=0"),
    ("[ a = a ]; echo rc=$?", "rc=0"),
    ("[ a != b ]; echo rc=$?", "rc=0"),
    ("[ 1 -lt 2 ]; echo rc=$?", "rc=0"),
    ("[ 2 -lt 1 ]; echo rc=$?", "rc=1"),
    ('[ -z "" ]; echo rc=$?', "rc=0"),
    ("[ ! -f /noexiste ]; echo rc=$?", "rc=0"),
    ("[ -f /noexiste -o -d /tmp ]; echo rc=$?", "rc=0"),

    # Y los CONDICIONALES, que caian al troceo como si "if" fuera un comando.
    ("if [ -f /etc/passwd ]; then echo si; fi", "si"),
    ("if [ ! -f /noexiste ]; then echo falta; fi", "falta"),
    ("if [ -d /noexiste ]; then echo dir; else echo nodir; fi", "nodir"),
    ("if false; then echo si; else echo no; fi", "no"),
    ("if false; then echo a; elif true; then echo b; fi", "b"),
    ("if true; then echo uno; echo dos; fi", "uno\ndos"),
    ("if [ -f /etc/passwd ]; then echo si; fi; echo fin", "si\nfin"),
    ("echo antes; if true; then echo si; fi", "antes\nsi"),
    ("if true; then if true; then echo anidado; fi; fi", "anidado"),
    ("if grep -q root /etc/passwd; then echo hay; fi", "hay"),
    ("if [ -f /noexiste ]; then echo si; fi", ""),

    # case/esac: es como un dropper detecta la arquitectura antes de bajarse
    # el binario que toca, y caia al troceo como si fuera un comando.
    ("case a in a) echo esA;; *) echo otro;; esac", "esA"),
    ("case z in a) echo esA;; *) echo otro;; esac", "otro"),
    ("case x86_64 in x86_64|amd64) echo intel;; arm*) echo arm;; esac",
     "intel"),
    ("case armv7l in x86_64|amd64) echo intel;; arm*) echo arm;; esac", "arm"),
    ("A=mips; case $A in mips*) echo esmips;; *) echo no;; esac", "esmips"),
    ("case foo.tar.gz in *.gz) echo comprimido;; esac", "comprimido"),
    ("case a in a) echo si;; esac; echo fin", "si\nfin"),
    ("case a in b) echo no;; esac", ""),

    # Seis que el sistema de ficheros DECLARA y no estaban emulados: no daban
    # "command not found" sino "No such file or directory", que es la
    # contradiccion peor.
    ("basename /a/b/c.txt", "c.txt"),
    ("basename /a/b/c.txt .txt", "c"),
    ("dirname /a/b/c.txt", "/a/b"),
    ("dirname c.txt", "."),
    ('printf "b\\na\\n" | sort', "a\nb"),
    ('printf "b\\na\\nb\\n" | sort -u', "a\nb"),
    ('printf "2\\n10\\n" | sort -n', "2\n10"),
    ("echo abc | rev", "cba"),
    ("echo uno dos | xargs echo", "uno dos"),
    ('printf "a\\nb\\n" | xargs -n1 echo', "a\nb"),
    # El recuento va alineado a la derecha en siete columnas. Aqui se espera
    # sin los blancos de delante de la PRIMERA linea porque este banco recorta
    # los extremos del bloque para poder quitar el prompt; los de la segunda
    # si se ven, que es lo que importa comprobar.
    ('printf "a\\na\\nb\\n" | uniq -c', "2 a\n      1 b"),
    ('printf "a\\na\\nb\\n" | uniq -d', "a"),

    # "set -e" volcaba las cincuenta y pico variables del entorno.
    ("set -e; echo a", "a"),
    ("set -x; echo a", "+ echo a\na"),

    # Un "&" suelto se colaba como una palabra mas: "echo b &" imprimia "b &".
    # El PID del aviso cambia, asi que aqui solo se comprueba lo que no.
    ("echo a & echo b", None),

    # ls sale con 2 cuando no puede acceder: sin eso un "ls /x || respaldo"
    # no lanzaba nunca el respaldo.
    ("ls /noexiste 2>/dev/null; echo rc=$?", "rc=2"),
    ("echo $(( $(echo 2) + 1 ))", "3"),

    # Funciones: el troceo veia "f()" como un comando y "}" como otro.
    ("f() { echo dentro; }; f", "dentro"),
    ("g() { echo $1; }; g hola", "hola"),
    ("h() { echo $#; }; h a b c", "3"),
    ("k() { echo $@; }; k x y", "x y"),
    ("f() { echo uno; echo dos; }; f", "uno\ndos"),
    ("f() { echo a; }; f; echo fin", "a\nfin"),

    # DE VARIAS LINEAS, que es como se escriben de verdad. Un heredoc no se
    # entendia: el "<<" se troceaba como una redireccion, contestaba
    # "-bash: <: No such file or directory" y despues EJECUTABA COMO ORDENES
    # cada linea del contenido.
    (["cat <<EOF", "linea uno", "linea dos", "EOF"], "linea uno\nlinea dos"),
    (["cat <<EOF > /tmp/h", "contenido", "EOF", "cat /tmp/h"], "contenido"),

    # UN BLOQUE PEGADO ENTRE COMILLAS. Con una comilla sin cerrar, bash saca su
    # prompt "> " y NO EJECUTA NADA hasta que se cierra: hasta entonces el salto
    # de linea es un caracter mas del texto. Salio de una captura de verdad ---un
    # atacante pegando un python3 -c, un node -e y un bash -c para llegar a una
    # base de datos--- donde el senuelo ejecutaba la primera linea y trataba las
    # demas como ordenes sueltas: en el log quedaban "import socket" y "try:"
    # como comandos que no supo ejecutar. Eso no lo hace ningun Linux.
    (["echo 'primera", "segunda'"], "primera\nsegunda"),
    (['echo "uno', 'dos"'], "uno\ndos"),
    # Y la segunda linea NO se ejecuta: es texto. Si se ejecutara, ademas de
    # delatarse, el senuelo estaria obedeciendo lo que va dentro de unas
    # comillas.
    (['echo "uno', 'rm -rf /tmp/noexiste"'], "uno\nrm -rf /tmp/noexiste"),
    (['echo "a"; echo "b', 'c"; echo fin'], "a\nb\nc\nfin"),
    (['cat <<"EOF"', "$HOME", "EOF"], "$HOME"),
    (["cat <<EOF", "$HOME", "EOF"], "/root"),
    (["cat <<EOF | wc -l", "a", "b", "EOF"], "2"),
    (["cat <<-EOF", "\tindentado", "\tEOF"], "indentado"),
    # Y con algo delante: el cuerpo es del "cat", no del "echo". Dandoselo al
    # primero de la linea, el cat se quedaba esperando y colgaba la sesion.
    (["echo antes; cat <<EOF", "cuerpo", "EOF"], "antes\ncuerpo"),

    # Un bucle en varias lineas daba "syntax error near unexpected token
    # `newline'": al juntarlas se metia un ";" detras del "do".
    (["for i in 1 2", "do", "echo n$i", "done"], "n1\nn2"),
    (["if true", "then", "echo si", "fi"], "si"),
    (["case a in", "a) echo si;;", "*) echo no;;", "esac"], "si"),

    # COMODINES. No se expandian: "echo /etc/pass*" contestaba el patron tal
    # cual, y con el, cosas como "rm -rf /tmp/*" no tocaban nada.
    ("echo /etc/pass*", "/etc/passwd /etc/passwd-"),
    ("cd /etc; echo pas*", "passwd passwd-"),
    ("echo /etc/p?sswd", "/etc/passwd"),
    ("echo /etc/[ps]asswd", "/etc/passwd"),
    # Un patron que no casa se deja SIN TOCAR, como en bash.
    ("echo /noexiste*", "/noexiste*"),
    # Y entrecomillado no se expande: "grep '[0-9]'" busca esa clase, no un
    # fichero que se llame asi.
    ("echo 'a*b'", "a*b"),
    ('echo "a*b"', "a*b"),

    # El "~" es el HOME, y solo al principio: "a~b" es un nombre valido.
    ("echo ~", "/root"),
    ("echo ~/x", "/root/x"),
    ("echo a~b", "a~b"),

    # Las tres formas de decir "ejecuta esto otro" se quedaban CALLADAS, que
    # es peor que un error: el guion cree que hizo algo.
    ("eval echo hola", "hola"),
    ('eval "echo dos"', "dos"),
    ("A=1; eval \"echo $A\"", "1"),
    ("command echo hola", "hola"),
    ("builtin echo hola", "hola"),
    # Y "source" no ejecutaba el fichero: un guion partido en dos perdia la
    # mitad sin decirlo.
    ('echo "echo desde-fichero" > /tmp/s.sh; . /tmp/s.sh', "desde-fichero"),

    # [[ ]] es una palabra clave de bash y contestaba "command not found",
    # que es lo que diria un shell que no es bash.
    ("[[ -f /etc/passwd ]] && echo si", "si"),
    ('[[ "a" == "a" ]] && echo igual', "igual"),
    ('[[ "a" == "b" ]] || echo no', "no"),
    ("[[ -f /noexiste ]] && echo si", ""),

    # tee creaba el fichero con su tamano y lo dejaba VACIO: peor que no
    # crearlo, que eso al menos se ve.
    ("echo x | tee /tmp/t; cat /tmp/t", "x\nx"),
    ("echo 1 | tee /tmp/t3; echo 2 | tee -a /tmp/t3; cat /tmp/t3",
     "1\n2\n1\n2"),

    # cut -c ACEPTABA la opcion y no la hacia: devolvia la linea entera, o sea
    # que un guion que recorta por columnas se llevaba todo, y en silencio.
    ("echo abcdef | cut -c1-3", "abc"),
    ("echo abcdef | cut -c2", "b"),
    ("echo abcdef | cut -c3-", "cdef"),
    ("echo abcdef | cut -c-2", "ab"),
    ("echo a:b:c | cut -d: -f2", "b"),

    # du no escribia NADA. Y lo que cuenta es el espacio en DISCO, no el
    # tamano: dos bytes ocupan un bloque de 4 KiB.
    ("echo x > /tmp/z1; du -h /tmp/z1", "4.0K\t/tmp/z1"),
    ("echo x > /tmp/z1; du /tmp/z1", "4\t/tmp/z1"),
    ("echo x > /tmp/z1; du -b /tmp/z1", "2\t/tmp/z1"),

    # rm escribia el acento invertido de un GNU antiguo; coreutils lo dejo
    # hace mas de una decada y el nuestro dice ser 9.7.
    ("rm /tmp/noexiste",
     "rm: cannot remove '/tmp/noexiste': No such file or directory"),

    # kill decia "No such process" de CUALQUIER pid, incluidos los que el "ps"
    # de al lado esta listando.
    ("kill -0 1; echo rc=$?", "rc=0"),
    ("kill -9 99999", "-bash: kill: (99999) - No such process"),

    # Los hashes desde la ENTRADA no daban nada: "cat binario | md5sum" es la
    # mitad de las veces que se teclean. El nombre que escribe coreutils
    # cuando lee de ahi es un guion.
    ("echo abc | md5sum", "0bee89b07a248e27c83fc3d5951213c1  -"),
    ("echo abc | sha256sum | cut -c1-20", "edeaaff3f1774ad28886"),
    ("echo abc | sha1sum | cut -c1-10", "03cfd74366"),

    # chmod SIMBOLICO no hacia nada: el atacante creia haber hecho ejecutable
    # su binario y "ls -l" seguia diciendo que no.
    ("echo x > /tmp/c1; chmod u+x /tmp/c1; ls -l /tmp/c1 | cut -c1-10",
     "-rwxr--r--"),
    ("echo x > /tmp/c2; chmod +x /tmp/c2; ls -l /tmp/c2 | cut -c1-10",
     "-rwxr-xr-x"),
    ("echo x > /tmp/c3; chmod a=r /tmp/c3; ls -l /tmp/c3 | cut -c1-10",
     "-r--r--r--"),

    # "stat -c" tomaba el formato por un nombre de fichero.
    ("echo x > /tmp/s1; stat -c '%s' /tmp/s1", "2"),
    ("echo x > /tmp/s2; stat -c '%s %n' /tmp/s2", "2 /tmp/s2"),
    ("echo x > /tmp/s3; stat -c '%U' /tmp/s3", "root"),

    # ln no existia, y el pickle declara /usr/bin/ln.
    ("echo x > /tmp/n1; ln -s /tmp/n1 /tmp/n2; readlink /tmp/n2", "/tmp/n1"),
    ("echo x > /tmp/n3; ln -s /tmp/n3 /tmp/n4; ls -l /tmp/n4 | cut -c1-10",
     "lrwxrwxrwx"),
    ("ln /noexiste /tmp/n5",
     "ln: failed to access '/noexiste': No such file or directory"),

    # grep -o escribia la linea entera, asi que un "grep -o x | wc -l"
    # contaba lineas donde tenia que contar coincidencias.
    ("printf aa | grep -o a", "a\na"),
    ('printf "aa\\nba\\n" | grep -o a | wc -l', "3"),
    # Pero "-c" sigue contando LINEAS aunque haya "-o".
    ('printf "aa\\n" | grep -oc a', "1"),
    # El parentesis se ejecuta EN SU SITIO, no al trocear: sin esto el
    # "true ||" no cortaba nada y el "dos" salia el primero.
    ("true || (echo X)", ""),
    # Y AL REVES: un parentesis a la IZQUIERDA del operador tambien es un
    # operando. Daba "syntax error near unexpected token" y lo de la derecha
    # no llegaba a ejecutarse nunca.
    ("(false) || echo respaldo", "respaldo"),
    ("(echo a) && echo si", "a\nsi"),
    ("(true) || echo no", ""),
    # El numero de "exit N" cuenta, y sale por una puerta de ocho bits.
    ("(exit 7); echo rc=$?", "rc=7"),
    ("(exit 300); echo rc=$?", "rc=44"),
    ("(exit -1); echo rc=$?", "rc=255"),
    ("(false; exit); echo rc=$?", "rc=1"),
    ("(echo a; exit 3; echo b); echo rc=$?", "a\nrc=3"),
    ("echo uno;(echo dos);echo tres", "uno\ndos\ntres"),
    ("A=uno; echo rc=$?", "rc=0"),

    # EL ENTRECOMILLADO. El lexer va en posix y tira las comillas, asi que lo
    # que no debe expandirse se marca ANTES de que las toque. Sin eso habia
    # que elegir entre expandir de verdad o no destrozar los programas de awk
    # y sed, y se elegia lo segundo.
    ("A=uno; echo '$A'", "$A"),
    ('A=uno; echo "$A"', "uno"),
    ("A=uno; echo \\$A", "$A"),
    ("echo a${NOEXISTE}b", "ab"),
    ("echo $NOEXISTE-fin", "-fin"),
    ("echo '$(date)'", "$(date)"),
    ("echo 'a`b`c'", "a`b`c"),
    ("A=uno; echo 'x'$A'y'", "xunoy"),
    ('A=uno; echo "\'$A\'"', "'uno'"),
    ("echo a b c | awk '{print $1}'", "a"),
    # El -F, en sus dos formas. Ninguna de las dos funcionaba: la lista de
    # opciones declaraba -F sin argumento, asi que el separador se tomaba por
    # el programa. Y aunque hubiera pasado, no se usaba en ningun sitio.
    ("echo a:b:c | awk -F: '{print $2}'", "b"),
    ("echo a:b:c | awk -F : '{print $2}'", "b"),
    ("printf 'a1b22c\\n' | awk -F '[0-9]+' '{print $2}'", "b"),
    ("echo a:b | awk -F: '{print NF}'", "2"),
    ("echo hola | awk -v x=adios '{print x}'", "adios"),
    # La coma pone UN espacio y sin coma se concatena: no son lo mismo.
    ("echo a b c | awk '{print $1, $3}'", "a c"),
    ("echo a:b:c | awk -F: '{print $1 $3}'", "ac"),
    ("echo x | awk '{print}'", "x"),
    ("echo hola | sed 's/o/0/g'", "h0la"),
    ('A=uno; echo "pre $A post"', "pre uno post"),
    ("A=uno; echo '${A}'", "${A}"),
    ('A=uno; echo "$A"\'$A\'', "uno$A"),
    ("false; echo $?", "1"),

    # LA EXPANSION DE PARAMETROS. Solo se entendian ${#V}, ${V:-x} y los
    # recortes ${V#pat}/${V%pat}: el operador se buscaba con un find() y el
    # primero que apareciera ganaba. Todo lo demas salia LITERAL en pantalla,
    # que es la peor forma de fallar ---un "${V/b/X}" impreso tal cual no lo
    # escribe ningun shell.
    ("V=abcabc; echo ${V/b/X}", "aXcabc"),
    ("V=abcabc; echo ${V//b/X}", "aXcaXc"),
    ("V=a.tar.gz; echo ${V/#a/B}", "B.tar.gz"),
    ("V=a.tar.gz; echo ${V/%gz/ZZ}", "a.tar.ZZ"),
    ("V=hola; echo ${V:1:2}", "ol"),
    ("V=abcabc; echo ${V:2}", "cabc"),
    # Con espacio a la fuerza: sin el, ${V:-2} es otra cosa. El lexer partia
    # el token justo ahi.
    ("V=abcabc; echo ${V: -2}", "bc"),
    ("V=hola; echo ${V^^}", "HOLA"),
    ("V=HOLA; echo ${V,,}", "hola"),
    ("echo ${NOEXISTE:=asignado}; echo $NOEXISTE", "asignado\nasignado"),
    ("N=NOM; NOM=valor; echo ${!N}", "valor"),
    ("unset V; echo ${V?falta}", "-bash: V: falta"),

    # LOS PARAMETROS POSICIONALES. "$#" ni siquiera llegaba entero: para el
    # lexer esa almohadilla abria un comentario y "echo $#" imprimia "$".
    ("echo $#", "0"),
    ("set -- a b c; echo $#; echo $2; shift; echo $1", "3\nb\nb"),
    ("set -- a b c; echo $@", "a b c"),

    # UN GRUPO COMPARTE UN ENTORNO. Cada orden de dentro se hacia su copia,
    # asi que una funcion no podia usar lo que ella misma acababa de asignar.
    ("(A=1; echo [$A])", "[1]"),
    ("f(){ x=5; echo [$x]; }; f", "[5]"),
    ("f(){ x=5; }; f; echo [$x]", "[5]"),

    # "local" y "return" contestaban SIEMPRE que solo valen dentro de una
    # funcion, tambien dentro de una.
    ("f(){ local x=5; echo [$x]; }; f", "[5]"),
    ("f(){ local x=5; }; f; echo [${x:-nada}]", "[nada]"),
    ("f(){ return 3; }; f; echo $?", "3"),
    ("f(){ echo uno; return 0; echo dos; }; f", "uno"),
    ("f(){ return 0; }; f && echo ok", "ok"),

    # La llave de cierre de una funcion se buscaba con una expresion regular
    # codiciosa y se llevaba hasta la ULTIMA de la linea: el ${...} del final
    # se comia el resto y el senuelo contestaba "]: command not found".
    ("f(){ local x=5; }; f; echo [${x:-nada}]x", "[nada]x"),

    # wc. El de la imagen no imprimia nada sin opciones, contaba las palabras
    # partiendo solo por espacios y no ensenaba ni el nombre ni el relleno.
    ("printf 'a b\\nc\\n' | wc -w", "3"),
    ("printf 'a b\\nc\\n' | wc -l", "2"),
    ("echo hola | wc -c", "5"),
    # El relleno se ve con tr porque el banco recorta los bordes: por una
    # tuberia coreutils reserva siete huecos por columna.
    ("echo hola | wc | tr ' ' '.'", "......1.......1.......5"),
    ("cd /tmp; printf 'a b c\\nd e\\n' > q1; wc q1 | tr ' ' '.'",
     ".2..5.10.q1"),
    ("cd /tmp; printf 'a b c\\nd e\\n' > q2; wc -lw q2 | tr ' ' '.'",
     ".2..5.q2"),
    ("cd /tmp; printf 'a b c\\nd e\\n' > q3; wc -l q3", "2 q3"),

    # UN CONDICIONAL DENTRO DE UN BUCLE. Los "if" se resolvian ANTES de
    # desenrollar el bucle, o sea que los del cuerpo no los miraba nadie:
    # tres "command not found" por vuelta ---if, then y fi--- y ademas se
    # ejecutaban las dos ramas.
    ("for i in 1 2 3; do if [ $i = 2 ]; then echo dos; fi; echo $i; done",
     "1\ndos\n2\n3"),
    ("for i in 1 2; do case $i in 1) echo uno;; *) echo otro;; esac; done",
     "uno\notro"),
    ("i=0; while [ $i -lt 2 ]; do if [ $i = 0 ]; then echo cero; fi;"
     " i=$((i+1)); done", "cero"),

    # LA SALIDA DE UN GRUPO NO ENTRABA EN LA TUBERIA: se escribia en pantalla
    # y el comando de detras corria sobre nada.
    ("(echo a; echo b) | wc -l", "2"),
    ("(echo a; echo b) | grep a", "a"),
    ("(echo a; echo b) | cat | wc -l", "2"),
    ("echo uno; (echo dos) | cat; echo tres", "uno\ndos\ntres"),
    # Y un bucle con una tuberia detras del "done" ni siquiera era un bucle:
    # la expresion pedia que la linea acabara ahi.
    ("for i in 1 2; do echo $i; done | wc -l", "2"),
    ("for i in 1 2; do echo $i; done | grep 2", "2"),

    # UNA ASIGNACION DENTRO DE UN GRUPO REPETIA LA SALIDA ANTERIOR: la ranura
    # donde se captura la salida se quedaba con la del comando de antes.
    ("(echo A; i=1; echo B)", "A\nB"),
    ("(echo A; i=$((i+1)); echo B)", "A\nB"),

    # "algo | while read": el while no arrancaba la linea, asi que caia al
    # troceo y contestaba "while: command not found". Es como se recorre un
    # fichero linea a linea en cualquier guion.
    ("printf 'a\\nb\\n' | while read l; do echo [$l]; done", "[a]\n[b]"),
    ("printf 'a b\\nc d\\n' | while read x y; do echo [$x][$y]; done",
     "[a][b]\n[c][d]"),
    ("printf 'a b c\\n' | while read x y; do echo [$x][$y]; done",
     "[a][b c]"),
    ("printf 'a\\nb\\n' | while read l; do echo [$l]; done; echo fin",
     "[a]\n[b]\nfin"),
    ("printf '' | while read l; do echo [$l]; done; echo vacio", "vacio"),
    ("printf 'a\\nb\\n' | while read l;"
     " do if [ $l = a ]; then echo A; else echo B; fi; done", "A\nB"),

    # "read" se rendia siempre, tambien cuando SI habia entrada.
    ("printf 'a b c\\n' > /tmp/rr; read x y < /tmp/rr; echo [$x][$y]",
     "[a][b c]"),
    ("printf '' > /tmp/ru; read q < /tmp/ru; echo rc=$? [$q]", "rc=1 []"),

    # "((i++))" contestaba "i++: command not found" y el contador no se movia.
    ("V=1; ((V++)); echo $V", "2"),
    ("V=1; ((V+=3)); echo $V", "4"),
    ("V=1; ((++V)); echo $V", "2"),
    ("((n=2*3)); echo $n", "6"),
    ("i=2; echo $((i++)); echo $i", "2\n3"),
    ("i=1; let 'i+=3'; echo $i", "4"),
    ("let k=0; echo rc=$?", "rc=1"),
    ("let m=5; echo rc=$?", "rc=0"),
    # La base: "2#101" son cinco, y el "#101" se lo comia el analizador.
    ("echo $((2#101))", "5"),
    ("echo $((16#ff))", "255"),
    # Y los errores son los TRES de bash, no "division by 0" para todo.
    ("((echo a)); echo b",
     '-bash: ((: echo a: syntax error in expression (error token is "a")\nb'),
    ("((1 +)); echo b",
     '-bash: ((: 1 +: syntax error: operand expected (error token is "+")\nb'),
    ("((x@y)); echo b",
     '-bash: ((: x@y: syntax error: invalid arithmetic operator'
     ' (error token is "@y")\nb'),
    ("let 'a b'; echo rc=$?",
     '-bash: let: a b: syntax error in expression (error token is "b")\nrc=1'),

    # "break" y "continue" contestaban "command not found", y dentro de un
    # bucle que por lo demas funcionaba: el guion corria y se quejaba a la vez.
    ("for i in 1 2 3; do if [ $i = 2 ]; then continue; fi; echo $i; done",
     "1\n3"),
    ("for i in 1 2 3; do if [ $i = 2 ]; then break; fi; echo $i; done; echo fin",
     "1\nfin"),
    ("for i in 1 2 3; do echo $i; break; done; echo fin", "1\nfin"),
    # En la ULTIMA vuelta "continue" acaba el bucle, no se queja de que no
    # haya otra.
    ("for i in 1 2 3; do continue; echo $i; done; echo fin", "fin"),
    ("printf 'a\\nb\\nc\\n' | while read l;"
     " do if [ $l = b ]; then break; fi; echo [$l]; done", "[a]"),
    # Y fuera de un bucle bash AVISA pero devuelve cero.
    ("break; echo rc=$?",
     "-bash: break: only meaningful in a `for', `while', or `until' loop"
     "\nrc=0"),

    # UN COMANDO QUE SE QUEJA Y DEVUELVE CERO. Casi ninguno ponia su codigo de
    # salida, asi que "cat fichero || wget URL" se tragaba el respaldo: el
    # atacante ve su guion seguir por la rama que no toca.
    ("cat /noexiste; echo rc=$?",
     "cat: /noexiste: No such file or directory\nrc=1"),
    ("cat /noexiste 2>/dev/null || echo fallo", "fallo"),
    ("head /noexiste; echo rc=$?",
     "head: cannot open '/noexiste' for reading: No such file or directory"
     "\nrc=1"),
    ("tail /noexiste; echo rc=$?",
     "tail: cannot open '/noexiste' for reading: No such file or directory"
     "\nrc=1"),
    ("cut -c1 /noexiste; echo rc=$?",
     "cut: /noexiste: No such file or directory\nrc=1"),
    ("md5sum /noexiste; echo rc=$?",
     "md5sum: /noexiste: No such file or directory\nrc=1"),
    ("rm /noexiste; echo rc=$?",
     "rm: cannot remove '/noexiste': No such file or directory\nrc=1"),
    ("rmdir /noexiste; echo rc=$?",
     "rmdir: failed to remove '/noexiste': No such file or directory\nrc=1"),
    ("cp /noexiste /tmp/x; echo rc=$?",
     "cp: cannot stat '/noexiste': No such file or directory\nrc=1"),
    ("mv /noexiste /tmp/x; echo rc=$?",
     "mv: cannot stat '/noexiste': No such file or directory\nrc=1"),
    ("touch /noexiste/x; echo rc=$?",
     "touch: cannot touch '/noexiste/x': No such file or directory\nrc=1"),
    ("readlink /noexiste; echo rc=$?", "rc=1"),
    ("grep x /noexiste; echo rc=$?",
     "grep: /noexiste: No such file or directory\nrc=2"),

    # Y el prefijo de "cd" era "bash:" a secas, cuando el resto del shell
    # dice "-bash:", que es lo que dice una sesion de login de verdad.
    ("cd /noexiste; echo rc=$?",
     "-bash: cd: /noexiste: No such file or directory\nrc=1"),

    # TRES QUE MATABAN O COLGABAN LA SESION.
    ("mkdir /noexiste/x; echo rc=$?",
     "mkdir: cannot create directory '/noexiste/x': "
     "No such file or directory\nrc=1"),
    ("tr a b c; echo rc=$?",
     "tr: extra operand 'c'\nTry 'tr --help' for more information.\nrc=1"),
    ("uniq /noexiste; echo rc=$?",
     "uniq: /noexiste: No such file or directory\nrc=1"),
    # uniq ni siquiera sabia leer un fichero: solo leia de la entrada, asi que
    # la forma normal de llamarlo se quedaba esperando.
    ("cd /tmp; printf 'a\\na\\nb\\n' > u1; uniq u1", "a\nb"),
    # Con tr porque el banco recorta los bordes y el relleno del recuento se
    # perderia justo en la primera linea.
    ("cd /tmp; printf 'a\\na\\nb\\n' > u2; uniq -c u2 | tr ' ' '.'",
     "......2.a\n......1.b"),

    # head y tail avisaban del numero malo y VOLCABAN EL FICHERO detras.
    ("cd /tmp; printf 'a\\nb\\n' > h1; head -n x h1; echo rc=$?",
     "head: invalid number of lines: 'x'\nrc=1"),
    ("cd /tmp; printf 'a\\nb\\n' > h2; tail -n x h2; echo rc=$?",
     "tail: invalid number of lines: 'x'\nrc=1"),

    # "hostname -I" NO DABA LA IP: le ponia a la maquina el nombre "-I", y a
    # partir de ahi el prompt del atacante decia "root@-I:~#".
    ("hostname -f; hostname", "unitTest\nunitTest"),
    ("hostname -I", "198.51.100.146"),
    ("hostname -s; hostname", "unitTest\nunitTest"),

    # "$$" se imprimia tal cual, y es como se nombra medio fichero temporal.
    ("echo $$", "48230"),
    ("echo /tmp/.$$", "/tmp/.48230"),
    ("echo $PPID", "48219"),

    # UNA SUSTITUCION SE RESOLVIA AL TROCEAR, o sea antes de que corrieran las
    # asignaciones de su propia linea.
    ("i=1; echo $(echo $i)", "1"),
    ("i=1; i=$(expr $i + 1); echo $i", "2"),
    ("A=uno; echo [$(echo $A)]", "[uno]"),

    # UN OPERADOR ESCAPADO CON BARRA volvia a ser operador despues del troceo:
    # el "2" acababa redirigido a un fichero llamado "1".
    ("expr 2 \\> 1", "1"),
    ("expr 3 \\* 2", "6"),
    ("echo \\|", "|"),
    ("echo a\\>b", "a>b"),

    # ls EN COLUMNAS AUNQUE LA SALIDA NO FUERA UN TERMINAL. No es formato: un
    # "ls | wc -l" contaba las lineas, no los ficheros.
    ("cd /tmp; mkdir -p lsd; cd lsd; touch a b c; ls | wc -l", "3"),
    ("cd /tmp; mkdir -p lse; cd lse; touch a b c; ls", "a  b  c"),
    ("cd /tmp; mkdir -p lsf; cd lsf; touch a b c; ls -1 | tr '\\n' ','",
     "a,b,c,"),

    # Nueve de coreutils que el sistema de ficheros declara y no estaban.
    ("expr 1 + 2", "3"),
    ("expr length abc", "3"),
    ("expr substr abcdef 2 3", "bcd"),
    ("echo abcdef | fold -w2 | tr '\\n' ','", "ab,cd,ef,"),
    ("printf 'a\\nb\\nc\\n' | paste -sd,", "a,b,c"),
    ("printf 'a\\nb\\nc\\nd\\n' | paste -d: - -", "a:b\nc:d"),
    ("realpath /etc/../etc/hosts", "/etc/hosts"),
    ("nice", "0"),
    ("nice -n 5 echo hola", "hola"),
    ("timeout 5 echo hola", "hola"),
    ("uptime -s", "2026-03-10 06:23:00"),
    ("ulimit -n", "1024"),

    # env solo sabia listar: se tragaba la orden que le dieran.
    ("env -i echo hola", "hola"),
    ("env A=1 sh -c 'echo $A'", "1"),

    # CRONTAB SE TRAGABA LA PERSISTENCIA Y ADEMAS COLGABA LA SESION: "crontab -"
    # no encajaba en ninguna rama del de la imagen y no llamaba a exit(), asi
    # que el atacante se quedaba sin prompt.
    ("crontab -l; echo rc=$?", "no crontab for root\nrc=1"),
    ("echo '* * * * * /tmp/x' | crontab -; crontab -l", "* * * * * /tmp/x"),
    ("echo '* * * * * /tmp/x' | crontab -; crontab -r; crontab -l; echo rc=$?",
     "no crontab for root\nrc=1"),
    # El de instalar sin perder lo que hubiera, que es el que se teclea.
    ("(crontab -l; echo '* * * * * /tmp/m') | crontab -; crontab -l",
     "no crontab for root\n* * * * * /tmp/m"),
    ("crontab -u nadie -l; echo rc=$?",
     "crontab:  user `nadie' unknown\nrc=1"),
    # Y lo guardado se ve tambien por el otro lado, con su cabecera.
    ("echo '* * * * * /tmp/x' | crontab -;"
     " head -1 /var/spool/cron/crontabs/root",
     "# DO NOT EDIT THIS FILE - edit the master and reinstall."),

    # "useradd" apuntaba a la MISMA clase que "adduser", que es otro programa:
    # contestaba "Adding user ..." y se quedaba pidiendo una contrasena.
    ("useradd pepe; echo rc=$?", "rc=0"),
    ("useradd pepe; grep pepe /etc/passwd",
     "pepe:x:1001:1001::/home/pepe:/bin/sh"),
    ("useradd pepe; useradd pepe; echo rc=$?",
     "useradd: user 'pepe' already exists\nrc=9"),
    ("useradd pepe; id pepe", "uid=1001(pepe) gid=1001(pepe) groups=1001(pepe)"),
    ("useradd pepe; usermod -aG sudo pepe; grep sudo /etc/group",
     "sudo:x:27:pepe"),
    ("useradd pepe; userdel pepe; echo rc=$?; grep -c pepe /etc/passwd",
     "rc=0\n0"),
    ("userdel pepe; echo rc=$?", "userdel: user 'pepe' does not exist\nrc=6"),

    # chattr se tragaba la bandera y lsattr no existia, asi que un "chattr +i"
    # seguido de un "lsattr" se contradecian.
    ("lsattr /etc/hosts", "--------------e------- /etc/hosts"),
    ("touch /tmp/im; chattr +i /tmp/im; lsattr /tmp/im",
     "----i---------e------- /tmp/im"),
    ("chattr +i /noexiste; echo rc=$?",
     "chattr: No such file or directory while trying to stat /noexiste\nrc=1"),

    # "service --status-all" describia un escritorio Ubuntu con cups y lightdm.
    ("service noexiste status; echo rc=$?",
     "noexiste: unrecognized service\nrc=1"),

    # "find /" DEJABA LA SESION COLGADA. Cada entrada se volvia a resolver
    # desde "/" ---cuatro recorridos del arbol por fichero--- y el coste crecia
    # con el cuadrado. Y "find / -perm -4000" es LA orden para buscar por donde
    # escalar: el atacante se iba antes de que contestara.
    ("find / -name hosts | head -1", "/etc/hosts"),
    ("find / -perm -4000 | head -1", "/usr/bin/chfn"),

    # "ps -ef" ensenaba SOLO LA CABECERA: no se miraban las opciones con
    # guion, asi que filtraba por usuario y por terminal y no quedaba ni una
    # linea.
    ("ps -ef | head -2",
     "UID          PID    PPID  C STIME TTY          TIME CMD\n"
     "root           1       0  0 Nov06 ?        00:00:00 init [2]"),
    ("ps -e | head -2", "PID TTY          TIME CMD\n"
     "      1 ?        00:00:00 init [2]"),
    ("ps -p 1", "PID TTY          TIME CMD\n"
     "      1 ?        00:00:00 init [2]"),

    # Las dos herramientas con las que se baja el binario NEGABAN SU VERSION,
    # que es lo primero que se mira porque las opciones cambian entre ellas.
    ("wget --version | head -1", "GNU Wget 1.25.0 built on linux-gnu."),
    ("curl --version | head -1 | cut -d' ' -f1-2", "curl 8.14.1"),
    ("tar --version | head -1", "tar (GNU tar) 1.35"),

    # gzip no estaba de ninguna forma, y el sistema de ficheros lo declara.
    ("printf 'hola mundo\\n' > /tmp/g2; gzip /tmp/g2; gunzip /tmp/g2.gz;"
     " cat /tmp/g2", "hola mundo"),
    ("printf 'hola\\n' > /tmp/g3; gzip -c /tmp/g3 | zcat", "hola"),
    ("gzip -d /etc/hosts; echo rc=$?",
     "gzip: hosts: not in gzip format\nrc=1"),

    # "sudo -l" salia EN BLANCO, y en un sudo de verdad no pasa nunca: o
    # lista o dice que no puedes.
    ("sudo -l | head -1", "Matching Defaults entries for root on unitTest:"),

    # "x86_64" es el CUARTO de la lista de que_le_falta_al_senuelo.py, y no
    # era un comando raro que fallara: es un enlace a setarch y lo que hace es
    # EJECUTAR lo que se le ponga detras. Sin el, un "x86_64 -R ./payload"
    # ---desactivar la aleatorizacion de memoria, tecnica de verdad--- cortaba
    # la cadena del atacante ahi mismo.
    ("x86_64 echo hola", "hola"),
    ("x86_64 -R echo hola", "hola"),
    ("x86_64 -v -R echo hola",
     "Switching on ADDR_NO_RANDOMIZE.\nExecute command `echo'.\nhola"),
    ("linux64 echo hola", "hola"),
    ("x86_64 --help | sed -n 2,3p",
     "Usage:\n x86_64 [options] [<program> [<argument>...]]"),
    ("x86_64 noexistejamas; echo rc=$?",
     "x86_64: failed to execute noexistejamas: No such file or directory"
     "\nrc=127"),

    # "time" contestaba "command not found", y no es un binario: es una
    # PALABRA CLAVE de bash, asi que funciona siempre aunque no haya nada en
    # el disco. El bloque va por la salida de ERROR, como en bash.
    ("time echo hola 2>/dev/null", "hola"),
    ("time echo hola 2>&1 | grep -c real", "1"),

    # LO QUE RELANZA UNA ORDEN NO IMPRIMIA NADA DENTRO DE UNA TUBERIA:
    # protocol.pp es una sola ranura y ejecutar por dentro la dejaba apuntando
    # al comando de dentro, asi que la tuberia de fuera perdia su salida.
    # Pasaba en eval, command, builtin, source, nice, timeout, setarch y env.
    ("eval echo hola | cat", "hola"),
    ("eval echo a | grep a", "a"),

    # LA CONDICION DEL WHILE NO SE EVALUABA: el cuerpo se repetia tres veces y
    # ya, asi que el numero de vueltas de cualquier bucle contado estaba mal
    # SIEMPRE ---y contar es justo para lo que se usa un while---.
    ("i=0; while [ $i -lt 2 ]; do echo x; i=$((i+1)); done", "x\nx"),
    ("i=0; while [ $i -lt 5 ]; do echo $i; i=$((i+1)); done", "0\n1\n2\n3\n4"),
    ("while false; do echo x; done; echo fin", "fin"),
    ("i=0; while [ $i -lt 3 ]; do echo $i; i=$((i+1)); done; echo fin",
     "0\n1\n2\nfin"),
    # Y con un "if" dentro, que es lo normal y ademas era lo que partia la
    # linea por donde no debia.
    ("i=0; while [ $i -lt 3 ]; do if [ $i = 1 ]; then break; fi; echo $i;"
     " i=$((i+1)); done; echo fin", "0\nfin"),
    ("i=0; while [ $i -lt 4 ]; do i=$((i+1));"
     " if [ $i = 2 ]; then continue; fi; echo $i; done; echo fin",
     "1\n3\n4\nfin"),
    ("while true; do echo x; break; done; echo fin", "x\nfin"),
    ("nice -n 5 echo hola | cat", "hola"),
    ("x86_64 echo hola | cat", "hola"),
    ("timeout 5 echo hola | cat", "hola"),

    # head METIA UNA LINEA EN BLANCO DE MAS: partia por "\n" y escribia un
    # salto detras de cada trozo, incluido el trozo vacio que deja el salto
    # del final. Un "head -2 fichero | wc -l" sobre un fichero de una linea
    # contestaba 2.
    ("printf 'unalinea\\n' > /tmp/h1; head -2 /tmp/h1 | wc -l", "1"),
    ("printf 'a\\nb\\nc\\n' > /tmp/h5; head -2 /tmp/h5 | wc -l", "2"),
    ("printf 'sinsalto' > /tmp/h7; head -2 /tmp/h7 | wc -c", "8"),

    # "cat -A" se aceptaba y no hacia nada, y es de lo que se teclea para ver
    # si un fichero trae tabuladores o retornos donde no debe: contestaba el
    # texto pelado, o sea que decia que no hay nada raro pase lo que pase.
    ("printf 'a\\tb\\n' > /tmp/c2; cat -A /tmp/c2", "a^Ib$"),
    ("printf 'a\\tb\\n' > /tmp/c3; cat -T /tmp/c3", "a^Ib"),
    # Y "cat -n" separaba con dos espacios donde va un TABULADOR, asi que un
    # corte por tabuladores detras se llevaba la linea entera.
    ("printf 'a\\nb\\n' > /tmp/c4; cat -n /tmp/c4 | cut -f2", "a\nb"),
]

# Lo que SIGUE SIN CUADRAR y esta explicado en el 3.4.2.8 del README.
# Va aparte para que la lista de arriba pueda estar en verde: un banco con un
# fallo permanente ensena a no mirar los fallos.
# Lo que se encuentra y no se arregla en el acto va aqui, con el motivo, en
# vez de dejarlo fallando arriba: un banco con un fallo permanente ensena a no
# mirar los fallos.
ABIERTOS: list = [
    ("V='a  b'; echo [$V]", "[a b]",
     "El reparto en palabras de una expansion SIN comillas. Bash parte por "
     "espacios lo que sale de $V y el echo vuelve a juntarlo con uno solo; "
     "aqui el valor llega entero. Se ve con valores que traigan espacios de "
     "sobra, que no es lo normal."),
    ("i=0; while [ $i -lt 9 ]; do echo x; i=$((i+1)); done | wc -l", "9",
     "Un while CON TUBERIA detras sigue con el desenrollado acotado: la "
     "salida del bucle entero tiene que entrar en la tuberia, y eso pide "
     "envolverlo con TODAS las vueltas dentro, que se generan de una en una."),
    ("f(){ local A=1; g(){ echo [$A]; }; g; }; f", "[1]",
     "Una funcion definida DENTRO de otra. El cuerpo lo ejecuta la misma "
     "maquinaria que un parentesis, y esa no busca definiciones: solo las "
     "reconoce lineReceived(). SE INTENTO Y SE DIO MARCHA ATRAS: reconocer "
     "la definicion ahi es facil, pero al llamarla la salida sale DUPLICADA "
     "---el sitio que ejecuta el cuerpo escribe en la terminal y ademas "
     "devuelve el texto al grupo que lo captura---, y una salida repetida en "
     "silencio es peor que un 'command not found' que se ve. Arreglarlo pide "
     "tocar como escribe una funcion cuando corre dentro de un grupo, que no "
     "es sitio para entrar la vispera de un despliegue. Se ve en guiones "
     "largos, no en un dropper."),
]

DENTRO = r'''
import os, shutil, glob, re, sys, json
SRC = "/cowrie/cowrie-git/src/cowrie"
for f in glob.glob("/patch/commands/*.py"):
    if not os.path.basename(f).startswith("test_"):
        shutil.copy(f, SRC + "/commands/" + os.path.basename(f))
shutil.copy("/patch/shell/honeypot.py", SRC + "/shell/honeypot.py")
os.environ.setdefault("COWRIE_HONEYPOT_DATA_PATH", SRC + "/data")
os.environ.setdefault("COWRIE_SHELL_FILESYSTEM", SRC + "/data/fs.pickle")
from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

def limpia(s):
    s = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", s)
    # El "> " es el prompt de continuacion: en un caso de varias lineas sale
    # uno por linea y no es salida del comando.
    s = re.sub(r"root@unitTest:[^#]*# ?", "", s)
    return re.sub(r"^(> )+", "", s.strip()).strip()

salida = []
for linea in json.load(sys.stdin):
    p = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
    tr = FakeTransport("", "31337"); p.makeConnection(tr)
    tr.clear()
    try:
        for _l in ([linea] if isinstance(linea, str) else linea):
            p.lineReceived(_l.encode())
        dice = limpia(tr.value().decode("utf-8", "replace"))
    except Exception as e:
        salida.append([linea, "REVIENTA %s: %s" % (type(e).__name__, e), False])
        continue
    # LA SESION TIENE QUE SEGUIR VIVA. Sin esto una prueba puede pasar y
    # dejar el senuelo inservible: paso de verdad, con lineReceived en bucle.
    tr.clear()
    try:
        p.lineReceived(b"echo VIVA")
        viva = "VIVA" in tr.value().decode("utf-8", "replace") \
            and len(p.cmdstack) == 1
    except Exception:
        viva = False
    salida.append([linea, dice, viva])
print("@@@" + json.dumps(salida))
'''


def main() -> int:
    # ESTO SE CORRE DESDE EL ARBOL DEL REPOSITORIO, no desde el home de la VPS.
    # Y hay que comprobarlo antes de llamar a docker, porque el fallo no daria
    # la cara: PARCHES se monta como volumen, y docker CREA el directorio del
    # anfitrion si no existe ---como root---. O sea que lanzado desde ~/ en la
    # VPS dejaria una carpeta basura en /home y montaria un /patch vacio: el
    # banco pasaria los casos contra el Cowrie DE FABRICA, sin ninguno de
    # nuestros comandos, y sus fallos no querrian decir nada.
    #
    # El install del apartado 3.6 lo copia al home con un comodin, junto a los
    # demas, asi que ese "lanzado desde ~/" es un despiste de un segundo.
    if not os.path.isdir(PARCHES):
        print("no encuentro los comandos parcheados en:", file=sys.stderr)
        print("  %s" % PARCHES, file=sys.stderr)
        print("\nEste banco se ejecuta DESDE EL ARBOL DEL REPOSITORIO, que es "
              "donde estan\nlos modulos que prueba:", file=sys.stderr)
        print('  python3 "3.6 Para facilitarnos la vida/banco_shell_real.py"',
              file=sys.stderr)
        print("\nNo se sigue a proposito: docker crearia esa carpeta vacia y el "
              "banco\nprobaria el Cowrie de fabrica, sin nuestros comandos.",
              file=sys.stderr)
        return 2

    verboso = "-v" in sys.argv
    import json
    todos = [c for c, _ in CASOS] + [c for c, _, _ in ABIERTOS]
    resultados: list = []
    for desde in range(0, len(todos), POR_TANDA):
        tanda = todos[desde:desde + POR_TANDA]
        proceso = subprocess.run(
            ["docker", "run", *LIMITES, "-i", "--user", "root",
             "-v", "%s:/patch:ro" % PARCHES, "--entrypoint",
             "/cowrie/cowrie-env/bin/python3", IMAGEN, "-c", DENTRO],
            input=json.dumps(tanda),
            capture_output=True, text=True)
        marca = [l for l in proceso.stdout.split("\n") if l.startswith("@@@")]
        if not marca:
            print("No se pudo correr la tanda %d-%d. Salida de docker "
                  "(rc=%s):\n%s\n%s"
                  % (desde, desde + len(tanda), proceso.returncode,
                     proceso.stdout[-2000:], proceso.stderr[-2000:]))
            if proceso.returncode == 137:
                print("  rc=137 es que se quedo sin memoria: baja POR_TANDA.")
            return 2
        resultados += json.loads(marca[0][3:])
    mal = 0
    for (linea, esperado), (_, dice, viva) in zip(CASOS, resultados):
        # Un caso con `esperado` a None es de los que llevan algo que cambia
        # en cada ejecucion ---el PID de un trabajo en el fondo---: solo se
        # comprueba que la sesion sigue viva y que contesta algo.
        if esperado is None:
            bien = viva and bool(dice)
        else:
            bien = dice == esperado and viva
        if bien and not verboso:
            continue
        mal += 0 if bien else 1
        print("%s %s" % ("ok   " if bien else "FALLO", linea))
        if not bien:
            print("        bash dice: %r" % esperado)
            print("        el senuelo: %r" % dice)
            if not viva:
                print("        Y LA SESION SE QUEDA MUERTA")
    # LAS MARCAS NO PUEDEN LLEGAR A LA PANTALLA. Se usan caracteres de
    # control para proteger lo entrecomillado del expansor; si alguno se
    # escapara sin restaurar, el atacante veria un byte raro en su salida.
    sueltas = [linea for (linea, _e), (_, dice, _v)
               in zip(CASOS, resultados)
               if any(c in dice for c in
                      "\x01\x02\x03\x04\x05\x06\x07\x0e\x0f\x10\x11\x12\x13")]
    if sueltas:
        mal += len(sueltas)
        print("FALLO se escapan marcas de control a la pantalla: %s" % sueltas)

    print("\n%d casos, %d discrepan" % (len(CASOS), mal))

    print("\nAbiertos a proposito (ver el 3.4.2.8 del README):")
    for (linea, esperado, por_que), (_, dice, _v) in zip(
            ABIERTOS, resultados[len(CASOS):]):
        print("  %s\n      bash %r / senuelo %r\n      %s"
              % (linea, esperado, dice, por_que))
    return 1 if mal else 0


if __name__ == "__main__":
    sys.exit(main())
