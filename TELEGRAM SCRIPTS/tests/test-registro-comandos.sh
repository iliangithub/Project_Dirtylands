#!/usr/bin/env bash
# test-registro-comandos.sh — que se registre lo que teclea una persona.
#
#   bash "TELEGRAM SCRIPTS/tests/test-registro-comandos.sh"
#
# Esto no comprueba un formato: comprueba una COBERTURA, y la pieza no la
# tenia. El 2026-08-29 se descubrio que un shell de root abierto con
# "sudo su" no registraba absolutamente nada ---se veia "cmd=sudo su" y
# despues silencio, sin ningun error---, porque /etc/profile.d solo lo leen
# los shells de LOGIN. Con "sudo -i" si funcionaba, y eso es lo que hacia el
# fallo dificil de ver: dependia de como te hicieras root.
#
# Asi que aqui se arranca un bash de verdad de cada tipo, se le teclean
# ordenes por la entrada estandar y se mira lo que habria llegado al journal.
# El "logger" es de mentira y escribe a un fichero; todo lo demas es real.
set -uo pipefail

AQUI=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
FUENTE="$AQUI/../registro-comandos.sh"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"

cat > "$TMP/bin/logger" <<'EOF'
#!/bin/bash
# El ultimo argumento es el mensaje; lo anterior son las opciones.
args=(); for a in "$@"; do args+=("$a"); done
printf '%s\n' "${args[-1]}" >> "$LOGGER_SALIDA"
EOF
chmod +x "$TMP/bin/logger"

OK=0; MAL=0
comprueba() {
    local que="$1" esperado="$2" obtenido="$3"
    if [ "$esperado" = "$obtenido" ]; then
        OK=$((OK + 1)); printf '  ok    %s\n' "$que"
    else
        MAL=$((MAL + 1))
        printf '  FALLO %s\n          esperaba <%s>\n          obtuvo   <%s>\n' \
            "$que" "$esperado" "$obtenido"
    fi
}

# Se teclean ordenes en un bash de verdad. $1 dice desde donde se carga el
# fichero, que es justo lo que distingue un shell de login de uno que no lo es.
#   perfil : como /etc/profile.d  -> solo shells de LOGIN
#   bashrc : como /etc/bash.bashrc -> shells interactivos NO login
# Se usa un HOME de mentira con .profile y .bashrc dentro, y se lanzan shells
# DE VERDAD de cada tipo. Es lo mismo que hace el sistema: un shell de login
# lee el perfil, uno interactivo normal lee el bashrc. Nada de banderas raras
# que simulen la situacion ---con --norc y --rcfile a la vez, por ejemplo,
# gana --norc y el fichero no se carga: la prueba diria que no se registra
# nada cuando el problema es la prueba---.
teclear() {   # $1 = perfil|bashrc ; $2... = ordenes
    local donde="$1"; shift
    local casa="$TMP/casa-$donde"
    rm -rf "$casa"; mkdir -p "$casa"
    if [ "$donde" = "perfil" ]; then
        printf '. "%s"\n' "$FUENTE" > "$casa/.profile"
    else
        printf '. "%s"\n' "$FUENTE" > "$casa/.bashrc"
    fi
    # Un historial de una sesion ANTERIOR, que es lo normal en una cuenta que
    # ya se ha usado. Si no se pone, el fallo del arranque no se reproduce.
    printf 'ls -la\nwhoami\nexit\n' > "$casa/hist"
    : > "$TMP/salida.txt"
    local ordenes=""
    for o in "$@"; do ordenes+="$o"$'\n'; done
    local bandera="-i"
    [ "$donde" = "perfil" ] && bandera="-l -i"
    # shellcheck disable=SC2086
    printf '%s' "$ordenes" | \
        env HOME="$casa" PATH="$TMP/bin:$PATH" \
            LOGGER_SALIDA="$TMP/salida.txt" HISTFILE="$casa/hist" \
            bash $bandera >/dev/null 2>&1
    cat "$TMP/salida.txt" 2>/dev/null
}

campo() {   # $1 = nombre del campo, $2 = linea
    printf '%s' "$2" | sed -nE "s/.*(^| )$1=([^ ]*).*/\\2/p"
}

echo
echo "Lo que teclea una persona queda anotado"
salida=$(teclear bashrc 'echo hola' 'false')
comprueba "una orden por linea" "2" "$(printf '%s' "$salida" | grep -c 'cmd=')"
comprueba "con el texto tal cual se escribio" "1" \
    "$(printf '%s' "$salida" | grep -c 'cmd=echo hola$')"
# El codigo de salida es la mitad del valor de esto: dice si lo que hizo el
# intruso le funciono.
comprueba "y el codigo de salida de cada una" "1" \
    "$(printf '%s' "$salida" | grep -c 'rc=1 cmd=false$')"
comprueba "el de la que salio bien, tambien" "1" \
    "$(printf '%s' "$salida" | grep -c 'rc=0 cmd=echo hola$')"

echo
echo "EL SHELL DE ROOT SIN LOGIN, que era el punto ciego"
# "sudo su", "sudo -s" y "sudo bash" abren un interactivo que NO es de login:
# no pasa por /etc/profile.d. Si esto falla, todo lo que se teclee como root
# por esa via se pierde en silencio.
salida=$(teclear bashrc 'id' 'cat /etc/shadow')
comprueba "un shell interactivo no-login SI registra" "2" \
    "$(printf '%s' "$salida" | grep -c 'cmd=')"
comprueba "incluida la orden que mas importaria ver" "1" \
    "$(printf '%s' "$salida" | grep -c 'cmd=cat /etc/shadow$')"

echo
echo "Y el de login sigue funcionando"
salida=$(teclear perfil 'whoami')
comprueba "un shell de login tambien registra" "1" \
    "$(printf '%s' "$salida" | grep -c 'cmd=whoami$')"

echo
echo "Ni se inventa ordenes ni pierde la ultima"
#
# Los dos fallos que se vieron el 2026-08-29 abriendo shells de root: llegaron
# dos avisos de "exit" que nadie habia tecleado en esa sesion, y no llego nada
# de lo que si se habia tecleado.

# 1. EL HISTORIAL YA VIENE LLENO. Al abrir un shell, bash carga
#    ~/.bash_history, y el primer disparo ---antes de que nadie teclee---
#    encontraba ahi la ultima linea de una sesion anterior y la anotaba como
#    recien ejecutada. Un registro que inventa ordenes manda a investigar humo.
salida=$(teclear bashrc 'id')
comprueba "no anota nada del historial de la sesion anterior" "0" \
    "$(printf '%s' "$salida" | grep -c 'cmd=ls -la$')"
comprueba "ni la ultima linea de aquel historial" "0" \
    "$(printf '%s' "$salida" | grep -cE 'cmd=whoami$')"
comprueba "y lo que SI se tecleo, si" "1" \
    "$(printf '%s' "$salida" | grep -c 'cmd=id$')"

# 2. LA ULTIMA ORDEN DE LA SESION. PROMPT_COMMAND salta ANTES de cada prompt,
#    y despues de "exit" ya no hay otro: se perdia siempre. Y es la que mas
#    interesa, porque es lo que alguien hace justo antes de irse.
salida=$(teclear bashrc 'cat /etc/shadow' 'exit')
comprueba "la ultima orden antes de salir se anota" "1" \
    "$(printf '%s' "$salida" | grep -c 'cmd=exit$')"
comprueba "y la de antes tambien" "1" \
    "$(printf '%s' "$salida" | grep -c 'cmd=cat /etc/shadow$')"

# 3. Y NO SE DUPLICA. Si el shell termina sin "exit" ---por fin de entrada, o
#    porque se corta la conexion--- la ultima orden ya se anoto por el camino
#    normal, y la trampa de salida tiene que reconocerla y callarse.
salida=$(teclear bashrc 'uname -a')
comprueba "al terminar sin exit, la ultima no sale dos veces" "1" \
    "$(printf '%s' "$salida" | grep -c 'cmd=uname -a$')"

echo
echo "Lo que NO debe hacer"
# En Debian un shell de login pasa por /etc/profile Y por /etc/bash.bashrc,
# asi que el fichero se carga dos veces en el mismo shell. Sin la guarda, cada
# orden saldria por duplicado.
rm -rf "$TMP/casa-doble"; mkdir -p "$TMP/casa-doble"
printf '. "%s"\n. "%s"\n' "$FUENTE" "$FUENTE" > "$TMP/casa-doble/.bashrc"
: > "$TMP/salida.txt"
printf 'echo dos\n' | env HOME="$TMP/casa-doble" PATH="$TMP/bin:$PATH" \
    LOGGER_SALIDA="$TMP/salida.txt" HISTFILE="$TMP/casa-doble/hist" \
    bash -i >/dev/null 2>&1
comprueba "cargarlo dos veces no duplica la anotacion" "1" \
    "$(grep -c 'cmd=echo dos$' "$TMP/salida.txt")"

# Un "ssh maquina orden" o un scp abren un bash NO interactivo. Ahi no hay
# nadie tecleando y no pinta nada.
: > "$TMP/salida.txt"
env PATH="$TMP/bin:$PATH" LOGGER_SALIDA="$TMP/salida.txt" \
    bash -c ". \"$FUENTE\"; echo nada" >/dev/null 2>&1
comprueba "en un shell no interactivo no anota nada" "0" \
    "$(grep -c 'cmd=' "$TMP/salida.txt" 2>/dev/null; true)"

echo
echo "El formato que espera comandos-watch.sh"
salida=$(teclear bashrc 'echo uno')
linea=$(printf '%s' "$salida" | grep 'cmd=echo uno$' | head -1)
for c in user tty from pwd rc cmd; do
    comprueba "lleva el campo $c" "si" \
        "$( printf '%s' "$linea" | grep -q "$c=" && echo si || echo no )"
done
# UNA ORDEN, UNA LINEA. Un salto de linea aqui parte el apunte del syslog en
# dos y el vigilante ve media orden. Paso de verdad: cuando no hay terminal,
# "tty" escribe "no es un `tty'" en la SALIDA ESTANDAR ---no en la de error---
# y ademas falla, asi que la forma antigua metia ese texto y un "?" con un
# salto de linea en medio.
comprueba "y ocupa UNA sola linea" "1" "$(printf '%s' "$salida" | grep -c .)"
comprueba "el tty nunca trae texto de error" "0" \
    "$(printf '%s' "$salida" | grep -c 'no es un')"

echo
echo "-------------------------------------"
echo "ok: $OK   fallos: $MAL"
[ "$MAL" -eq 0 ]
