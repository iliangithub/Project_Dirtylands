# DIONAEA

Lo que define la **identidad Windows** del segundo senuelo. Solo hay un fichero
aqui, y esta aqui por lo mismo que los modulos de Cowrie estan en su carpeta:
lo que llevamos nosotros se copia del repositorio, no se teclea en la VPS.

| Fichero | Que es |
|---|---|
| `smb.yaml` | La configuracion del servicio SMB: version de Windows, nombre de maquina, workgroup y recursos compartidos. Va a `/opt/dirtyland/dionaea/services-enabled/` (README 3.4.3.2). |

Los otros tres servicios que quedan habilitados ---`epmap`, `mssql` y `nbns`---
**no** estan aqui a proposito: se copian del contenedor en marcha con
`docker cp`, porque son los de serie de Dionaea y no dependen de nuestra
historia. Mismo criterio que con el `issue.net` de Cowrie: lo de serie se
copia de donde sale, lo de la leyenda lo llevamos nosotros.

## El detalle que se pierde al teclearlo

En `path: 'C:\Windows'` la barra invertida va **sola** y entre **comillas
simples**. En un escalar YAML sin comillas no hay escapes, asi que escribir
`C:\\Windows` produce literalmente dos barras y Dionaea anunciaria el recurso
como `C:\\Windows`. Es pequeno y muy visible para quien enumere los recursos
compartidos, y es exactamente la clase de detalle que se estropea al pegar el
fichero a mano en un editor.
