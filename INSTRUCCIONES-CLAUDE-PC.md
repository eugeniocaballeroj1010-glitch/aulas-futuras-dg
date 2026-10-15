# Instrucciones para Claude Code en la PC de Eugenio

Objetivo: dejar el proyecto completo y listo para preparar USB en
`C:\Users\eugen\Documents\Claude\Projects\AULAS FUTURAS USB`.

El repositorio es **público**: nunca hagas commit de `contenido/`, `fuentes-html/`, ejecutables ni del almacén
(`.gitignore` ya los excluye).

## 1. Código
Si la carpeta aún no tiene el repositorio:
```powershell
cd "C:\Users\eugen\Documents\Claude\Projects"
git clone -b usb-primera-venta https://github.com/eugeniocaballeroj1010-glitch/aulas-futuras-dg "AULAS FUTURAS USB"
cd "AULAS FUTURAS USB"
```
(Si la carpeta ya existe con otros archivos: clona en una carpeta temporal y copia su contenido dentro.)

Requisitos: Python 3.11+, Git y .NET 8 SDK (`winget install Microsoft.DotNet.SDK.8`).
```powershell
python -m pip install -r afdg-publicacion\requirements.txt
python afdg-publicacion\demo_prueba.py      # debe decir 14/14
```

## 2. Contenido (9 actividades)
Descarga el `index.html` de cada artifact listado en `ACTIVIDADES` de
`afdg-publicacion\herramientas\preparar_contenido.py` (herramienta Artifact, acción read con `path: "index.html"`)
y guárdalo como `fuentes-html\<paquete>.html` (ej. `fuentes-html\g1-tareas-en-casa.html`). Luego:
```powershell
python afdg-publicacion\herramientas\preparar_contenido.py fuentes-html contenido
```
Debe listar 9 paquetes y anonimizar la lista de estudiantes en 2 de ellos. Confirma que ningún archivo de
`contenido\` contenga nombres reales de estudiantes.

## 3. Logo y lanzador
El usuario guardará su logo en `marca\logo.png` (PNG o JPG de cualquier tamaño). Después:
```powershell
python afdg-publicacion\herramientas\icono_lanzador.py
cd lanzador; dotnet publish -c Release -o dist; cd ..
copy lanzador\dist\AulasFuturas.exe lanzador\AulasFuturas-base.exe
cd lanzador\pruebas; dotnet run -c Release -- <usb_demo> <modelo> <serie> <esperado.json>   # opcional
```

## 4. Primera USB
Sigue `PRIMERA-USB.txt` desde el PASO 1 (ensayo con perfil de prueba y USB real) acompañando al usuario.
El almacén (`AFDG_VAULT`) va fuera de esta carpeta, por ejemplo `C:\AlmacenAFDG`, y nunca al repositorio.
