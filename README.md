# Aulas Futuras DG — USB offline

Contenido educativo interactivo en memorias USB, sin internet, con licencia atada a cada memoria.

| Carpeta | Qué contiene |
|---|---|
| `afdg-publicacion/` | Herramientas en Python: almacén y emisión de licencias (`afdg_emisor.py`), revisión, copia maestra, preparación y verificación de unidades (`afdg_publicar.py`), demo automática (`demo_prueba.py`) |
| `lanzador/` | `AulasFuturas.exe` (.NET 8 + WebView2): verifica la USB y la licencia, descifra en memoria y muestra el menú de actividades |
| `lanzador/pruebas/` | Pruebas cruzadas del núcleo C# contra imágenes generadas por Python |

El contenido de pago (`contenido/`) y todos los secretos están excluidos del repositorio (`.gitignore`).

## Seguridad en breve
- Licencia Ed25519 atada al modelo y número de serie del dispositivo USB (IOCTL, sin admin).
- Paquetes cifrados con ChaCha20-Poly1305 por bloques; clave de contenido envuelta por unidad (HKDF).
- El lanzador base no contiene secretos; `afdg_emisor.py sellar-lanzador` le agrega claves públicas, pepper ofuscado y revocaciones en la estación emisora.
- Falla cerrado con códigos L01, L02, L03, P01, P02 y W01 (falta WebView2).

## Uso
Guía paso a paso: `PRIMERA-USB.txt` (en el kit). Comprobación rápida:

```powershell
cd afdg-publicacion
python -m pip install -r requirements.txt
python demo_prueba.py            # 14/14 comprobaciones correctas
```

Compilar el lanzador (Windows o Linux con .NET 8 SDK):

```bash
cd lanzador
dotnet publish -c Release -o dist   # dist/AulasFuturas.exe (base, sin sellar)
```

GitHub Actions (`.github/workflows/lanzador.yml`) ejecuta la demo y las pruebas cruzadas en Windows y publica el `.exe` base como artefacto.
