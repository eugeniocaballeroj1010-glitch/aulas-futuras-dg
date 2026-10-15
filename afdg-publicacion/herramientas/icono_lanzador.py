"""Genera lanzador/app.ico desde marca/logo.png (recorta el borde blanco). Luego recompile el lanzador."""
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from afdg_publicar import preparar_logo

raiz = pathlib.Path(__file__).resolve().parents[2]
logo = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else raiz / "marca" / "logo.png"
_, ico, lado = preparar_logo(logo.read_bytes())
(raiz / "lanzador" / "app.ico").write_bytes(ico)
print(f"lanzador/app.ico generado desde {logo.name} ({lado} px). Recompile: cd lanzador; dotnet publish -c Release -o dist")
