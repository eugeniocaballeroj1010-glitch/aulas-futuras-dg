using System.Net;
using System.Text;
using System.Text.Json;

namespace AulasFuturas;

/// <summary>Menú principal y script inyectado en cada actividad (sin dependencias de Windows).</summary>
public static class Portal
{
    public const string Dominio = ".afdg.example", Url = "https://portal.afdg.example/";

    public static string ScriptActividad(Unidad unidad, string portal)
    {
        var marca = JsonSerializer.Serialize($"{unidad.Id} · {unidad.Cliente}");
        return $$"""
        (() => {
          if (location.hostname === 'portal.afdg.example' || !location.hostname.endsWith('.afdg.example')) return;
          const poner = () => {
            if (document.getElementById('afdg-inicio')) return;
            const b = document.createElement('a');
            b.id = 'afdg-inicio'; b.href = '{{portal}}'; b.textContent = '🏠';
            b.title = 'Volver al menú'; b.setAttribute('aria-label', 'Volver al menú');
            b.style.cssText = 'position:fixed;left:12px;bottom:12px;z-index:2147483647;width:52px;height:52px;border-radius:50%;' +
              'display:flex;align-items:center;justify-content:center;font-size:26px;text-decoration:none;' +
              'background:#1d4ed8;color:#fff;box-shadow:0 4px 12px rgba(0,0,0,.25);opacity:.88';
            const w = document.createElement('div');
            w.textContent = {{marca}};
            w.style.cssText = 'position:fixed;right:8px;bottom:4px;z-index:2147483647;font:11px system-ui,sans-serif;' +
              'color:#000;opacity:.35;pointer-events:none;user-select:none';
            document.body.append(b, w);
          };
          if (document.readyState === 'loading') addEventListener('DOMContentLoaded', poner); else poner();
        })();
        """;
    }

    static string Grado(int? g) => g switch
    {
        null => "Para todos",
        1 or 3 => $"{g}.er grado",
        _ => $"{g}.º grado",
    };

    public static string Html(Unidad unidad, string version)
    {
        static string H(string s) => WebUtility.HtmlEncode(s);
        var sb = new StringBuilder();
        foreach (var grupo in unidad.Paquetes.OrderBy(p => p.Grado ?? 99).ThenBy(p => p.Titulo).GroupBy(p => p.Grado))
        {
            sb.Append($"<section><h2>{H(Grado(grupo.Key))}</h2><div class=grid>");
            foreach (var p in grupo)
                sb.Append($"<div class=card><a href=\"https://{p.Id}{Dominio}/\"><span class=ico aria-hidden=true>{H(p.Icono)}</span>" +
                          $"<span class=tit>{H(p.Titulo)}</span></a><button class=voz data-t=\"{H(p.Titulo)}\" aria-label=\"Escuchar: {H(p.Titulo)}\">🔊</button></div>");
            sb.Append("</div></section>");
        }
        return $$$"""
        <!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
        <title>Aulas Futuras DG</title><style>
        :root{--fondo:#fff8ec;--tinta:#1f2937;--suave:#6b7280;--azul:#1d4ed8;--borde:#f1d9b5}
        *{box-sizing:border-box}body{margin:0;font-family:"Segoe UI",system-ui,sans-serif;background:var(--fondo);color:var(--tinta)}
        header{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:20px 28px;background:#fff;border-bottom:3px solid var(--borde)}
        .marca{display:flex;align-items:center;gap:16px}.logo{width:72px;height:72px;border-radius:18px;object-fit:contain}
        h1{margin:0;font-size:clamp(22px,3vw,32px);color:var(--azul)}header p{margin:4px 0 0;font-size:18px;color:var(--suave)}
        main{max-width:1200px;margin:0 auto;padding:16px 24px 80px}h2{font-size:24px;margin:28px 0 12px}
        .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:18px}
        .card{position:relative;background:#fff;border:3px solid var(--borde);border-radius:22px;transition:transform .12s,border-color .12s}
        .card:hover,.card:focus-within{transform:translateY(-3px);border-color:var(--azul)}
        .card a{display:flex;flex-direction:column;align-items:center;gap:10px;padding:26px 14px 22px;color:inherit;text-decoration:none;text-align:center;border-radius:20px;min-height:180px}
        .ico{font-size:60px;line-height:1}.tit{font-size:20px;font-weight:700}
        .voz{position:absolute;top:8px;right:8px;width:44px;height:44px;border:0;border-radius:50%;background:#eef2ff;font-size:20px;cursor:pointer}
        a:focus-visible,button:focus-visible{outline:4px solid #f59e0b;outline-offset:2px}
        .salir{font-size:18px;padding:12px 22px;border-radius:14px;border:2px solid var(--borde);background:#fff;cursor:pointer;min-height:48px}
        footer{position:fixed;bottom:0;left:0;right:0;padding:8px 24px;font-size:13px;color:var(--suave);background:#fffdf8;border-top:1px solid var(--borde)}
        @media (max-width:600px){header{padding:16px}main{padding:8px 16px 80px}.grid{grid-template-columns:repeat(2,1fr);gap:12px}.card a{min-height:130px;padding:20px 10px 16px}.ico{font-size:44px}.tit{font-size:17px}.logo{width:52px;height:52px}}
        @media (prefers-reduced-motion:reduce){.card{transition:none}}
        </style></head><body>
        <header><div class=marca><img class=logo src="logo.png" alt="" onerror="this.remove()"><div><h1>Aulas Futuras DG</h1><p>¿Qué vamos a aprender hoy?</p></div></div><button class=salir id=salir>Salir</button></header>
        <main>{{{sb}}}</main>
        <footer>Unidad {{{H(unidad.Id)}}} · Versión del programa {{{version}}}</footer>
        <script>
        document.getElementById('salir').onclick=()=>window.chrome?.webview?.postMessage('salir');
        document.addEventListener('click',e=>{const b=e.target.closest('.voz');if(!b||!('speechSynthesis'in window))return;
          speechSynthesis.cancel();const u=new SpeechSynthesisUtterance(b.dataset.t);u.lang='es-ES';u.rate=.9;speechSynthesis.speak(u);});
        </script></body></html>
        """;
    }
}
