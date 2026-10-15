using System.Diagnostics;
using System.Drawing;
using System.Text;
using System.Text.Json;
using Microsoft.Web.WebView2.Core;
using static AulasFuturas.Win32;

namespace AulasFuturas;

static class Program
{
    public const string Version = "1.0.0";
    const string Titulo = "Aulas Futuras DG", Dominio = Portal.Dominio, PortalUrl = Portal.Url;

    static WndProc? proc; // referencia viva para el GC
    static IntPtr hwnd;
    static UiContext? ui;
    static CoreWebView2Environment? env;
    static CoreWebView2Controller? ctl;
    static Unidad? unidad;
    static string raiz = "";
    static readonly Dictionary<string, Dictionary<string, byte[]>> contenido = new();

    static void Error(string code, string detalle = "")
    {
        var msg = LaunchError.Mensajes.TryGetValue(code, out var m) ? m : "Error inesperado.";
        var extra = code == "W01"
            ? "\n\nInstálelo una sola vez desde:\nhttps://go.microsoft.com/fwlink/p/?LinkId=2124703"
            : "\n\nSi el problema continúa, comuníquese con soporte e indique este código.";
        MessageBoxW(hwnd, $"Código {code}\n\n{msg}{extra}" + (detalle.Length > 0 ? $"\n\nDetalle: {detalle}" : ""),
                    Titulo, MB_ICONERROR | MB_TOPMOST);
    }

    static byte[] ColaEjecutable(string exe)
    {
        using var f = File.OpenRead(exe);
        long n = Math.Min(f.Length, 2L << 20);
        f.Seek(-n, SeekOrigin.End);
        var b = new byte[n];
        f.ReadExactly(b);
        return b;
    }

    [STAThread]
    static int Main()
    {
        var exe = Environment.ProcessPath!;
        raiz = Path.GetDirectoryName(exe)!;
        try
        {
            var sello = Nucleo.LeerSello(ColaEjecutable(exe)) ?? throw new LaunchError("L02", "lanzador sin sello");
            (string, string, string) id;
            try { id = Usb.Identidad(raiz); }
            catch (Exception e) { throw new LaunchError("L01", e.Message); }
            unidad = Nucleo.Abrir(raiz, id, sello, Version);
            foreach (var p in unidad.Paquetes) contenido[p.Id] = unidad.Archivos(p.Id); // falla cerrado antes de mostrar nada
            try { CoreWebView2Environment.GetAvailableBrowserVersionString(); }
            catch (WebView2RuntimeNotFoundException) { throw new LaunchError("W01"); }

            using var unico = new Mutex(true, "AulasFuturasDG-" + unidad.Id, out bool primero);
            if (!primero)
            {
                MessageBoxW(IntPtr.Zero, "Aulas Futuras DG ya está abierto en esta computadora.", Titulo, MB_ICONWARNING);
                return 0;
            }
            return Ejecutar(sello.Perfil == "prod");
        }
        catch (LaunchError e)
        {
            Error(e.Code, e.Detalle);
            return 1;
        }
    }

    static int Ejecutar(bool prod)
    {
        var inst = GetModuleHandleW(null);
        proc = WndProcImpl;
        var wc = new WNDCLASSEXW
        {
            cbSize = System.Runtime.InteropServices.Marshal.SizeOf<WNDCLASSEXW>(),
            lpfnWndProc = System.Runtime.InteropServices.Marshal.GetFunctionPointerForDelegate(proc),
            hInstance = inst, hIcon = LoadIconW(inst, new IntPtr(32512)), hCursor = LoadCursorW(IntPtr.Zero, new IntPtr(32512)),
            hbrBackground = new IntPtr(6), lpszClassName = "AulasFuturasDG",
        };
        RegisterClassExW(ref wc);
        hwnd = CreateWindowExW(0, wc.lpszClassName, Titulo, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 1280, 800,
                               IntPtr.Zero, IntPtr.Zero, inst, IntPtr.Zero);
        var ico = Path.Combine(raiz, "logo.ico");
        if (File.Exists(ico))
            foreach (var (tipo, lado) in new[] { (1, 0), (0, 16) }) // ICON_BIG, ICON_SMALL
            {
                var h = LoadImageW(IntPtr.Zero, ico, 1, lado, lado, 0x10 | (lado == 0 ? 0x40u : 0u)); // LR_LOADFROMFILE | LR_DEFAULTSIZE
                if (h != IntPtr.Zero) SendMessageW(hwnd, 0x0080, new IntPtr(tipo), h); // WM_SETICON
            }
        ui = new UiContext(hwnd);
        SynchronizationContext.SetSynchronizationContext(ui);
        ShowWindow(hwnd, SW_SHOWMAXIMIZED);
        SetTimer(hwnd, new IntPtr(1), 3000, IntPtr.Zero);
        _ = IniciarWebView(prod);
        while (GetMessageW(out var msg, IntPtr.Zero, 0, 0) > 0)
        {
            TranslateMessage(ref msg);
            DispatchMessageW(ref msg);
        }
        return 0;
    }

    static IntPtr WndProcImpl(IntPtr h, uint msg, IntPtr w, IntPtr l)
    {
        switch (msg)
        {
            case WM_APP_RUN: ui?.Ejecutar(); return IntPtr.Zero;
            case WM_SIZE: Ajustar(); break;
            case WM_MOVE: ctl?.NotifyParentWindowPositionChanged(); break;
            case WM_SETFOCUS: ctl?.MoveFocus(CoreWebView2MoveFocusReason.Programmatic); break;
            case WM_DPICHANGED:
                var r = System.Runtime.InteropServices.Marshal.PtrToStructure<RECT>(l);
                SetWindowPos(h, IntPtr.Zero, r.Left, r.Top, r.Right - r.Left, r.Bottom - r.Top, 0x0014);
                return IntPtr.Zero;
            case WM_TIMER:
                if (!File.Exists(Path.Combine(raiz, "license.afl")))
                {
                    ctl?.Close(); ctl = null;
                    MessageBoxW(h, "Se retiró la memoria USB. Vuelva a conectarla y abra Aulas Futuras otra vez.", Titulo, MB_ICONWARNING);
                    DestroyWindow(h);
                }
                return IntPtr.Zero;
            case WM_CLOSE: ctl?.Close(); ctl = null; DestroyWindow(h); return IntPtr.Zero;
            case WM_DESTROY: PostQuitMessage(0); return IntPtr.Zero;
        }
        return DefWindowProcW(h, msg, w, l);
    }

    static void Ajustar()
    {
        if (ctl == null) return;
        GetClientRect(hwnd, out var r);
        ctl.Bounds = new Rectangle(0, 0, r.Right - r.Left, r.Bottom - r.Top);
    }

    static async Task IniciarWebView(bool prod)
    {
        try
        {
            var datos = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AulasFuturasDG", unidad!.Id);
            env = await CoreWebView2Environment.CreateAsync(null, datos,
                new CoreWebView2EnvironmentOptions("--disable-features=msSmartScreenProtection,msEdgeTranslate") { Language = "es" });
            ctl = await env.CreateCoreWebView2ControllerAsync(hwnd);
            var wv = ctl.CoreWebView2;
            var s = wv.Settings;
            s.AreDevToolsEnabled = !prod;
            s.AreDefaultContextMenusEnabled = !prod;
            s.AreBrowserAcceleratorKeysEnabled = !prod;
            s.IsStatusBarEnabled = false;
            s.IsPasswordAutosaveEnabled = false;
            s.IsGeneralAutofillEnabled = false;
            s.IsSwipeNavigationEnabled = false;
            wv.AddWebResourceRequestedFilter("*", CoreWebView2WebResourceContext.All);
            wv.WebResourceRequested += Servir;
            wv.NavigationStarting += (_, e) =>
            {
                if (!EsPropio(e.Uri)) { e.Cancel = true; AbrirFuera(e.Uri); }
            };
            wv.NewWindowRequested += (_, e) =>
            {
                e.Handled = true;
                if (EsPropio(e.Uri)) wv.Navigate(e.Uri); else AbrirFuera(e.Uri);
            };
            wv.WebMessageReceived += (_, e) =>
            {
                if (e.Source.StartsWith(PortalUrl, StringComparison.Ordinal) && e.TryGetWebMessageAsString() == "salir")
                    PostMessageW(hwnd, WM_CLOSE, IntPtr.Zero, IntPtr.Zero);
            };
            await wv.AddScriptToExecuteOnDocumentCreatedAsync(Portal.ScriptActividad(unidad!, PortalUrl));
            Ajustar();
            ctl.IsVisible = true;
            ctl.MoveFocus(CoreWebView2MoveFocusReason.Programmatic);
            wv.Navigate(PortalUrl);
        }
        catch (Exception e)
        {
            Error("W01", e.Message);
            PostMessageW(hwnd, WM_CLOSE, IntPtr.Zero, IntPtr.Zero);
        }
    }

    static bool EsPropio(string uri) =>
        Uri.TryCreate(uri, UriKind.Absolute, out var u) && u.Scheme == "https" && u.Host.EndsWith(Dominio, StringComparison.Ordinal)
        || uri.StartsWith("about:", StringComparison.Ordinal) || uri.StartsWith("data:", StringComparison.Ordinal);

    static void AbrirFuera(string uri)
    {
        if (Uri.TryCreate(uri, UriKind.Absolute, out var u) && (u.Scheme == "https" || u.Scheme == "http"))
            try { Process.Start(new ProcessStartInfo(u.AbsoluteUri) { UseShellExecute = true }); } catch { /* sin navegador */ }
    }

    static readonly Dictionary<string, string> Mime = new(StringComparer.OrdinalIgnoreCase)
    {
        [".html"] = "text/html; charset=utf-8", [".htm"] = "text/html; charset=utf-8", [".css"] = "text/css; charset=utf-8",
        [".js"] = "text/javascript; charset=utf-8", [".mjs"] = "text/javascript; charset=utf-8",
        [".json"] = "application/json; charset=utf-8", [".txt"] = "text/plain; charset=utf-8", [".svg"] = "image/svg+xml",
        [".png"] = "image/png", [".jpg"] = "image/jpeg", [".jpeg"] = "image/jpeg", [".gif"] = "image/gif",
        [".webp"] = "image/webp", [".ico"] = "image/x-icon", [".mp3"] = "audio/mpeg", [".ogg"] = "audio/ogg",
        [".wav"] = "audio/wav", [".m4a"] = "audio/mp4", [".mp4"] = "video/mp4", [".webm"] = "video/webm",
        [".woff"] = "font/woff", [".woff2"] = "font/woff2", [".ttf"] = "font/ttf", [".otf"] = "font/otf",
    };

    static void Servir(object? _, CoreWebView2WebResourceRequestedEventArgs e)
    {
        Uri u;
        try { u = new Uri(e.Request.Uri); } catch (UriFormatException) { return; }
        if (u.Scheme is not ("http" or "https")) return;
        if (!u.Host.EndsWith(Dominio, StringComparison.Ordinal))
        {
            e.Response = env!.CreateWebResourceResponse(null, 403, "Sin conexion", ""); // todo es offline
            return;
        }
        var sub = u.Host[..^Dominio.Length];
        var ruta = Uri.UnescapeDataString(u.AbsolutePath).TrimStart('/');
        if (ruta.Length == 0 || ruta.EndsWith('/')) ruta += "index.html";
        byte[]? datos = null;
        if (sub == "portal" && ruta == "index.html") datos = Encoding.UTF8.GetBytes(Portal.Html(unidad!, Version));
        else if (sub == "portal" && ruta == "logo.png" && File.Exists(Path.Combine(raiz, "logo.png")))
            datos = File.ReadAllBytes(Path.Combine(raiz, "logo.png"));
        else if (contenido.TryGetValue(sub, out var archivos)) archivos.TryGetValue(ruta, out datos);
        if (datos == null)
        {
            e.Response = env!.CreateWebResourceResponse(null, 404, "No encontrado", "");
            return;
        }
        var tipo = Mime.TryGetValue(Path.GetExtension(ruta), out var t) ? t : "application/octet-stream";
        e.Response = env!.CreateWebResourceResponse(new MemoryStream(datos, false), 200, "OK",
            $"Content-Type: {tipo}\r\nCache-Control: no-store\r\nAccess-Control-Allow-Origin: *");
    }

}
