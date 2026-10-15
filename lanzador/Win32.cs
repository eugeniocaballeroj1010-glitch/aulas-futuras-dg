using System.Collections.Concurrent;
using System.Runtime.InteropServices;

namespace AulasFuturas;

static class Win32
{
    public const uint WM_DESTROY = 0x0002, WM_MOVE = 0x0003, WM_SIZE = 0x0005, WM_SETFOCUS = 0x0007, WM_CLOSE = 0x0010,
        WM_TIMER = 0x0113, WM_DPICHANGED = 0x02E0, WM_APP_RUN = 0x8001;
    public const uint WS_OVERLAPPEDWINDOW = 0x00CF0000, MB_ICONERROR = 0x10, MB_ICONWARNING = 0x30, MB_TOPMOST = 0x40000;
    public const int CW_USEDEFAULT = unchecked((int)0x80000000), SW_SHOWMAXIMIZED = 3;

    public delegate IntPtr WndProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WNDCLASSEXW
    {
        public int cbSize; public uint style; public IntPtr lpfnWndProc; public int cbClsExtra, cbWndExtra;
        public IntPtr hInstance, hIcon, hCursor, hbrBackground; public string? lpszMenuName; public string lpszClassName; public IntPtr hIconSm;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MSG { public IntPtr hwnd; public uint message; public IntPtr wParam, lParam; public uint time; public int x, y; }

    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left, Top, Right, Bottom; }

    [DllImport("user32", CharSet = CharSet.Unicode, SetLastError = true)] public static extern ushort RegisterClassExW(ref WNDCLASSEXW wc);
    [DllImport("user32", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateWindowExW(uint exStyle, string cls, string title, uint style, int x, int y, int w, int h,
                                                IntPtr parent, IntPtr menu, IntPtr inst, IntPtr param);
    [DllImport("user32", CharSet = CharSet.Unicode)] public static extern IntPtr DefWindowProcW(IntPtr h, uint m, IntPtr w, IntPtr l);
    [DllImport("user32", CharSet = CharSet.Unicode)] public static extern int GetMessageW(out MSG m, IntPtr h, uint min, uint max);
    [DllImport("user32")] public static extern bool TranslateMessage(ref MSG m);
    [DllImport("user32", CharSet = CharSet.Unicode)] public static extern IntPtr DispatchMessageW(ref MSG m);
    [DllImport("user32", CharSet = CharSet.Unicode)] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
    [DllImport("user32")] public static extern void PostQuitMessage(int code);
    [DllImport("user32")] public static extern bool ShowWindow(IntPtr h, int cmd);
    [DllImport("user32")] public static extern bool DestroyWindow(IntPtr h);
    [DllImport("user32")] public static extern bool GetClientRect(IntPtr h, out RECT r);
    [DllImport("user32")] public static extern bool SetWindowPos(IntPtr h, IntPtr after, int x, int y, int w, int hh, uint flags);
    [DllImport("user32")] public static extern IntPtr SetTimer(IntPtr h, IntPtr id, uint ms, IntPtr fn);
    [DllImport("user32", CharSet = CharSet.Unicode)] public static extern int MessageBoxW(IntPtr h, string text, string caption, uint type);
    [DllImport("user32", CharSet = CharSet.Unicode)] public static extern IntPtr LoadIconW(IntPtr inst, IntPtr name);
    [DllImport("user32", CharSet = CharSet.Unicode)] public static extern IntPtr LoadCursorW(IntPtr inst, IntPtr name);
    [DllImport("user32", CharSet = CharSet.Unicode)] public static extern IntPtr LoadImageW(IntPtr inst, string name, uint type, int cx, int cy, uint load);
    [DllImport("user32", CharSet = CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
    [DllImport("kernel32", CharSet = CharSet.Unicode)] public static extern IntPtr GetModuleHandleW(string? name);
}

/// <summary>Contexto de sincronización sobre el bucle de mensajes Win32 (necesario para async/await con WebView2).</summary>
sealed class UiContext(IntPtr hwnd) : SynchronizationContext
{
    readonly ConcurrentQueue<(SendOrPostCallback Cb, object? St)> cola = new();

    public override void Post(SendOrPostCallback d, object? state)
    {
        cola.Enqueue((d, state));
        Win32.PostMessageW(hwnd, Win32.WM_APP_RUN, IntPtr.Zero, IntPtr.Zero);
    }

    public override void Send(SendOrPostCallback d, object? state) => d(state);

    public void Ejecutar()
    {
        while (cola.TryDequeue(out var x)) x.Cb(x.St);
    }
}
