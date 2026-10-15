// Identidad física del disco: misma lectura que afdg_crypto._win_identity (IOCTL, sin permisos de administrador).
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace AulasFuturas;

public static class Usb
{
    static readonly char[] Ws = [' ', '\t', '\r', '\n', '\0']; // mismo recorte que afdg_crypto.WS
    static readonly Dictionary<uint, string> Buses = new()
    {
        [1] = "SCSI", [2] = "ATAPI", [3] = "ATA", [7] = "USB", [8] = "RAID", [10] = "SAS",
        [11] = "SATA", [12] = "SD", [13] = "MMC", [17] = "NVME",
    };

    [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr sa, uint disp, uint flags, IntPtr tmpl);

    [DllImport("kernel32", SetLastError = true)]
    static extern bool DeviceIoControl(SafeFileHandle h, uint code, byte[]? inBuf, int inSize, byte[] outBuf, int outSize,
                                       out int returned, IntPtr overlapped);

    [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool GetVolumePathNameW(string path, StringBuilder volume, int len);

    static SafeFileHandle Abrir(string ruta)
    {
        var h = CreateFileW(ruta, 0, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (h.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), ruta);
        return h;
    }

    static byte[] Ioctl(SafeFileHandle h, uint code, byte[]? input, int outSize)
    {
        var out_ = new byte[outSize];
        if (!DeviceIoControl(h, code, input, input?.Length ?? 0, out_, outSize, out var n, IntPtr.Zero))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        return out_[..n];
    }

    static string Cadena(byte[] d, uint off)
    {
        if (off == 0 || off >= d.Length) return "";
        int end = Array.IndexOf(d, (byte)0, (int)off);
        if (end < 0) end = d.Length;
        return Encoding.ASCII.GetString(d, (int)off, end - (int)off).Trim(Ws);
    }

    public static (string Bus, string Modelo, string Serie) Identidad(string ruta)
    {
        var vol = new StringBuilder(260);
        if (!GetVolumePathNameW(Path.GetFullPath(ruta), vol, vol.Capacity))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        var letra = vol.ToString().TrimEnd('\\');
        uint numero;
        using (var hv = Abrir(@"\\.\" + letra))
            numero = BitConverter.ToUInt32(Ioctl(hv, 0x2D1080, null, 12), 4); // IOCTL_STORAGE_GET_DEVICE_NUMBER
        byte[] d;
        using (var hd = Abrir(@"\\.\PhysicalDrive" + numero))
            d = Ioctl(hd, 0x2D1400, new byte[12], 4096); // IOCTL_STORAGE_QUERY_PROPERTY, StorageDeviceProperty
        uint U(int o) => BitConverter.ToUInt32(d, o);
        var bus = Buses.TryGetValue(U(28), out var b) ? b : $"BUS{U(28)}";
        var modelo = $"{Cadena(d, U(12))} {Cadena(d, U(16))}".Trim(Ws);
        return (bus, modelo, Cadena(d, U(24)));
    }
}
