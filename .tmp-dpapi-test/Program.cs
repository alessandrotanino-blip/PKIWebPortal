using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

struct CRYPTOIDATA_BLOB
{
    public uint cbData;
    public IntPtr pbData;
    public uint dwReserved;
}

class Program
{
    const uint LOCAL_MACHINE = 0x4;
    const uint UI_FORBIDDEN = 0x1;

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CryptProtectData(ref CRYPTOIDATA_BLOB inB, string? d, IntPtr ent, IntPtr r, IntPtr p, uint f, ref CRYPTOIDATA_BLOB outB);

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CryptUnprotectData(ref CRYPTOIDATA_BLOB inB, out string? d, IntPtr ent, IntPtr r, IntPtr p, uint f, ref CRYPTOIDATA_BLOB outB);

    static byte[] Transform(byte[] input, byte[] entropy, bool protect)
    {
        IntPtr inPtr = Marshal.AllocHGlobal(input.Length);
        IntPtr entPtr = Marshal.AllocHGlobal(entropy.Length);
        try
        {
            Marshal.Copy(input, 0, inPtr, input.Length);
            Marshal.Copy(entropy, 0, entPtr, entropy.Length);
            var inB = new CRYPTOIDATA_BLOB { cbData = (uint)input.Length, pbData = inPtr, dwReserved = 0 };
            var outB = new CRYPTOIDATA_BLOB();
            uint flags = LOCAL_MACHINE | UI_FORBIDDEN;
            bool ok = protect
                ? CryptProtectData(ref inB, "PkiPortal.PrivateKey", entPtr, IntPtr.Zero, IntPtr.Zero, flags, ref outB)
                : CryptUnprotectData(ref inB, out _, entPtr, IntPtr.Zero, IntPtr.Zero, flags, ref outB);
            if (!ok) throw new CryptographicException($"DPAPI failed (Win32 {Marshal.GetLastWin32Error()})");
            var outBytes = new byte[outB.cbData];
            Marshal.Copy(outB.pbData, outBytes, 0, outBytes.Length);
            Marshal.FreeHGlobal(outB.pbData);
            return outBytes;
        }
        finally
        {
            Marshal.FreeHGlobal(inPtr);
            Marshal.FreeHGlobal(entPtr);
        }
    }

    static void Main()
    {
        var entropy = RandomNumberGenerator.GetBytes(32);
        var secret = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----";
        var cipher = Convert.ToBase64String(Transform(Encoding.UTF8.GetBytes(secret), entropy, true));
        Console.WriteLine($"CIPHER OK ({cipher.Length} chars): {cipher.Substring(0, 32)}...");
        var decrypted = Encoding.UTF8.GetString(Transform(Convert.FromBase64String(cipher), entropy, false));
        Console.WriteLine(decrypted == secret ? "ROUND-TRIP OK" : "ROUND-TRIP FAILED");
        var entropy2 = RandomNumberGenerator.GetBytes(32);
        try
        {
            Transform(Convert.FromBase64String(cipher), entropy2, false);
            Console.WriteLine("WRONG-ENTROPY: UNEXPECTED SUCCESS");
        }
        catch (CryptographicException)
        {
            Console.WriteLine("WRONG-ENTROPY REJECTED OK");
        }
    }
}
