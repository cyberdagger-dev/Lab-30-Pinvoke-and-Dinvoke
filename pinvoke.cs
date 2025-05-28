// C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /target:exe /out:pinvoke.exe pinvoke.cs /Platform:x64

using System;
using System.Runtime.InteropServices;

public class Program
{
    [DllImport("user32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern int MessageBoxA(IntPtr hWnd, string lpText, string lpCaption, uint uType);

    public static void Main(string[] args)
    {
        MessageBoxA(IntPtr.Zero, "Hi from Pinvoke", "WKLSEC", 0);
    }
}
