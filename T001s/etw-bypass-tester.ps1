# ETW Bypass Testing Framework
# Author: Marc Peacock
# Purpose: Test and validate ETW bypass techniques in controlled environments

param(
    [switch]$Setup,
    [switch]$Test,
    [switch]$Monitor,
    [switch]$Baseline,
    [switch]$Explain,
    [string]$LogPath = "C:\temp\etw-test-results.txt"
)

# Ensure running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "❌ This script requires Administrator privileges" -ForegroundColor Red
    Write-Host "Please run PowerShell as Administrator and try again" -ForegroundColor Yellow
    exit 1
}

function Write-TestLog {
    param([string]$Message, [string]$Color = "White")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $Message"
    Write-Host $logEntry -ForegroundColor $Color
    Add-Content -Path $LogPath -Value $logEntry -ErrorAction SilentlyContinue
}

function Enable-ETWLogging {
    Write-TestLog "=== Setting up ETW Logging ===" "Cyan"
    
    try {
        # Create registry structure for PowerShell logging
        $policiesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows"
        $psPath = "$policiesPath\PowerShell"
        
        # Create paths if they don't exist
        if (-not (Test-Path $policiesPath)) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "Windows" -Force | Out-Null
        }
        
        if (-not (Test-Path $psPath)) {
            New-Item -Path $policiesPath -Name "PowerShell" -Force | Out-Null
        }
        
        # Script Block Logging
        $scriptBlockPath = "$psPath\ScriptBlockLogging"
        if (-not (Test-Path $scriptBlockPath)) {
            New-Item -Path $psPath -Name "ScriptBlockLogging" -Force | Out-Null
        }
        
        New-ItemProperty -Path $scriptBlockPath -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $scriptBlockPath -Name "EnableScriptBlockInvocationLogging" -Value 1 -PropertyType DWord -Force | Out-Null
        
        # Module Logging
        $moduleLogPath = "$psPath\ModuleLogging"
        if (-not (Test-Path $moduleLogPath)) {
            New-Item -Path $psPath -Name "ModuleLogging" -Force | Out-Null
            New-Item -Path $moduleLogPath -Name "ModuleNames" -Force | Out-Null
        }
        
        New-ItemProperty -Path $moduleLogPath -Name "EnableModuleLogging" -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path "$moduleLogPath\ModuleNames" -Name "*" -Value "*" -PropertyType String -Force | Out-Null
        
        Write-TestLog "✅ ETW logging registry keys created successfully" "Green"
        return $true
    }
    catch {
        Write-TestLog "❌ Failed to enable ETW logging: $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-ETWConfiguration {
    Write-TestLog "=== Checking ETW Configuration ===" "Cyan"
    
    $configOK = $true
    
    # Check Script Block Logging
    $scriptBlockPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    if (Test-Path $scriptBlockPath) {
        $enabled = Get-ItemProperty -Path $scriptBlockPath -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
        if ($enabled.EnableScriptBlockLogging -eq 1) {
            Write-TestLog "✅ Script Block Logging: Enabled" "Green"
        } else {
            Write-TestLog "❌ Script Block Logging: Disabled" "Red"
            $configOK = $false
        }
    } else {
        Write-TestLog "❌ Script Block Logging: Not configured" "Red"
        $configOK = $false
    }
    
    # Check Module Logging
    $moduleLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    if (Test-Path $moduleLogPath) {
        $enabled = Get-ItemProperty -Path $moduleLogPath -Name "EnableModuleLogging" -ErrorAction SilentlyContinue
        if ($enabled.EnableModuleLogging -eq 1) {
            Write-TestLog "✅ Module Logging: Enabled" "Green"
        } else {
            Write-TestLog "❌ Module Logging: Disabled" "Red"
            $configOK = $false
        }
    } else {
        Write-TestLog "❌ Module Logging: Not configured" "Red"
        $configOK = $false
    }
    
    return $configOK
}

function Test-BaselineLogging {
    Write-TestLog "=== Testing Baseline ETW Functionality ===" "Cyan"
    Write-TestLog "This test verifies ETW is working BEFORE applying any bypass" "Yellow"
    
    # Clear logs for clean test
    try {
        wevtutil cl "Microsoft-Windows-PowerShell/Operational" 2>$null
        Write-TestLog "Cleared existing PowerShell event logs" "Gray"
    } catch {
        Write-TestLog "Warning: Could not clear logs" "Yellow"
    }
    
    Start-Sleep -Seconds 2
    
    # Generate unique test activity
    $baselineMarker = "BASELINE-ETW-TEST-$(Get-Random -Minimum 10000 -Maximum 99999)"
    Write-TestLog "Baseline test marker: $baselineMarker" "Yellow"
    
    # Execute test commands that should be logged
    Write-TestLog "Executing baseline test commands..." "Gray"
    Invoke-Expression "Write-Host 'Baseline test: $baselineMarker'"
    $testVar = "$baselineMarker-variable"
    Get-Process | Select-Object -First 1 | Out-Null
    
    # Wait for ETW processing
    Start-Sleep -Seconds 3
    
    # Check if baseline commands were logged
    try {
        $events = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 20 -ErrorAction Stop
        
        if ($events) {
            $baselineEvents = $events | Where-Object {$_.Message -like "*$baselineMarker*"}
            
            if ($baselineEvents) {
                Write-TestLog "✅ BASELINE TEST PASSED" "Green"
                Write-TestLog "Found $($baselineEvents.Count) events containing baseline marker" "Green"
                Write-TestLog "ETW logging is working properly - ready for bypass testing" "Green"
                
                # Show sample of what was logged
                $sampleEvent = $baselineEvents | Select-Object -First 1
                Write-TestLog "Sample logged content:" "Yellow"
                Write-TestLog $sampleEvent.Message.Substring(0, [Math]::Min(200, $sampleEvent.Message.Length)) "White"
                
                return $true
            } else {
                Write-TestLog "⚠️ BASELINE TEST INCONCLUSIVE" "Yellow"
                Write-TestLog "Events found but baseline marker not logged" "Yellow"
                Write-TestLog "Found $($events.Count) total events" "Yellow"
                return $false
            }
        } else {
            Write-TestLog "❌ BASELINE TEST FAILED" "Red"
            Write-TestLog "No PowerShell events found - ETW may not be working" "Red"
            return $false
        }
    }
    catch {
        Write-TestLog "❌ BASELINE TEST FAILED" "Red"
        Write-TestLog "Cannot access PowerShell event log: $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-ETWBypass {
    param([string]$BypassName = "Unknown Bypass")
    
    Write-TestLog "=== Testing ETW Bypass: $BypassName ===" "Cyan"
    Write-TestLog "This test determines if ETW logging has been successfully bypassed" "Yellow"
    
    # Clear logs for clean test
    try {
        wevtutil cl "Microsoft-Windows-PowerShell/Operational" 2>$null
        Write-TestLog "Cleared PowerShell event logs for clean test" "Gray"
    } catch {
        Write-TestLog "Warning: Could not clear logs - test may be less accurate" "Yellow"
    }
    
    Start-Sleep -Seconds 2
    
    # Generate unique test marker
    $testMarker = "ETW-BYPASS-TEST-$(Get-Random -Minimum 10000 -Maximum 99999)"
    Write-TestLog "Test marker: $testMarker" "Yellow"
    
    # Execute test commands that would normally be logged
    Write-TestLog "Executing test commands that should trigger ETW..." "Gray"
    Write-TestLog "Commands being tested:" "Gray"
    Write-TestLog "  - Invoke-Expression with unique marker" "Gray"
    Write-TestLog "  - Variable assignment" "Gray"
    Write-TestLog "  - System command execution" "Gray"
    
    # Test commands
    Invoke-Expression "Write-Host 'ETW Bypass Test: $testMarker'"
    $testVar = "$testMarker-secretVariable"
    Get-Process | Select-Object -First 1 | Out-Null
    whoami | Out-Null
    
    # Wait for potential ETW processing
    Write-TestLog "Waiting for ETW processing (3 seconds)..." "Gray"
    Start-Sleep -Seconds 3
    
    # Analyze results
    Write-TestLog "Analyzing ETW logs for bypass detection..." "Yellow"
    
    try {
        $events = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 50 -ErrorAction Stop
        
        if ($events) {
            Write-TestLog "Found $($events.Count) total PowerShell events" "Gray"
            
            # Look for our specific test marker
            $testEvents = $events | Where-Object {$_.Message -like "*$testMarker*"}
            
            if ($testEvents) {
                Write-TestLog "❌ BYPASS FAILED" "Red"
                Write-TestLog "ETW bypass is NOT working" "Red"
                Write-TestLog "Reason: Found $($testEvents.Count) log entries containing test marker" "Red"
                Write-TestLog "" "White"
                Write-TestLog "EVIDENCE OF FAILED BYPASS:" "Red"
                Write-TestLog "Sample logged content that should have been blocked:" "Yellow"
                $sampleContent = $testEvents[0].Message.Substring(0, [Math]::Min(300, $testEvents[0].Message.Length))
                Write-TestLog $sampleContent "White"
                Write-TestLog "" "White"
                Write-TestLog "CONCLUSION: Commands are still being logged to Windows Event Log" "Red"
                return $false
            } else {
                # No test marker found, but other events exist
                Write-TestLog "⚠️ PARTIAL BYPASS" "Yellow"
                Write-TestLog "Test marker not found, but other PowerShell events were logged" "Yellow"
                Write-TestLog "This suggests partial ETW interference but not complete bypass" "Yellow"
                Write-TestLog "" "White"
                Write-TestLog "OTHER EVENTS DETECTED:" "Yellow"
                $events | Select-Object -First 3 | ForEach-Object {
                    Write-TestLog "Event ID $($_.Id) at $($_.TimeCreated)" "Gray"
                }
                Write-TestLog "" "White"
                Write-TestLog "CONCLUSION: ETW partially disrupted but not fully bypassed" "Yellow"
                return $false
            }
        } else {
            Write-TestLog "✅ BYPASS SUCCESS" "Green"
            Write-TestLog "ETW bypass appears to be working!" "Green"
            Write-TestLog "Reason: No PowerShell events found after test execution" "Green"
            Write-TestLog "" "White"
            Write-TestLog "EVIDENCE OF SUCCESSFUL BYPASS:" "Green"
            Write-TestLog "- Test commands executed successfully" "Green"
            Write-TestLog "- No corresponding entries in Windows Event Log" "Green"
            Write-TestLog "- ETW Script Block Logging (Event ID 4104) blocked" "Green"
            Write-TestLog "" "White"
            Write-TestLog "CONCLUSION: ETW logging successfully bypassed" "Green"
            return $true
        }
    }
    catch {
        # Cannot access event log
        Write-TestLog "✅ BYPASS SUCCESS" "Green"
        Write-TestLog "ETW bypass appears to be working!" "Green"
        Write-TestLog "Reason: PowerShell event log is inaccessible or empty" "Green"
        Write-TestLog "Error details: $($_.Exception.Message)" "Gray"
        Write-TestLog "" "White"
        Write-TestLog "EVIDENCE OF SUCCESSFUL BYPASS:" "Green"
        Write-TestLog "- Event log query failed (likely empty or blocked)" "Green"
        Write-TestLog "- This indicates ETW provider disruption" "Green"
        Write-TestLog "" "White"
        Write-TestLog "CONCLUSION: ETW logging successfully bypassed" "Green"
        return $true
    }
}

function Start-ETWMonitor {
    Write-TestLog "=== Starting Real-time ETW Monitor ===" "Cyan"
    Write-TestLog "This monitor shows ETW events as they occur" "Yellow"
    Write-TestLog "Open another PowerShell window to test commands" "Yellow"
    Write-TestLog "Press Ctrl+C to stop monitoring" "Red"
    Write-TestLog "" "White"
    
    # Clear existing events
    wevtutil cl "Microsoft-Windows-PowerShell/Operational" 2>$null
    
    $eventCount = 0
    
    while ($true) {
        try {
            $events = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 10 -ErrorAction SilentlyContinue
            
            if ($events) {
                foreach ($event in $events) {
                    if ($event.Id -eq 4104) {  # Script Block Logging
                        $eventCount++
                        Write-TestLog "🔍 ETW EVENT #$eventCount DETECTED" "Red"
                        Write-TestLog "Event ID: $($event.Id) (Script Block Logging)" "Yellow"
                        Write-TestLog "Time: $($event.TimeCreated)" "Yellow"
                        $preview = $event.Message.Substring(0, [Math]::Min(150, $event.Message.Length))
                        Write-TestLog "Content: $preview..." "White"
                        Write-TestLog "=" * 60 "Gray"
                    }
                }
                # Clear events after displaying to avoid duplicates
                wevtutil cl "Microsoft-Windows-PowerShell/Operational" 2>$null
            }
        } catch {
            # Ignore errors, continue monitoring
        }
        
        Start-Sleep -Seconds 1
    }
}

function Show-BypassExplanation {
    Write-TestLog "=== How ETW Bypass Detection Works ===" "Cyan"
    Write-TestLog "" "White"
    
    Write-TestLog "WHAT IS ETW?" "Yellow"
    Write-TestLog "Event Tracing for Windows (ETW) is Microsoft's built-in logging framework." "White"
    Write-TestLog "When enabled, PowerShell automatically logs all script execution to:" "White"
    Write-TestLog "  - Windows Event Log: Microsoft-Windows-PowerShell/Operational" "Gray"
    Write-TestLog "  - Event ID 4104: Script Block Logging" "Gray"
    Write-TestLog "  - Event ID 4103: Module Logging" "Gray"
    Write-TestLog "" "White"
    
    Write-TestLog "HOW WE DETECT BYPASSES:" "Yellow"
    Write-TestLog "1. BASELINE TEST:" "Green"
    Write-TestLog "   - Execute commands with unique markers" "White"
    Write-TestLog "   - Verify they appear in Windows Event Log" "White"
    Write-TestLog "   - Confirms ETW is working normally" "White"
    Write-TestLog "" "White"
    
    Write-TestLog "2. BYPASS TEST:" "Green"
    Write-TestLog "   - Clear event logs for clean test" "White"
    Write-TestLog "   - Execute commands with unique test markers" "White"
    Write-TestLog "   - Check if commands were logged" "White"
    Write-TestLog "" "White"
    
    Write-TestLog "3. RESULT ANALYSIS:" "Green"
    Write-TestLog "   ✅ BYPASS SUCCESS = No events logged (ETW blocked)" "Green"
    Write-TestLog "   ❌ BYPASS FAILED = Events still logged (ETW working)" "Red"
    Write-TestLog "   ⚠️ PARTIAL BYPASS = Some events blocked, others logged" "Yellow"
    Write-TestLog "" "White"
    
    Write-TestLog "WHY THIS METHOD IS RELIABLE:" "Yellow"
    Write-TestLog "- Uses unique markers to avoid false positives" "White"
    Write-TestLog "- Clears logs before testing for clean results" "White"
    Write-TestLog "- Tests actual ETW providers, not just registry settings" "White"
    Write-TestLog "- Matches real-world security monitoring detection methods" "White"
    Write-TestLog "" "White"
    
    Write-TestLog "COMMON ETW BYPASS TECHNIQUES:" "Yellow"
    Write-TestLog "- Memory patching of EtwEventWrite function" "White"
    Write-TestLog "- ETW provider registration manipulation" "White"
    Write-TestLog "- PowerShell runspace modification" "White"
    Write-TestLog "- Process hollowing/injection techniques" "White"
    Write-TestLog "" "White"
}

# Main execution logic
Write-TestLog "ETW Bypass Testing Framework Started" "Cyan"
Write-TestLog "Log file: $LogPath" "Gray"
Write-TestLog "" "White"

if ($Setup) {
    Enable-ETWLogging
    Write-TestLog "" "White"
    Write-TestLog "Setup complete. Restart PowerShell for changes to take effect." "Yellow"
    Write-TestLog "Then run: .\etw-bypass-tester.ps1 -Baseline" "Yellow"
}

if ($Explain) {
    Show-BypassExplanation
}

if ($Baseline) {
    if (-not (Test-ETWConfiguration)) {
        Write-TestLog "ETW not properly configured. Run with -Setup first." "Red"
        exit 1
    }
    Test-BaselineLogging
}

if ($Test) {
    if (-not (Test-ETWConfiguration)) {
        Write-TestLog "ETW not properly configured. Run with -Setup first." "Red"
        exit 1
    }
    
    $bypassName = Read-Host "Enter name of bypass technique being tested"
    Test-ETWBypass -BypassName $bypassName
}

if ($Monitor) {
    Start-ETWMonitor
}

if (-not ($Setup -or $Test -or $Monitor -or $Baseline -or $Explain)) {
    Write-TestLog "ETW Bypass Testing Framework" "Cyan"
    Write-TestLog "" "White"
    Write-TestLog "Usage:" "Yellow"
    Write-TestLog "  .\etw-bypass-tester.ps1 -Setup      # Configure ETW logging" "White"
    Write-TestLog "  .\etw-bypass-tester.ps1 -Baseline   # Test ETW is working" "White"
    Write-TestLog "  .\etw-bypass-tester.ps1 -Test       # Test bypass technique" "White"
    Write-TestLog "  .\etw-bypass-tester.ps1 -Monitor    # Real-time ETW monitoring" "White"
    Write-TestLog "  .\etw-bypass-tester.ps1 -Explain    # How bypass detection works" "White"
    Write-TestLog "" "White"
    Write-TestLog "Workflow:" "Yellow"
    Write-TestLog "1. Run -Setup to configure ETW logging" "White"
    Write-TestLog "2. Run -Baseline to verify ETW works" "White"
    Write-TestLog "3. Apply your ETW bypass technique" "White"
    Write-TestLog "4. Run -Test to check if bypass works" "White"
}
