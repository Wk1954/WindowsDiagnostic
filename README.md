<#
.SYNOPSIS
    Performs a comprehensive diagnostic on a Windows machine and generates a detailed HTML report.

.DESCRIPTION
    This script gathers various system information, including CPU, memory, disk, network,
    running processes, event log errors, installed software, running services, startup programs,
    network connectivity, and recent Windows updates.
    It then compiles this information into a user-friendly HTML report and saves it
    to the user's Documents folder.

.PARAMETER ReportPath
    Specifies the directory where the HTML report will be saved.
    Defaults to the user's Documents folder.

.PARAMETER ReportFileName
    Specifies the base name for the HTML report file. A timestamp will be appended.
    Defaults to "WindowsDiagnosticReport".

.PARAMETER EventLogDaysBack
    Specifies the number of days to look back for critical and error events in the event logs.
    Defaults to 7 days.

.NOTES
    Author: W.Keldaoui
    Date: July 1, 2025
    Version: 1.4

    IMPORTANT: This script MUST be run with Administrator privileges.

    To run this script:
    1. Save it as a .ps1 file (e.g., 'DiagnosticReport.ps1').
    2. Open PowerShell as an Administrator (Right-click PowerShell icon -> Run as administrator).
    3. Navigate to the directory where you saved the script.
    4. Run the script using: .\DiagnosticReport.ps1
       You can also use parameters, e.g.:
       .\DiagnosticReport.ps1 -ReportPath "C:\Temp" -EventLogDaysBack 14
    (You might need to adjust your execution policy: Set-ExecutionPolicy RemoteSigned)

.EXAMPLE
    .\DiagnosticReport.ps1
    Runs the diagnostic and saves the report in the Documents folder with default settings.

.EXAMPLE
    .\DiagnosticReport.ps1 -ReportPath "C:\Reports" -ReportFileName "MySystemHealth" -EventLogDaysBack 30
    Runs the diagnostic, saves the report to C:\Reports, names the file "MySystemHealth_...",
    and looks back 30 days for event log entries.
#>

[CmdletBinding()]
param(
    [string]$ReportPath = (Join-Path $env:USERPROFILE "Documents"),
    [string]$ReportFileName = "WindowsDiagnosticReport",
    [int]$EventLogDaysBack = 7
)

# --- ENSURE SCRIPT IS RUN AS ADMINISTRATOR ---
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script requires Administrator privileges to run all diagnostic checks."
    Write-Warning "Please restart PowerShell (or your terminal) as an Administrator and try again."
    Write-Host "Exiting script."
    exit 1 # Exit with an error code
}

$Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$FullReportFileName = "$($ReportFileName)_$($Timestamp).html"
$FullReportFilePath = Join-Path $ReportPath $FullReportFileName

Write-Host "Starting Windows Diagnostic Report generation..." -ForegroundColor Cyan
Write-Host "Report will be saved to: $FullReportFilePath" -ForegroundColor Cyan

# --- Functions for Data Collection ---

Function Get-SystemOverview {
    Write-Host "  Collecting System Overview..." -ForegroundColor Green
    try {
        $ComputerInfo = Get-ComputerInfo -Property OsName, OsVersion, OsBuildNumber, WindowsProductName, CsManufacturer, CsModel, CsTotalPhysicalMemory, CsNumberOfProcessors, CsLogicalProcessors, CsSystemType, CsLastBootUpTime, CsUserName, WindowsRegisteredOwner, WindowsInstallationDate -ErrorAction Stop

        $Uptime = New-TimeSpan -Seconds 0 # Default to 0
        $LastBootUpTime = $ComputerInfo.CsLastBootUpTime
        if ($LastBootUpTime -is [DateTime]) {
            $Uptime = (Get-Date) - $LastBootUpTime
        } else {
            # Attempt to parse if it's a string, or set to a default if it's truly unparseable
            try {
                $LastBootUpTime = [DateTime]::Parse($LastBootUpTime)
                $Uptime = (Get-Date) - $LastBootUpTime
            }
            catch {
                Write-Warning "  Could not parse CsLastBootUpTime: '$($ComputerInfo.CsLastBootUpTime)' for System Uptime calculation. Setting uptime to 0."
            }
        }

        # Handle potentially empty/null properties gracefully
        $LogicalProcessors = if ($ComputerInfo.CsLogicalProcessors) { $ComputerInfo.CsLogicalProcessors } else { "N/A" }
        $InstallationDate = if ($ComputerInfo.WindowsInstallationDate -and ($ComputerInfo.WindowsInstallationDate -is [DateTime])) { $ComputerInfo.WindowsInstallationDate.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }

        $SystemData = [PSCustomObject]@{
            'Operating System'      = $ComputerInfo.OsName
            'OS Version'            = $ComputerInfo.OsVersion
            'OS Build'              = $ComputerInfo.OsBuildNumber
            'Windows Product'       = $ComputerInfo.WindowsProductName
            'Manufacturer'          = $ComputerInfo.CsManufacturer
            'Model'                 = $ComputerInfo.CsModel
            'Total Physical Memory' = "$([math]::Round($ComputerInfo.CsTotalPhysicalMemory / 1GB, 2)) GB"
            'Number of Processors'  = $ComputerInfo.CsNumberOfProcessors
            'Logical Processors'    = $LogicalProcessors
            'System Type'           = $ComputerInfo.CsSystemType
            'Last Boot Up Time'     = $ComputerInfo.CsLastBootUpTime
            'System Uptime'         = "$($Uptime.Days) Days, $($Uptime.Hours) Hours, $($Uptime.Minutes) Minutes"
            'Current User'          = ($ComputerInfo.CsUserName | Select-Object -First 1) # Take first if multiple
            'Registered Owner'      = ($ComputerInfo.WindowsRegisteredOwner | Select-Object -First 1) # Take first if multiple
            'Installation Date'     = $InstallationDate
        }
        return ($SystemData | Format-List | Out-String)
    }
    catch {
        Write-Warning "  Could not retrieve System Overview: $($_.Exception.Message)"
        return "Failed to retrieve System Overview. (Error: $($_.Exception.Message))"
    }
}

Function Get-CpuInfo {
    Write-Host "  Collecting CPU Information..." -ForegroundColor Green
    try {
        $Processor = Get-WmiObject Win32_Processor -ErrorAction Stop
        $CpuLoad = (Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction Stop).CounterSamples.CookedValue

        $CpuData = [PSCustomObject]@{
            'Name'          = $Processor.Name
            'Manufacturer'  = $Processor.Manufacturer
            'NumberOfCores' = $Processor.NumberOfCores
            'NumberOfLogicalProcessors' = $Processor.NumberOfLogicalProcessors
            'CurrentClockSpeed' = "$($Processor.CurrentClockSpeed) MHz"
            'MaxClockSpeed' = "$($Processor.MaxClockSpeed) MHz"
            'Architecture'  = switch ($Processor.Architecture) {
                0 {"x86"}
                1 {"MIPS"}
                2 {"Alpha"}
                3 {"PowerPC"}
                5 {"ARM"}
                6 {"ia64"}
                9 {"x64"}
                default {"Unknown"}
            }
            'Current Load'  = "$([math]::Round($CpuLoad, 2)) %"
        }
        return ($CpuData | Format-List | Out-String)
    }
    catch {
        Write-Warning "  Could not retrieve CPU Information: $($_.Exception.Message)"
        return "Failed to retrieve CPU Information. (Error: $($_.Exception.Message))"
    }
}

Function Get-MemoryInfo {
    Write-Host "  Collecting Memory Information..." -ForegroundColor Green
    try {
        $TotalPhysicalMemoryBytes = (Get-WmiObject Win32_ComputerSystem -ErrorAction Stop).TotalPhysicalMemory
        $TotalPhysicalMemoryGB = [math]::Round($TotalPhysicalMemoryBytes / 1GB, 2)
        $AvailableMemoryMB = (Get-Counter '\Memory\Available MBytes' -ErrorAction Stop).CounterSamples.CookedValue
        $AvailableMemoryGB = [math]::Round($AvailableMemoryMB / 1KB, 2) # Convert MB to GB for consistency
        $MemoryUsagePercent = [math]::Round((($TotalPhysicalMemoryGB - $AvailableMemoryGB) / $TotalPhysicalMemoryGB) * 100, 2)

        $MemoryData = [PSCustomObject]@{
            'Total Physical Memory' = "$($TotalPhysicalMemoryGB) GB"
            'Available Memory'      = "$($AvailableMemoryGB) GB"
            'Memory Usage'          = "$($MemoryUsagePercent) %"
        }
        return ($MemoryData | Format-List | Out-String)
    }
    catch {
        Write-Warning "  Could not retrieve Memory Information: $($_.Exception.Message)"
        return "Failed to retrieve Memory Information. (Error: $($_.Exception.Message))"
    }
}

Function Get-DiskInfo {
    Write-Host "  Collecting Disk Drive Information..." -ForegroundColor Green
    try {
        $Disks = Get-WmiObject Win32_LogicalDisk | Where-Object {$_.DriveType -eq 3} # DriveType 3 = Local Disk
        $DiskData = @()
        foreach ($Disk in $Disks) {
            $TotalSizeGB = [math]::Round($Disk.Size / 1GB, 2)
            $FreeSpaceGB = [math]::Round($Disk.FreeSpace / 1GB, 2)
            $UsedSpaceGB = [math]::Round(($Disk.Size - $Disk.FreeSpace) / 1GB, 2)
            $FreeSpacePercent = [math]::Round(($Disk.FreeSpace / $Disk.Size) * 100, 2)
            $UsedSpacePercent = [math]::Round((($Disk.Size - $Disk.FreeSpace) / $Disk.Size) * 100, 2)

            $DiskData += [PSCustomObject]@{
                'Drive Letter'      = $Disk.DeviceID
                'Volume Name'       = $Disk.VolumeName
                'File System'       = $Disk.FileSystem
                'Total Size (GB)'   = $TotalSizeGB
                'Free Space (GB)'   = $FreeSpaceGB
                'Used Space (GB)'   = $UsedSpaceGB
                'Free Space (%)'    = $FreeSpacePercent
                'Used Space (%)'    = $UsedSpacePercent
            }
        }
        if ($DiskData.Count -gt 0) {
            return ($DiskData | ConvertTo-Html -Fragment -As Table | Out-String) # Changed -As HtmlTable to -As Table
        } else {
            return "No local disk drives found."
        }
    }
    catch {
        Write-Warning "  Could not retrieve Disk Drive Information: $($_.Exception.Message)"
        return "Failed to retrieve Disk Drive Information. (Error: $($_.Exception.Message))"
    }
}

Function Get-NetworkInfo {
    Write-Host "  Collecting Network Information..." -ForegroundColor Green
    try {
        $NetworkAdapters = Get-NetAdapter -ErrorAction Stop | Where-Object {$_.Status -eq 'Up'}
        $NetworkData = @()

        foreach ($Adapter in $NetworkAdapters) {
            $IPConfig = Get-NetIPConfiguration -InterfaceIndex $Adapter.IfIndex -ErrorAction SilentlyContinue
            $IPAddress = ($IPConfig.IPv4Address.IPAddress | Select-Object -First 1)
            $DNSServers = ($IPConfig.DNSServer.ServerAddresses -join ', ')

            $NetworkData += [PSCustomObject]@{
                'Name'          = $Adapter.Name
                'Description'   = $Adapter.InterfaceDescription
                'Status'        = $Adapter.Status
                'MAC Address'   = $Adapter.MacAddress
                'IPv4 Address'  = $IPAddress
                'DNS Servers'   = $DNSServers
            }
        }
        if ($NetworkData.Count -gt 0) {
            return ($NetworkData | ConvertTo-Html -Fragment -As Table | Out-String) # Changed -As HtmlTable to -As Table
        } else {
            return "No active network adapters found."
        }
    }
    catch {
        Write-Warning "  Could not retrieve Network Information: $($_.Exception.Message)"
        return "Failed to retrieve Network Information. (Error: $($_.Exception.Message))"
    }
}

Function Get-NetworkConnectivity {
    Write-Host "  Checking Network Connectivity..." -ForegroundColor Green
    try {
        # Using -ComputerName as an alias for -TargetName for broader compatibility.
        # Also ensuring the command exists before trying to run it.
        if (Get-Command Test-Connection -ErrorAction SilentlyContinue) {
            $PingResult = Test-Connection -ComputerName "8.8.8.8" -Count 1 -ErrorAction SilentlyContinue
            if ($PingResult) {
                return "Internet Connectivity: Connected (Ping to 8.8.8.8 successful, Latency: $($PingResult.ResponseTime) ms)"
            } else {
                return "Internet Connectivity: Disconnected (Ping to 8.8.8.8 failed or timed out)"
            }
        } else {
            return "Test-Connection cmdlet not found or accessible."
        }
    }
    catch {
        Write-Warning "  Could not check Network Connectivity: $($_.Exception.Message)"
        return "Failed to check Network Connectivity. (Error: $($_.Exception.Message))"
    }
}

Function Get-TopProcesses {
    Write-Host "  Collecting Top Running Processes..." -ForegroundColor Green
    try {
        # Get top 20 processes by Working Set (Memory)
        $Processes = Get-Process -ErrorAction Stop | Select-Object -Property Name, Id, @{Name='Memory (MB)'; Expression={[math]::Round($_.WS / 1MB, 2)}}, CPU | Sort-Object -Property 'Memory (MB)' -Descending | Select-Object -First 20
        if ($Processes.Count -gt 0) {
            return ($Processes | ConvertTo-Html -Fragment -As Table | Out-String) # Changed -As HtmlTable to -As Table
        } else {
            return "No running processes found."
        }
    }
    catch {
        Write-Warning "  Could not retrieve Top Running Processes: $($_.Exception.Message)"
        return "Failed to retrieve Top Running Processes. (Error: $($_.Exception.Message))"
    }
}

Function Get-EventLogErrors {
    param(
        [int]$DaysBack
    )
    Write-Host "  Collecting Recent Critical & Error Events (last $DaysBack days)..." -ForegroundColor Green
    try {
        $StartTime = (Get-Date).AddDays(-$DaysBack)
        $EventLogs = Get-WinEvent -FilterHashtable @{LogName='System','Application'; Level=1,2; StartTime=$StartTime} -ErrorAction SilentlyContinue |
            Select-Object -Property TimeCreated, LevelDisplayName, LogName, ProviderName, Id, Message -First 50 |
            Sort-Object TimeCreated -Descending

        if ($EventLogs.Count -gt 0) {
            return ($EventLogs | ConvertTo-Html -Fragment -As Table | Out-String) # Changed -As HtmlTable to -As Table
        } else {
            return "No Critical or Error events found in the last $DaysBack days."
        }
    }
    catch {
        Write-Warning "  Could not retrieve event logs: $($_.Exception.Message)"
        return "Failed to retrieve Event Log Errors. (Error: $($_.Exception.Message))"
    }
}

Function Get-InstalledSoftware {
    Write-Host "  Collecting Installed Software..." -ForegroundColor Green
    try {
        $Software = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
            Where-Object {$_.DisplayName -ne $null -and $_.SystemComponent -ne 1 -and $_.ParentKeyName -eq $null} |
            Select-Object DisplayName, DisplayVersion, InstallDate, Publisher |
            Sort-Object DisplayName

        if ($Software.Count -gt 0) {
            return ($Software | ConvertTo-Html -Fragment -As Table | Out-String) # Changed -As HtmlTable to -As Table
        } else {
            return "No installed software found."
        }
    }
    catch {
        Write-Warning "  Could not retrieve Installed Software: $($_.Exception.Message)"
        return "Failed to retrieve Installed Software. (Error: $($_.Exception.Message))"
    }
}

Function Get-RunningServices {
    Write-Host "  Collecting Running Services..." -ForegroundColor Green
    try {
        $Services = Get-Service -ErrorAction Stop | Where-Object {$_.Status -eq 'Running'} | Select-Object Name, DisplayName, Status | Sort-Object DisplayName

        if ($Services.Count -gt 0) {
            return ($Services | ConvertTo-Html -Fragment -As Table | Out-String) # Changed -As HtmlTable to -As Table
        } else {
            return "No running services found."
        }
    }
    catch {
        Write-Warning "  Could not retrieve Running Services: $($_.Exception.Message)"
        return "Failed to retrieve Running Services. (Error: $($_.Exception.Message))"
    }
}

Function Get-StartupPrograms {
    Write-Host "  Collecting Startup Programs..." -ForegroundColor Green
    try {
        $StartupPrograms = Get-CimInstance Win32_StartupCommand -ErrorAction Stop | Select-Object Name, Command, Location, User | Sort-Object Name

        if ($StartupPrograms.Count -gt 0) {
            return ($StartupPrograms | ConvertTo-Html -Fragment -As Table | Out-String) # Changed -As HtmlTable to -As Table
        } else {
            return "No startup programs found."
        }
    }
    catch {
        Write-Warning "  Could not retrieve Startup Programs: $($_.Exception.Message)"
        return "Failed to retrieve Startup Programs. (Error: $($_.Exception.Message))"
    }
}

Function Get-WindowsUpdates {
    Write-Host "  Collecting Recent Windows Updates..." -ForegroundColor Green
    try {
        $Updates = Get-HotFix -ErrorAction Stop | Select-Object HotFixID, Description, InstalledBy, InstalledOn | Sort-Object InstalledOn -Descending
        if ($Updates.Count -gt 0) {
            return ($Updates | ConvertTo-Html -Fragment -As Table | Out-String) # Changed -As HtmlTable to -As Table
        } else {
            return "No recent Windows updates found."
        }
    }
    catch {
        Write-Warning "  Could not retrieve Windows Updates: $($_.Exception.Message)"
        return "Failed to retrieve Windows Updates. (Error: $($_.Exception.Message))"
    }
}

Function Get-ReportSummary {
    param(
        $CpuLoad,
        $MemoryUsagePercent,
        $DiskData, # This will be the raw object, not HTML
        $EventLogErrorsCount
    )
    $Summary = [PSCustomObject]@{
        'CPU Load'              = "$([math]::Round($CpuLoad, 2)) %"
        'Memory Usage'          = "$([math]::Round($MemoryUsagePercent, 2)) %"
        'Total Critical/Error Events (Last 7 Days)' = $EventLogErrorsCount
    }

    # Add disk space summary
    $TotalDiskSpace = ($DiskData | Measure-Object -Property 'Total Size (GB)' -Sum).Sum
    $TotalFreeSpace = ($DiskData | Measure-Object -Property 'Free Space (GB)' -Sum).Sum
    if ($TotalDiskSpace -gt 0) {
        $OverallDiskUsage = [math]::Round((($TotalDiskSpace - $TotalFreeSpace) / $TotalDiskSpace) * 100, 2)
        $Summary | Add-Member -MemberType NoteProperty -Name 'Overall Disk Usage' -Value "$($OverallDiskUsage) %"
    }

    return ($Summary | Format-List | Out-String)
}


# --- Main Script Logic ---

# --- Collect raw data for summary (attempt robustly) ---
$RawCpuLoad = 0
try { $RawCpuLoad = (Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction SilentlyContinue).CounterSamples.CookedValue } catch {}

$RawTotalPhysicalMemoryBytes = 0
try { $RawTotalPhysicalMemoryBytes = (Get-WmiObject Win32_ComputerSystem -ErrorAction SilentlyContinue).TotalPhysicalMemory } catch {}
$RawTotalPhysicalMemoryGB = if ($RawTotalPhysicalMemoryBytes) { [math]::Round($RawTotalPhysicalMemoryBytes / 1GB, 2) } else { 0 }

$RawAvailableMemoryMB = 0
try { $RawAvailableMemoryMB = (Get-Counter '\Memory\Available MBytes' -ErrorAction SilentlyContinue).CounterSamples.CookedValue } catch {}
$RawAvailableMemoryGB = if ($RawAvailableMemoryMB) { [math]::Round($RawAvailableMemoryMB / 1KB, 2) } else { 0 }

$RawMemoryUsagePercent = if ($RawTotalPhysicalMemoryGB -gt 0) { [math]::Round((($RawTotalPhysicalMemoryGB - $RawAvailableMemoryGB) / $RawTotalPhysicalMemoryGB) * 100, 2) } else { 0 }

$RawDisks = @()
try { $RawDisks = Get-WmiObject Win32_LogicalDisk | Where-Object {$_.DriveType -eq 3} } catch {}
$RawDiskDataForSummary = @()
foreach ($Disk in $RawDisks) {
    try {
        $RawDiskDataForSummary += [PSCustomObject]@{
            'Total Size (GB)'   = [math]::Round($Disk.Size / 1GB, 2)
            'Free Space (GB)'   = [math]::Round($Disk.FreeSpace / 1GB, 2)
        }
    } catch {}
}

$RawEventLogsCount = 0
try {
    $RawEventLogsCount = (Get-WinEvent -FilterHashtable @{LogName='System','Application'; Level=1,2; StartTime=(Get-Date).AddDays(-$EventLogDaysBack)} -ErrorAction SilentlyContinue).Count
} catch {}


# Collect all data for report sections
$SystemOverviewHTML = Get-SystemOverview
$CpuInfoHTML = Get-CpuInfo
$MemoryInfoHTML = Get-MemoryInfo
$DiskInfoHTML = Get-DiskInfo
$NetworkInfoHTML = Get-NetworkInfo
$NetworkConnectivityHTML = Get-NetworkConnectivity
$TopProcessesHTML = Get-TopProcesses
$EventLogErrorsHTML = Get-EventLogErrors -DaysBack $EventLogDaysBack
$InstalledSoftwareHTML = Get-InstalledSoftware
$RunningServicesHTML = Get-RunningServices
$StartupProgramsHTML = Get-StartupPrograms
$WindowsUpdatesHTML = Get-WindowsUpdates

# Generate Summary after all raw data is collected
$ReportSummaryHTML = Get-ReportSummary -CpuLoad $RawCpuLoad -MemoryUsagePercent $RawMemoryUsagePercent -DiskData $RawDiskDataForSummary -EventLogErrorsCount $RawEventLogsCount

# HTML Report Template
$HtmlReport = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Windows Diagnostic Report - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Inter', sans-serif;
            margin: 20px;
            background-color: #f4f7f6;
            color: #333;
            line-height: 1.6;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: #ffffff;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
        }
        h1 {
            color: #2c3e50;
            text-align: center;
            margin-bottom: 30px;
            font-weight: 700;
            font-size: 2.5em;
        }
        h2 {
            color: #34495e;
            border-bottom: 2px solid #e0e0e0;
            padding-bottom: 10px;
            margin-top: 40px;
            margin-bottom: 20px;
            font-weight: 600;
            font-size: 1.8em;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
            border-radius: 8px;
            overflow: hidden; /* Ensures rounded corners apply to content */
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #4CAF50; /* A pleasant green */
            color: white;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.9em;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        tr:hover {
            background-color: #f1f1f1;
        }
        pre {
            background-color: #ecf0f1;
            padding: 15px;
            border-radius: 8px;
            overflow-x: auto;
            white-space: pre-wrap; /* Ensures long lines wrap */
            word-wrap: break-word; /* Breaks words if necessary */
        }
        .info-box {
            background-color: #e8f5e9; /* Light green for info */
            border-left: 5px solid #4CAF50;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 8px;
        }
        .error-box {
            background-color: #ffebee; /* Light red for errors */
            border-left: 5px solid #ef5350;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 8px;
            color: #d32f2f;
            font-weight: 600;
        }
        .footer {
            text-align: center;
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid #e0e0e0;
            color: #777;
            font-size: 0.9em;
        }
        /* Responsive adjustments */
        @media (max-width: 768px) {
            body {
                margin: 10px;
            }
            .container {
                padding: 15px;
            }
            h1 {
                font-size: 2em;
            }
            h2 {
                font-size: 1.5em;
            }
            table, th, td {
                display: block;
                width: 100%;
            }
            th {
                text-align: center;
                background-color: #34495e; /* Darker header for mobile */
            }
            td {
                text-align: right;
                position: relative;
                padding-left: 50%;
            }
            td::before {
                content: attr(data-label);
                position: absolute;
                left: 0;
                width: 45%;
                padding-left: 15px;
                font-weight: bold;
                text-align: left;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Windows Diagnostic Report</h1>
        <div class="info-box">
            <p><strong>Report Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
            <p>This report provides a snapshot of your system's health and configuration.</p>
        </div>

        <h2>Report Summary</h2>
        <pre>$ReportSummaryHTML</pre>

        <h2>System Overview</h2>
        <pre>$SystemOverviewHTML</pre>

        <h2>CPU Information</h2>
        <pre>$CpuInfoHTML</pre>

        <h2>Memory Information</h2>
        <pre>$MemoryInfoHTML</pre>

        <h2>Disk Drive Information</h2>
        $DiskInfoHTML

        <h2>Network Information</h2>
        $NetworkInfoHTML

        <h2>Network Connectivity</h2>
        <pre>$NetworkConnectivityHTML</pre>

        <h2>Top 20 Running Processes (by Memory Usage)</h2>
        $TopProcessesHTML

        <h2>Recent Critical & Error Events (Last $EventLogDaysBack Days)</h2>
        $EventLogErrorsHTML

        <h2>Installed Software</h2>
        $InstalledSoftwareHTML

        <h2>Running Services</h2>
        $RunningServicesHTML

        <h2>Startup Programs</h2>
        $StartupProgramsHTML

        <h2>Recent Windows Updates</h2>
        $WindowsUpdatesHTML

        <div class="footer">
            <p>&copy; $(Get-Date -Format 'yyyy') Windows Diagnostic Report. All rights reserved.</p>
            <p>Generated by PowerShell Script.</p>
        </div>
    </div>
</body>
</html>
"@

# Save the report
try {
    # Ensure the report directory exists
    if (-not (Test-Path $ReportPath)) {
        New-Item -Path $ReportPath -ItemType Directory -Force | Out-Null
        Write-Host "Created report directory: $ReportPath" -ForegroundColor Yellow
    }

    $HtmlReport | Out-File -FilePath $FullReportFilePath -Encoding UTF8 -Force
    Write-Host "Diagnostic report successfully saved to: $FullReportFilePath" -ForegroundColor Green
    # Optionally, open the report automatically
    Start-Process $FullReportFilePath
}
catch {
    Write-Error "Failed to save or open the report. Error: $($_.Exception.Message)"
}

Write-Host "Diagnostic report generation complete." -ForegroundColor Cyan
