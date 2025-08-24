<#
EmergencyToolkit.ps1
A one-stop "oh no" toolkit for Windows. Run as Administrator.
Tested on Windows 10/11 PowerShell 5.1/7.x (where supported).
#>

#region Helpers
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function New-TimeStamp {
    return (Get-Date -Format "yyyyMMdd_HHmmss")
}

function Ensure-Path([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
}

function Write-Section($text) {
    Write-Host ""
    Write-Host "==== $text ====" -ForegroundColor Cyan
}
#endregion Helpers

#region Actions
function Start-QuickBackup {
    param(
        [string[]] $Sources = @("$HOME\Desktop", "$HOME\Documents", "$HOME\Pictures", "$HOME\Videos", "$HOME\Downloads"),
        [string] $DestinationRoot
    )

    if (-not $DestinationRoot) {
        $DestinationRoot = Read-Host "Enter destination drive/folder (e.g. D:\Backups)"
    }

    if (-not $DestinationRoot) {
        Write-Warning "No destination provided. Aborting backup."
        return
    }

    $stamp = New-TimeStamp
    $dest = Join-Path $DestinationRoot "EmergencyBackup_$stamp"
    Ensure-Path $dest
    $log = Join-Path $dest "backup_$stamp.log"

    Write-Section "Quick Backup to '$dest'"
    Write-Host "Logging to $log"

    $excludeDirs = @("node_modules", "venv", ".git", "bin", "obj")
    foreach ($src in $Sources) {
        if (Test-Path -LiteralPath $src) {
            $name = Split-Path $src -Leaf
            $tgt = Join-Path $dest $name
            Ensure-Path $tgt

            # Build robocopy exclude directories switches
            $xd = @()
            foreach ($d in $excludeDirs) { $xd += @("/XD", $d) }

            $args = @(
                $src, $tgt, "/E",
                "/COPY:DAT",        # Data, Attributes, Timestamps
                "/R:1","/W:1",      # Retry faster
                "/MT:16",           # Multi-threaded copy
                "/XJ",              # Exclude junctions
                "/NFL","/NDL","/NP" # Cleaner log
            ) + $xd + @("/LOG+:$log")

            Write-Host "Backing up $src -> $tgt"
            Start-Process -FilePath robocopy -ArgumentList $args -NoNewWindow -Wait
        } else {
            Write-Warning "Source not found: $src"
        }
    }

    # Export a quick "what's on this machine" snapshot
    $snapshot = Join-Path $dest "SystemSnapshot_$stamp.txt"
    Write-Host "Collecting system snapshot -> $snapshot"
    try {
        @"
=== Computer Info ===
$(Get-ComputerInfo | Out-String)

=== IP Config ===
$(ipconfig /all | Out-String)

=== Disks ===
$(Get-PhysicalDisk | Select-Object FriendlyName,SerialNumber,MediaType,Size,HealthStatus | Format-Table | Out-String)

"@ | Set-Content -LiteralPath $snapshot -Encoding UTF8
    } catch {
        Write-Warning "Snapshot collection failed: $($_.Exception.Message)"
    }

    Write-Host "Quick Backup complete." -ForegroundColor Green
}

function New-SystemRestorePoint {
    if (-not (Test-Admin)) {
        Write-Warning "System Restore requires Administrator. Skipping."
        return
    }
    try {
        Write-Section "Creating System Restore Point"
        Checkpoint-Computer -Description "EmergencyToolkit $(New-TimeStamp)" -RestorePointType "MODIFY_SETTINGS"
        Write-Host "Restore point created." -ForegroundColor Green
    } catch {
        Write-Warning "Could not create restore point: $($_.Exception.Message)"
        Write-Host "Tip: Ensure 'System Protection' is enabled for your system drive."
    }
}

function Export-InstalledApps {
    param([string]$DestinationRoot)

    if (-not $DestinationRoot) {
        $DestinationRoot = Read-Host "Enter destination drive/folder (e.g. D:\Backups)"
    }

    $stamp = New-TimeStamp
    $dest = Join-Path $DestinationRoot "EmergencyBackup_$stamp"
    Ensure-Path $dest

    Write-Section "Exporting Installed Apps"
    $csv = Join-Path $dest "InstalledApps_$stamp.csv"
    try {
        # Use multiple sources for better coverage
        $list1 = Get-Package | Select-Object Name,Version,ProviderName,Source | Sort-Object Name -Unique
        $list2 = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                  HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* `
                  -ErrorAction SilentlyContinue |
                Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
                Where-Object { $_.DisplayName } |
                Sort-Object DisplayName -Unique

        # Normalize and merge
        $apps = foreach ($a in $list1) {
            [PSCustomObject]@{
                Name          = $a.Name
                Version       = $a.Version
                Publisher     = $a.ProviderName
                InstallDate   = $null
                Source        = "Get-Package"
            }
        }
        foreach ($b in $list2) {
            [PSCustomObject]@{
                Name          = $b.DisplayName
                Version       = $b.DisplayVersion
                Publisher     = $b.Publisher
                InstallDate   = $b.InstallDate
                Source        = "Registry"
            }
        }

        $apps | Sort-Object Name,Version | Export-Csv -NoTypeInformation -Path $csv -Encoding UTF8
        Write-Host "Saved: $csv" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to export apps: $($_.Exception.Message)"
    }
}

function Export-Drivers {
    param([string]$DestinationRoot)

    if (-not (Test-Admin)) {
        Write-Warning "Driver export requires Administrator. Skipping."
        return
    }

    if (-not $DestinationRoot) {
        $DestinationRoot = Read-Host "Enter destination drive/folder (e.g. D:\Backups)"
    }

    $stamp = New-TimeStamp
    $dest = Join-Path $DestinationRoot "EmergencyBackup_$stamp\Drivers"
    Ensure-Path $dest

    Write-Section "Exporting Device Drivers"
    try {
        Start-Process -FilePath dism -ArgumentList "/online","/export-driver","/destination:$dest" -NoNewWindow -Wait
        Write-Host "Drivers exported to: $dest" -ForegroundColor Green
    } catch {
        Write-Warning "Driver export failed: $($_.Exception.Message)"
    }
}

function Enable-RansomwareProtection {
    if (-not (Test-Admin)) {
        Write-Warning "Changing Defender settings requires Administrator. Skipping."
        return
    }
    Write-Section "Enabling Windows Defender Controlled Folder Access"
    try {
        Set-MpPreference -EnableControlledFolderAccess Enabled
        # Add common folders to protected list
        $folders = @("$HOME\Documents", "$HOME\Pictures", "$HOME\Desktop")
        foreach ($f in $folders) {
            try { Add-MpPreference -ControlledFolderAccessProtectedFolders $f -ErrorAction Stop } catch {}
        }
        Write-Host "Controlled Folder Access enabled and common folders protected." -ForegroundColor Green
        Write-Host "Note: Legit apps might need to be allowed in 'Ransomware protection' settings."
    } catch {
        Write-Warning "Could not enable Controlled Folder Access: $($_.Exception.Message)"
    }
}

function Network-Lockdown {
    param([switch]$Enable)

    if (-not (Test-Admin)) {
        Write-Warning "Network adapter control requires Administrator. Skipping."
        return
    }

    if ($Enable) {
        Write-Section "Re-enabling Network Adapters"
        try {
            Get-NetAdapter -Physical | Where-Object { $_.Status -ne 'Up' } | Enable-NetAdapter -Confirm:$false -ErrorAction SilentlyContinue
            Write-Host "Adapters re-enabled (where possible)." -ForegroundColor Green
        } catch {
            Write-Warning "Failed to re-enable adapters: $($_.Exception.Message)"
        }
    } else {
        Write-Section "Disabling Network Adapters (Kill Switch)"
        try {
            Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' } | Disable-NetAdapter -Confirm:$false -ErrorAction SilentlyContinue
            Write-Host "Adapters disabled. Run option 6 again to re-enable." -ForegroundColor Yellow
        } catch {
            Write-Warning "Failed to disable adapters: $($_.Exception.Message)"
        }
    }
}

function Run-FullEmergency {
    param([string]$DestinationRoot)

    if (-not $DestinationRoot) {
        $DestinationRoot = Read-Host "Enter destination drive/folder (e.g. D:\Backups)"
    }
    if (-not $DestinationRoot) {
        Write-Warning "No destination provided. Aborting."
        return
    }

    Start-QuickBackup -DestinationRoot $DestinationRoot
    New-SystemRestorePoint
    Export-InstalledApps -DestinationRoot $DestinationRoot
    Export-Drivers -DestinationRoot $DestinationRoot
}
#endregion Actions

#region Menu
function Show-Menu {
    Clear-Host
    Write-Host "====================================="
    Write-Host "  Emergency Toolkit (Windows)"
    Write-Host "====================================="
    Write-Host "1) Quick Backup (Desktop, Documents, Pictures, Downloads, Videos)"
    Write-Host "2) Create System Restore Point"
    Write-Host "3) Export Installed Apps (CSV)"
    Write-Host "4) Export Device Drivers (for reinstall)"
    Write-Host "5) Enable Ransomware Protection (Defender Controlled Folder Access)"
    Write-Host "6) Network Kill Switch (toggle disable/enable adapters)"
    Write-Host "7) FULL RUN (1-4)"
    Write-Host "0) Exit"
    Write-Host "-------------------------------------"
}

if (-not (Test-Admin)) {
    Write-Warning "It's strongly recommended to 'Run as Administrator' for full functionality."
}

do {
    Show-Menu
    $choice = Read-Host "Choose an option"
    switch ($choice) {
        '1' { Start-QuickBackup }
        '2' { New-SystemRestorePoint }
        '3' { Export-InstalledApps }
        '4' { Export-Drivers }
        '5' { Enable-RansomwareProtection }
        '6' {
            # Toggle behavior: if any physical adapter is Up, disable; else enable
            $anyUp = (Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }).Count -gt 0
            if ($anyUp) { Network-Lockdown } else { Network-Lockdown -Enable }
        }
        '7' { Run-FullEmergency }
        '0' { break }
        default { Write-Host "Invalid choice."; Start-Sleep -Seconds 1 }
    }
    if ($choice -ne '0') {
        Write-Host ""
        Read-Host "Press Enter to continue..."
    }
} while ($true)
#endregion Menu
