# Copyright (c) Microsoft Corporation. All rights reserved.

function Export-OSConfigDiagnostics {
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]$DestinationArchivePath
    )

    $FileDateTimeUniversal = Get-Date -Format FileDateTimeUniversal
    $TempDirectoryPath = Join-Path $Env:SystemDrive -ChildPath "Tmp" | Join-Path -ChildPath $FileDateTimeUniversal

    if (-not $DestinationArchivePath) {
        $DestinationArchivePath = "OSConfig_$FileDateTimeUniversal.zip"
    }

    Remove-Item -Path $TempDirectoryPath -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path $DestinationArchivePath -Force -ErrorAction SilentlyContinue | Out-Null
    New-Item -Type Directory -Path $TempDirectoryPath -Force | Out-Null

    function Export-Registry {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory)]
            [ValidateNotNullOrEmpty()]
            [String]$Path
        )

        Write-Output "Exporting '$Path'..."

        try {
            reg export $Path "$TempDirectoryPath\$($Path -replace '\\', '_').reg" | Out-Null
        } catch {
            Write-Warning $_
        }
    }

    function Export-Directory {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory)]
            [ValidateNotNullOrEmpty()]
            [String]$Path
        )

        Write-Output "Exporting '$Path'..."

        try {
            robocopy $Path "$($TempDirectoryPath)\$(Split-Path -Path $Path -Leaf)" /E /NJH /NJS | Out-Null
        } catch {
            Write-Warning $_
        }
    }

    function Export-WinEvent {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory)]
            [ValidateNotNullOrEmpty()]
            [String]$ProviderName,

            [Parameter(Mandatory)]
            [ValidateNotNullOrEmpty()]
            [String]$LogName,

            [Parameter(Mandatory)]
            [ValidateNotNullOrEmpty()]
            [Int]$Level
        )

        Write-Output "Exporting '$LogName'..."

        try {
            $Events = Get-WinEvent -FilterHashtable @{
                ProviderName = $ProviderName
                LogName      = $LogName
                Level        = $Level
            } -ErrorAction SilentlyContinue
            $Events | ConvertTo-Json -Depth 32 | Out-File -FilePath "$TempDirectoryPath\$($LogName -replace '/', '_').json"
        } catch {
            Write-Warning $_
        }
    }

    function Export-ScriptBlock {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory)]
            [ValidateNotNullOrEmpty()]
            [String]$Name,

            [Parameter(Mandatory)]
            [ValidateNotNullOrEmpty()]
            [ScriptBlock]$ScriptBlock
        )

        Write-Output "Exporting '$($ScriptBlock.ToString().Trim())'..."

        try {
            $ScriptBlock.Invoke() | Out-File -FilePath "$TempDirectoryPath\$Name.json"
        } catch {
            Write-Warning $_
        }
    }

    Export-Registry -Path "HKLM\SOFTWARE\Microsoft\OSConfig"
    Export-Registry -Path "HKLM\SOFTWARE\Microsoft\DeclaredConfiguration"
    Export-Registry -Path "HKLM\SOFTWARE\Microsoft\PolicyManager"
    Export-Registry -Path "HKLM\SOFTWARE\Microsoft\DMOrchestrator"
    Export-Registry -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"

    Export-WinEvent -ProviderName "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider" -LogName "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin" -Level 2
    Export-WinEvent -ProviderName "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider" -LogName "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational" -Level 2

    Export-Directory -Path "C:\ProgramData\Microsoft\DC"
    Export-Directory -Path "C:\ProgramData\GuestConfig\arc_policy_logs"
    Export-Directory -Path "C:\ProgramData\GuestConfig\Configuration"

    Export-ScriptBlock -Name Module -ScriptBlock { Get-Module -Name Microsoft.OSConfig -ListAvailable | Select-Object -Property Name, Version, Path | ConvertTo-Json -Depth 32 }
    Export-ScriptBlock -Name Document -ScriptBlock { Get-OSConfiguration | Get-OsConfigurationDocument | ConvertTo-Json -Depth 32 }
    Export-ScriptBlock -Name DocumentContent -ScriptBlock { Get-OSConfiguration | Get-OsConfigurationDocument | Get-OsConfigurationDocumentContent | ConvertFrom-Json | ConvertTo-Json -Depth 32 }
    Export-ScriptBlock -Name DocumentResult -ScriptBlock { Get-OSConfiguration | Get-OsConfigurationDocument | Get-OsConfigurationDocumentResult | ConvertFrom-Json | ConvertTo-Json -Depth 32 }
    Export-ScriptBlock -Name CiTool -ScriptBlock { citool -lp --json }

    # Compress the temporary directory into a ZIP file.
    Write-Output "Compressing '$($TempDirectoryPath)'..."
    Compress-Archive -Path "$($TempDirectoryPath)\*" -DestinationPath $DestinationArchivePath

    # Remove the temporary directory.
    Remove-Item -Path $TempDirectoryPath -Recurse -Force

    Write-Output "Output: '$(Get-Item $DestinationArchivePath)'."
}
