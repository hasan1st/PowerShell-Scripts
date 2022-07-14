<#
        Copyright (C) 2022  Stolpe.io
        <https://stolpe.io>
        This program is free software: you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation, either version 3 of the License, or
        (at your option) any later version.
        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.
        You should have received a copy of the GNU General Public License
        along with this program.  If not, see <https://www.gnu.org/licenses/>.
#>

$PSVersion = $Host.Version.Major

### Colors
$Gr = @{ForegroundColor= 'Green'}
$Re = @{ForegroundColor= 'Red'}
$Ye = @{ForegroundColor= 'Yellow'}

Function Find-NeededModules {
    Write-Host "`n=== Making sure that all modules are installad and up to date ===`n"
    
    #region Vars
    # Modules to check if it's installed and imported
    $NeededModules       = @('PowerShellGet', 'MSIPatches', 'PSWindowsUpdate', 'NuGet')
    $NeededPackages      = @('NuGet', 'PowerShellGet')
    # Collects all of the installed modules on the system
    $CurrentModules      = Get-InstalledModule | Select-Object -Property Name, Version | Sort-Object -Property Name
    # Collects all of the installed packages
    $AllPackageProviders = Get-PackageProvider -ListAvailable | Select-Object -Property Name -ExpandProperty Name

    # Making sure that TLS 1.2 is used.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    #endregion Vars

    # Installing needed packages if it's missing.
    Write-Information -MessageData 'Making sure that all of the PackageProviders that are needed are installed...'
    ForEach ($Provider in $NeededPackages) {
        If ($Provider -NotIn $AllPackageProviders) {
            Try {
                Write-Warning -Message "Installing $($Provider) as it's missing..."
                Install-PackageProvider -Name $provider -Scope AllUsers -Force
                Write-Host "$($Provider) is now installed" @Gr
            } Catch {
                Write-Error -Message "Error installing $($Provider)"
                Write-Error -Message "$($PSItem.Exception.Message)"
                continue
            }
        } Else {
            Write-Host "$($provider) is already installed." @Gr
        }
    }

    # Setting PSGallery as trusted if it's not trusted
    Write-Information -MessageData 'Making sure that PSGallery is set to Trusted...'
    If ((Get-PSRepository -Name PSGallery | Select-Object -ExpandProperty InstallationPolicy) -eq 'Untrusted') {
        Try {
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
            Write-Host 'PSGallery is now set to trusted' @Gr
        } Catch {
            Write-Error -Message 'Error could not set PSGallery to trusted'
            Write-Error -Message "$($PSItem.Exception.Message)"
            continue
        }
    } Else {
        Write-Host 'PSGallery is already trusted' @Gr
    }

    # Checks if all modules in $NeededModules are installed and up to date.
    Write-Information -MessageData 'Making sure that all of the needed modules are installed and up to date...'
    ForEach ($m in $NeededModules) {
        If ($m -in $CurrentModules.Name) {
            # Collects the latest version of module
            $NewestVersion = Find-Module -Name $m | Sort-Object -Property Version -Descending | Select-Object -Property Version -First 1
            # Get all the installed modules and versions
            $AllVersions = Get-InstalledModule -Name $m -AllVersions | Sort-Object -Property PublishedDate -Descending
            $MostRecentVersion = $AllVersions[0].Version

            # Check if the module are up to date
            If ($NewestVersion.Version -gt $AllVersions.Version) {
                Try {
                    Write-Information -MessageData "Updating $($m) to version $($NewestVersion.Version)..."
                    Update-Module -Name $($m) -Scope AllUsers
                    Write-Host "$($m) has been updated!" @Gr
                } Catch {
                    Write-Host "Error updating module $($m)" @Re
                    Write-Host "$($PSItem.Exception.Message)" @Re
                    continue
                }

                # Remove old versions of the modules
                If ($AllVersions.Count -gt 1 ) {
                    Foreach ($Version in $AllVersions) {
                        If ($Version.Version -ne $MostRecentVersion) {
                            Try {
                                Write-Information -MessageData "Uninstalling previous version $($Version.Version) of module $($m)..."
                                Uninstall-Module -Name $m -RequiredVersion $Version.Version -Force -ErrorAction SilentlyContinue
                                Write-Host "$($m) are not uninstalled!" @Gr
                            } Catch {
                                Write-Host "Error uninstalling previous version $($Version.Version) of module $($m)" @Re
                                Write-Host "$($PSItem.Exception.Message)" @Re
                                continue
                            }
                        }
                    }
                }
            } Else {
                Write-Host "$($m) don't need to be updated as it's on the latest version" @Gr
            }
        } Else {
            # Installing missing module
            Write-Information -MessageData "Installing module $($m) as it's missing..."
            Try {
                Install-Module -Name $m -Scope AllUsers -Force
                Write-Host "$($m) are now installed!" @Gr
            } Catch {
                Write-Host "Could not install $($m)" @Re
                Write-Host "$($PSItem.Exception.Message)" @Re
                continue
            }
        }
    }
    # Collect all of the imported modules.
    $ImportedModules = Get-module | Select-Object -Property Name, Version
    
    # Import module if it's not imported
    ForEach ($module in $NeededModules) {
        If ($module -eq 'MSIPatches' -and $PSVersion -gt 5) {
            Write-Host 'Remove-MSPatches only works with PowerShell 5.1, skipping it.' @Ye
        } Else {
            If ($module -in $ImportedModules.Name) {
                Write-Host "$($Module) are already imported!" @Gr
            } Else {
                Try {
                    Write-Information -MessageData "Importing $($module) module..."
                    Import-Module -Name $module -Force
                    Write-Host "$($module) are now imported!" @Gr
                } Catch {
                    Write-Host "Could not import module $($module)" @Re
                    Write-Host "$($PSItem.Exception.Message)" @Re
                    continue
                }
            }
        }
    }
}

Function Remove-MSPatches {
    If ($PSVersion -gt 5) {
        Write-Host 'Remove-MSPatches only works with PowerShell 5.1, skipping this function.' @Ye
    } Else {
        Write-Host "`n=== Delete all orphaned patches ===`n"
        $OrphanedPatch = Get-OrphanedPatch
        If ($Null -ne $OrphanedPatch) {
            $FreeUp = Get-MsiPatch | Select-Object -ExpandProperty OrphanedPatchSize
            Write-Information -MessageData "This will free up: $($FreeUp)GB"
            Try {
                Write-Host 'Deleting all of the orphaned patches...'
                Get-OrphanedPatch | Remove-Item
                Write-Host 'Success, all of the orphaned patches has been deleted!' @Gr
            } Catch {
                Write-Host 'Something went wrong when trying to delete the orphaned patches!' @Re
                Write-Host "$($PSItem.Exception.Message)" @Re
                continue
            }
        } Else {
            Write-Host 'No orphaned patches was found.' @Gr
        }
    }
}

Function Update-MSUpdates {
    Write-Information -MessageData "`n=== Windows Update and Windows Store ===`n"
    #Update Windows Store apps!
    If ($PSVersion -gt 5) {
        Write-Host 'Microsoft store updates only works with PowerShell 5.1, skipping this function.' @Ye
    } Else {
        Try {
            Write-Information -MessageData 'Checking if Windows Store has any updates...'
            $namespaceName = 'root\cimv2\mdm\dmmap'
            $className     = 'MDM_EnterpriseModernAppManagement_AppManagement01'
            $wmiObj        = Get-WmiObject -Namespace $namespaceName -Class $className
            $result        = $wmiObj.UpdateScanMethod()
            Write-Host "$($result)" @Gr
            Write-Host 'Success, checking and if needed updated Windows Store apps!' @Gr
        } Catch {
            Write-Host 'Something went wrong when trying to check Windows Store!' @Re
            Write-Host "$($PSItem.Exception.Message)" @Re
            continue
        }
    }

    # Checking after Windows Updates
    Try {
        Write-Information -MessageData 'Starting to search after Windows Updates...'
        $WSUSUpdates = Get-WindowsUpdate
        If ($Null -ne $WSUSUpdates) {
            Install-WindowsUpdate -AcceptAll
            Write-Host 'All of the Windows Updates has been installed!' @Gr
        } Else {
            Write-Host 'All of the latest updates has been installed already! Your up to date!' @Gr
        }
    } Catch {
        Write-Host 'Something went wrong when trying to run Windows Update!' @Re
        Write-Host "$($PSItem.Exception.Message)" @Re
        continue
    }
}

Function Update-MSDefender {
    Write-Information -MessageData "`n=== Microsoft Defender ===`n"
    Try {
        Write-Host 'Update signatures from Microsoft Update Server...'
        Update-MpSignature -UpdateSource MicrosoftUpdateServer
        Write-Host 'Updated signatures complete!' @Gr
    } Catch {
        Write-Host 'Something went wrong when trying to update signatures!' @Re
        Write-Host "$($PSItem.Exception.Message)" @Re
        continue
    }

    Try {
        Write-Host 'Starting Defender Quick Scan, please wait...'
        Start-MpScan -ScanType QuickScan -ErrorAction SilentlyContinue
        Write-Host 'Defender quick scan is completed!' @Gr
    } Catch {
        Write-Host 'Something went wrong when trying to run defender quick scan!' @Re
        Write-Host "$($PSItem.Exception.Message)" @Re
        continue
    }
}

Function Remove-TempFolderFiles {
    Write-Information -MessageData "`n=== Starting to delete temp files and folders ===`n"
    $WindowsOld     = 'C:\Windows.old'
    $Users          = Get-ChildItem -Path 'C:\Users' | Select-Object -ExpandProperty Name
    $TempFolders    = @('C:\Temp', 'C:\Tmp', 'C:\Windows\Temp', 'C:\Windows\Prefetch', 'C:\Windows\SoftwareDistribution\Download')
    $SpecialFolders = @("C:\`$Windows`.~BT", "C:\`$Windows`.~WS")

    Try {
        Write-Information -MessageData 'Stopping wuauserv...'
        Stop-Service -Name 'wuauserv'
        Do {
            Write-Host 'Waiting for wuauserv to stop...'
            Start-Sleep -Seconds 1
        } While ((Get-Service -Name 'wuauserv' -ErrorAction SilentlyContinue).Status -eq 'Running')
        Write-Host 'Wuauserv is now stopped!' @Gr
    } Catch {
        Write-Host 'Could not stop wuauserv!' @Re
        Write-Host "$($PSItem.Exception.Message)" @Re
        continue
    }

    ForEach ($TempFolder in $TempFolders) {
        If (Test-Path -Path $TempFolder) {
            Try {
                Write-Host "Deleting all files in $($TempFolder)..."
                Remove-Item -Path "$($TempFolder)\*" -Recurse -Force -Confirm:$false
                Write-Host "All files in $($TempFolder) has been deleted!" @Gr
            } Catch {
                Write-Host "Something went wrong when trying to delete all files in $($TempFolder)!" @Re
                Write-Host "$($PSItem.Exception.Message)" @Re
                continue
            }
        }  
    }

    Try {
        Write-Host 'Starting wuauserv again...'
        Start-Service -Name 'wuauserv'
        Write-Host 'Wuauserv has started again!' @Gr
    } Catch {
        Write-Host 'Something went wrong when trying to start wuauserv!' @Re
        Write-Host "$($PSItem.Exception.Message)" @Re
        continue
    }

    ForEach ($usr in $Users) {
        $UsrTemp = "C:\Users\$($usr)\AppData\Local\Temp"
        If (Test-Path -Path $UsrTemp) {
            Try {
                Write-Information -MessageData "Deleting all files in $($UsrTemp)..."
                Remove-Item -Path "$($UsrTemp)\*" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
                Write-Host "All files in $($UsrTemp) has been deleted!" @Gr
            } Catch {
                Write-Host "Something went wrong when trying to delete all files in $($UsrTemp)!" @Re
                Write-Host "$($PSItem.Exception.Message)" @Re
                continue
            }
        }
    }

    If (Test-Path -Path $WindowsOld) {
        Try {
            Write-Host "Deleting folder $($WindowsOld)..."
            Remove-Item -Path "$($WindowsOld)\" -Recurse -Force -Confirm:$false
            Write-Host "The folder $($WindowsOld) has been deleted!" @Gr
        } Catch {
            Write-Host "Something went wrong when trying to delete the folder $($WindowsOld)!" @Re
            Write-Host "$($PSItem.Exception.Message)" @Re
            continue
        }
    }

    ForEach ($sFolder in $SpecialFolders) {
        If (Test-Path -Path $sFolder) {
            Try {
                takeown /F "$($sFolder)\*" /R /A
                icacls "$($sFolder)\*.*" /T /grant administrators:F
                Write-Output -InputObject -InputObjct "Deleting folder $($sFolder)\..."
                Remove-Item -Path "$($sFolder)\" -Recurse -Force -Confirm:$False
                Write-Host "Folder $($sFolder)\* has been deleted!" @Gr
            } Catch {
                Write-Host "Something went wrong when trying to delete the folder $($sFolder)\!" @Re
                Write-Host "$($PSItem.Exception.Message)" @Re
                continue
            }
        }
    }
}

Function Start-CleanDisk {
    Param (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]]$Section
    )

    $sections = @(
        'Active Setup Temp Folders',
        'BranchCache',
        'Content Indexer Cleaner',
        'Device Driver Packages',
        'Downloaded Program Files',
        'GameNewsFiles',
        'GameStatisticsFiles',
        'GameUpdateFiles',
        'Internet Cache Files',
        'Memory Dump Files',
        'Offline Pages Files',
        'Old ChkDsk Files',
        'Previous Installations',
        'Recycle Bin',
        'Service Pack Cleanup',
        'Setup Log Files',
        'System error memory dump files',
        'System error minidump files',
        'Temporary Files',
        'Temporary Setup Files',
        'Temporary Sync Files',
        'Thumbnail Cache',
        'Update Cleanup',
        'Upgrade Discarded Files',
        'User file versions',
        'Windows Defender',
        'Windows Error Reporting Archive Files',
        'Windows Error Reporting Queue Files',
        'Windows Error Reporting System Archive Files',
        'Windows Error Reporting System Queue Files',
        'Windows ESD installation files',
        'Windows Upgrade Log Files'
    )

    If ($PSBoundParameters.ContainsKey('Section')) {
        If ($Section -notin $sections) {
            throw "The section [$($Section)] is not available. Available options are: [$($Section -join ',')]."
        }
    } Else {
        $Section = $sections
    }

    Write-Verbose -Message 'Clearing CleanMgr.exe automation settings.'

    $getItemParams = @{
        Path        = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\*'
        Name        = 'StateFlags0001'
        ErrorAction = 'SilentlyContinue'
    }
    Get-ItemProperty @getItemParams | Remove-ItemProperty -Name StateFlags0001 -ErrorAction SilentlyContinue

    Write-Verbose -Message 'Adding enabled disk cleanup sections...'
    ForEach ($keyName in $Section) {
        $newItemParams = @{
            Path         = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\$keyName"
            Name         = 'StateFlags0001'
            Value        = 1
            PropertyType = 'DWord'
            ErrorAction  = 'SilentlyContinue'
        }
        $null = New-ItemProperty @newItemParams
    }

    Write-Verbose -Message 'Starting CleanMgr.exe...'
    Start-Process -FilePath CleanMgr.exe -ArgumentList '/sagerun:1' -NoNewWindow

    Write-Verbose -Message 'Waiting for CleanMgr and DismHost processes...'
    Get-Process -Name cleanmgr, dismhost -ErrorAction SilentlyContinue | Wait-Process
}


Find-NeededModules
Remove-MSPatches
Remove-TempFolderFiles
Start-CleanDisk
Update-MSDefender
Update-MSUpdates

Write-Output -InputObject 'The script is finished!'
$RebootNeeded = Get-WURebootStatus | Select-Object -Property RebootRequired -ExpandProperty RebootRequired
If ($RebootNeeded -eq 'true') {
    Write-Host 'Windows Update want you to reboot your computer!' @Ye
}
