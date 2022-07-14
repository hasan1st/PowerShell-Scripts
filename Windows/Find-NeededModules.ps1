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

### Colors
$Gr = @{ForegroundColor = 'Green'}

Function Find-NeededModules {
    Write-Host "`n=== Making sure that all modules are installad and up to date ===`n"

    # Modules to check if it's installed and imported
    $NeededModules       = @('PowerShellGet', 'MSIPatches', 'PSWindowsUpdate', 'NuGet')
    $NeededPackages      = @('NuGet', 'PowerShellGet')
    # Collects all of the installed modules on the system
    $CurrentModules      = Get-InstalledModule | Select-Object -Property Name, Version | Sort-Object -Property Name
    # Collects all of the installed packages
    $AllPackageProviders = Get-PackageProvider -ListAvailable | Select-Object -ExpandProperty Name

    # Making sure that TLS 1.2 is used.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    # Installing needed packages if it's missing.
    Write-Host 'Making sure that all of the PackageProviders that are needed are installed...'
    ForEach ($Provider in $NeededPackages) {
        If ($Provider -NotIn $AllPackageProviders) {
            Try {
                Write-Host "Installing $($Provider) as it's missing..."
                Install-PackageProvider -Name $provider -Force -Scope AllUsers
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
    Write-Host 'Making sure that PSGallery is set to Trusted...'
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
    ForEach ($m in $NeededModules) {
        If ($m -in $CurrentModules.Name) {
            # Collects the latest version of module
            $NewestVersion     = Find-Module -Name $m | Sort-Object -Property Version -Descending | Select-Object -Property Version -First 1
            # Get all the installed modules and versions
            $AllVersions       = Get-InstalledModule -Name $m -AllVersions | Sort-Object -Property PublishedDate -Descending
            $MostRecentVersion = $AllVersions[0].Version

            Write-Host "Checking if $($m) needs to be updated..."
            # Check if the module are up to date
            If ($NewestVersion.Version -gt $AllVersions.Version) {
                Try {
                    Write-Host "Updating $($m) to version $($NewestVersion.Version)..."
                    Update-Module -Name $($m) -Scope AllUsers
                    Write-Host "$($m) has been updated!" @Gr
                } Catch {
                    Write-Error -Message "Error updating module $($m)"
                    Write-Error -Message "$($PSItem.Exception.Message)"
                    continue
                }

                # Remove old versions of the modules
                If ($AllVersions.Count -gt 1 ) {
                    Foreach ($Version in $AllVersions) {
                        If ($Version.Version -ne $MostRecentVersion) {
                            Try {
                                Write-Host "Uninstalling previous version $($Version.Version) of module $($m)..."
                                Uninstall-Module -Name $m -RequiredVersion $Version.Version -Force -ErrorAction SilentlyContinue
                                Write-Host "$($m) are not uninstalled!" @Gr
                            } Catch {
                                Write-Error -Message "Error uninstalling previous version $($Version.Version) of module $($m)"
                                Write-Error -Message "$($PSItem.Exception.Message)"
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
            Write-Host "Installing module $($m) as it's missing..."
            Try {
                Install-Module -Name $m -Scope AllUsers -Force
                Write-Host "$($m) are now installed!" @Gr
            } Catch {
                Write-Error -Message "Could not install $($m)"
                Write-Error -Message "$($PSItem.Exception)"
                continue
            }
        }
    }
    # Collect all of the imported modules.
    $ImportedModules = Get-Module | Select-Object -Property Name, Version
    
    # Import module if it's not imported
    ForEach ($module in $NeededModules) {
        If ($module -in $ImportedModules.Name) {
            Write-Host "$($Module) are already imported!" @Gr
        } Else {
            Try {
                Write-Host "Importing $($module) module..."
                Import-Module -Name $module -Force
                Write-Host "$($module) are now imported!" @Gr
            } Catch {
                Write-Error -Message "Could not import module $($module)"
                Write-Error -Message "$($PSItem.Exception.Message)"
                continue
            }
        }
    }
}
