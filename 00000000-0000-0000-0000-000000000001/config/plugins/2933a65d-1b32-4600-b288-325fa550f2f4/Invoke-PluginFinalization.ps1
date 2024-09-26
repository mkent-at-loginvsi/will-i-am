param(
    [parameter(Mandatory = $true, ValueFromPipeline = $false)]
    [AutomationMachine.Data.Plugin] $Plugin
)
$StatusPath = Join-Path $([AutomationMachine.Data.DataFilePath]::REGISTRY_KEY_ROOT).Replace("HKEY_LOCAL_MACHINE", "HKLM:") "Status"
$MaintenanceFlag = (Get-ItemProperty -Path $StatusPath -Name "Maintenance" -ErrorAction SilentlyContinue)
if (($null -eq $MaintenanceFlag) -or ($MaintenanceFlag.Maintenance -ne $true)) {
    Write-AMInfo "Deployment flag not set to true, not processing deployment plugin during this run"
}
else {

    if (($am_col_forcereboot -eq $true) -and ($am_pkg_installed -eq $true)) {
        Write-AMInfo "Forcing reboot after deployment"
        $AMDataManager.RebootNeeded = $true
    }

    # Cleanup environment variables
    [System.Environment]::SetEnvironmentVariable("am_wua_enabled", "", [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable("am_wua_recommended", "", [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable("am_col_forcereboot", "", [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable("am_pkg_installed", "", [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable("am_wua_other", "", [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable("am_wua_manage_service", "", [System.EnvironmentVariableTarget]::Process)

    # Cleanup global plugin variables
    Remove-Variable -name am_col_forcereboot -Scope 3
    Remove-Variable -name am_pkg_installed -Scope 3
    Remove-Variable -name am_wua_enabled -Scope 3
    Remove-Variable -name am_wua_recommended -Scope 3
    Remove-Variable -name am_wua_other -Scope 3
    Remove-Variable -name am_wua_manage_service -Scope 3

    # Disable Maintenance mode
    if (($global:am_rebooting -eq $false) -or ($global:am_aborting -eq $false)) {
        Disable-AMMaintenance
    }
}