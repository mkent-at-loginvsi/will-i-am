param(
    [parameter(Mandatory = $true, ValueFromPipeline = $false)]
    [AutomationMachine.Data.Plugin] $Plugin
)

# SCRIPT: Plugin Initialization
# PLUGIN: Deployment

If (!(Test-AMElevation)) {
    . Set-Variable -name "plugin_$($plugin.id)_enabled" -value $false
    throw "Process is not running elevated, unable to process deployment plugin"
}

$StatusPath = Join-Path $([AutomationMachine.Data.DataFilePath]::REGISTRY_KEY_ROOT).Replace("HKEY_LOCAL_MACHINE", "HKLM:") "Status"
$MaintenanceFlag = (Get-ItemProperty -Path $StatusPath -Name "Maintenance" -ErrorAction SilentlyContinue)
if (($null -eq $MaintenanceFlag) -or ($MaintenanceFlag.Maintenance -ne $true)) {
    Write-AMInfo "Deployment flag not set to true, not processing deployment plugin during this run"
}
else {
    Write-AMInfo "Deployment flag set to true, processing deployment plugin during this run"
    Set-Variable -name "plugin_$($plugin.id)_maintenance" -value $false -Scope 2
    #region Get plugin variables

    Set-Variable -Name am_col_forcereboot -value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000008 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value) -Scope 3
    Set-Variable -Name am_wua_enabled -value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-00000000001D -ParentId $Plugin.Id -CollectionId $am_col.Id).Value) -Scope 3
    Set-Variable -Name am_wua_recommended -value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-00000000001E -ParentId $Plugin.Id -CollectionId $am_col.Id).Value) -Scope 3
    Set-Variable -Name am_wua_other -value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-00000000001F -ParentId $Plugin.Id -CollectionId $am_col.Id).Value) -Scope 3
    Set-Variable -Name am_wua_manage_service -value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000027 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value) -Scope 3
    Set-Variable -Name am_pkg_installed -value ([boolean] $false) -Scope 3
    Set-Variable -Name am_wua_kb_exclusions -value ([string] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000064 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value) -Scope 3
    Set-Variable -Name am_wua_ms_update -value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000065 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value)

    #endregion

    #region Setup environment variables

    [System.Environment]::SetEnvironmentVariable("am_col_forcereboot", ($am_col_forcereboot.ToString()), [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable("am_pkg_installed", ($am_pkg_installed.ToString()), [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable("am_wua_enabled", ($am_pkg_installed.ToString()), [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable("am_wua_recommended", ($am_pkg_installed.ToString()), [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable("am_wua_other", ($am_pkg_installed.ToString()), [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable("am_wua_manage_service", ($am_pkg_installed.ToString()), [System.EnvironmentVariableTarget]::Process)

    #endregion
}