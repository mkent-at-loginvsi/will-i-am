param
(
	$Plugins
)

# FINALIZE SYSTEM SCHEDULED EVENT FOR Generic Server


ForEach ($Plugin in $Plugins)
{
    Invoke-AMPluginFinalization -Plugin $Plugin
}
If (Test-Path Variable:Plugin) {. remove-Item variable:plugin -force}
#Write-AMStatus "Ready"
Disable-AMSystemEventFlag
& "$am_env_files\config\plugins\3572102e-07be-4112-ac2c-a214179f420c\Optional\SetupMaintSchTasks.ps1" # Maintenance plugin