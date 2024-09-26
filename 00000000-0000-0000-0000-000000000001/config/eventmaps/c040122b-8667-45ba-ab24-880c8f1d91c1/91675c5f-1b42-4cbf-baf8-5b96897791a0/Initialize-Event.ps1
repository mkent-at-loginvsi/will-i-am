param
(
	$Plugins
)


# Set context
Set-Variable -Name am_context -Value "system" -Scope 3

#override abort and reboot preferences
$AMDataManager.RebootPreference = [AutomationMachine.Data.RebootPreference]::Reboot

# Some platform/event specific actions
Wait-AMSystemEvent
Write-AMStatus "Processing image sealing"
Update-AMCache
Enable-AMSystemEventFlag

# Remove background task processing
& "$am_env_files\config\plugins\6952e8c1-459a-4ed3-b4ec-2506575e2069\Optional\RemoveAMBackgroundTask.ps1" # System configuration plugin

# Get me those variables
ForEach ($Plugin in $Plugins)
{
        Invoke-AMPluginInitialization -Plugin $Plugin
}

If (Test-Path Variable:Plugin) {. remove-Item variable:plugin -force}