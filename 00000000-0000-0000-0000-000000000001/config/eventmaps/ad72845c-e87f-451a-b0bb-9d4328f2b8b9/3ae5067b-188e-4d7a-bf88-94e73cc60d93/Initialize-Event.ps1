param
(
	$Plugins
)

# Set context
Set-Variable -Name am_context -Value "system" -Scope 3
Set-Variable -name am_disablestatuslogging -value $true -scope 3


# INITIALIZE SYSTEM SCHEDULED EVENT FOR Generic Server
Wait-AMSystemEvent
#Write-AMStatus "Processing Scheduled System Configuration"
Update-AMCache
Enable-AMSystemEventFlag
Update-AMGroupPolicyObjects

ForEach ($Plugin in $Plugins)
{
    Invoke-AMPluginInitialization -Plugin $Plugin
}
If (Test-Path Variable:Plugin) {. remove-Item variable:plugin -force}