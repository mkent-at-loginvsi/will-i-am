param
(
	$Plugins
)

# INITIALIZE REBOOT EVENT ON XenApp 6.5 Session Host
# Set context
Set-Variable -Name am_context -Value "system" -Scope 3
# Some platform/event specific actions
Wait-AMSystemEvent
Enable-AMSystemEventFlag
#Disable-AMLogons

#Invoke plugin finalization scripts
ForEach ($Plugin in $Plugins)
{
    Invoke-AMPluginInitialization -Plugin $Plugin
}
If (Test-Path Variable:Plugin) {. remove-Item variable:plugin -force}