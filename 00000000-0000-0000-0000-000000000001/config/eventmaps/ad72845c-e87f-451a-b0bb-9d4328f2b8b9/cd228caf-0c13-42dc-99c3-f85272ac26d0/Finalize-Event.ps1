param
(
	$Plugins
)

# FINALIZE REBOOT EVENT ON XenApp 6.5 Session Host



#Invoke plugin initialization scripts
ForEach ($Plugin in $Plugins)
{
    Invoke-AMPluginFinalization -Plugin $Plugin
}
If (Test-Path Variable:Plugin) {. remove-Item variable:plugin -force}


Disable-AMSystemEventFlag

Enable-AMMaintenance


# Reboot the computer
Restart-AMComputer