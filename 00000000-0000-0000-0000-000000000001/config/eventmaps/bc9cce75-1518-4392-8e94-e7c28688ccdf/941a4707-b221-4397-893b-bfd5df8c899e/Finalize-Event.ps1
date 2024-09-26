param
(
	$Plugins
)

# FINALIZE SYSTEMMAINTENANCE EVENT ON RDS 2012R2 Session Host with maintenance



#Invoke plugin initialization scripts
ForEach ($Plugin in $Plugins)
{
    Invoke-AMPluginFinalization -Plugin $Plugin
}
If (Test-Path Variable:Plugin) {. remove-Item variable:plugin -force}

# Reset systemevent flag
Disable-AMSystemEventFlag

