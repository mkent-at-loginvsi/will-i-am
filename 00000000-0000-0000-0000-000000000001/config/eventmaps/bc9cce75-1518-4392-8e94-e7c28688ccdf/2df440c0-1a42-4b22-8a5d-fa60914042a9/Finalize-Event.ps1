param
(
	$Plugins
)

# FINALIZE LOGONASYNC EVENT FOR RDS 2012R2 Session Host

# Invoke plugin initialization scripts
ForEach ($Plugin in $Plugins)
{
        Invoke-AMPluginFinalization -Plugin $Plugin
}
If (Test-Path Variable:Plugin) {. remove-Item variable:plugin -force}