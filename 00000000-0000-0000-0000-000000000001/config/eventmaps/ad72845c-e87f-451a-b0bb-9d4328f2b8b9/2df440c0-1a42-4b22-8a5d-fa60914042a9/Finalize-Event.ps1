param
(
	$Plugins
)

# FINALIZE LOGONASYNC EVENT FOR XenApp 6.5 Session Host

# Invoke plugin initialization scripts
ForEach ($Plugin in $Plugins)
{
        Invoke-AMPluginFinalization -Plugin $Plugin
}
If (Test-Path Variable:Plugin) {. remove-Item variable:plugin -force}