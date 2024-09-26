param
(
	$Plugins
)

# INITIALIZE LOGONASYNC EVENT FOR XenApp 6.5 Session Host
Start-AMSplashScreen -Text "Processing login scripts"
# Set context
Set-Variable -Name am_context -Value "user" -Scope 3
# Invoke plugin initialization scripts
ForEach ($Plugin in $Plugins)
{
        Invoke-AMPluginInitialization -Plugin $Plugin
}
If (Test-Path Variable:Plugin) {. remove-Item variable:plugin -force}