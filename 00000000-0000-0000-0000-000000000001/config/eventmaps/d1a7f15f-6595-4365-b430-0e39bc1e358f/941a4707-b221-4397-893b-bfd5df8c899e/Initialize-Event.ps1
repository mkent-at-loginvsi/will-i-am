param
(
	$Plugins
)

# INITIALIZE SYSTEMMAINTENANCE EVENT ON Generic Server
# Set context
Set-Variable -Name am_context -Value "system" -Scope 3

# Update the cache to make sure we have the latest configured settings for maintenance
Update-AMCache

#Invoke plugin initialization scripts
foreach ($Plugin in $Plugins)
{
    Invoke-AMPluginInitialization -Plugin $Plugin
}
if (Test-Path Variable:Plugin) {. Remove-Item variable:plugin -Force}

Invoke-AMMaintenance