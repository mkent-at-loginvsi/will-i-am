param
(
	$Plugins
)

# INITIALIZE LOGON EVENT FOR XenApp 6.5 Session Host
Start-AMSplashScreen -Text "Processing login scripts"
# Set context
Set-Variable -Name am_context -Value "user" -Scope 3

# Execute optional plugin functions


# Invoke plugin initialization scripts
ForEach ($Plugin in $Plugins)
{
        Invoke-AMPluginInitialization -Plugin $Plugin
}

# Copy start menu and desktop shortcuts
& "$am_env_files\config\plugins\a28d9155-af9a-4f2a-81f1-c85fef611a21\Optional\Copy-Shortcuts.ps1"
