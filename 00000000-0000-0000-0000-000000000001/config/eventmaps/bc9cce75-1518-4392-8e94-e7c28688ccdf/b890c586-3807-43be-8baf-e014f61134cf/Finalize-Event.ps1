param
(
	$Plugins
)

# FINALIZE LOGON EVENT FOR RDS 2012R2 Session Host

# Setup Logon Async trigger

& "$am_env_files\config\plugins\f9dcdc52-4638-4939-870c-52f40e733d59\Optional\Setup-LogonAsync.ps1" # Copy startmenu shortcuts

# Invoke plugin initialization scripts
ForEach ($Plugin in $Plugins)
{
        Invoke-AMPluginFinalization -Plugin $Plugin
}

