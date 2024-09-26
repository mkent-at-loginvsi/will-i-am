param
(
	$Plugins
)

# FINALIZE REBOOT EVENT ON RDS 2012R2 Session Host

# Set RDS Maitenance Flag
& "$am_env_files\config\plugins\6952e8c1-459a-4ed3-b4ec-2506575e2069\Optional\EnableRDSHostMaintenance.ps1" # Move RDSH to maintenance collection


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