[CmdletBinding()]
param (
	
	[parameter(Mandatory=$true,ValueFromPipeline=$false)]
	[AutomationMachine.Data.Plugin] $Plugin,
		
	[parameter(Mandatory=$true,ValueFromPipeline=$false)]
	[AutomationMachine.Data.Package] $Package

)

# PROCESS STARTUP EVENT FOR XenApp 6.5 Session Host

#During startup on this platform (XenApp65) we will simply execute all packages
Invoke-AMPluginExecution -Package $Package -Plugin $Plugin
