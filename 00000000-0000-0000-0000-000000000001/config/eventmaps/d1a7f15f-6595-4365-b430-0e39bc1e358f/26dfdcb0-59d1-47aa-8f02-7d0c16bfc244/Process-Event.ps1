[CmdletBinding()]
param (
	
	[parameter(Mandatory=$true,ValueFromPipeline=$false)]
	[AutomationMachine.Data.Plugin] $Plugin,
		
	[parameter(Mandatory=$true,ValueFromPipeline=$false)]
	[AutomationMachine.Data.Package] $Package

)

# PROCESS STARTUP EVENT FOR Generic Server

#During startup on this platform (generic server) we will simply execute all packages
Invoke-AMPluginExecution -Package $Package -Plugin $Plugin
