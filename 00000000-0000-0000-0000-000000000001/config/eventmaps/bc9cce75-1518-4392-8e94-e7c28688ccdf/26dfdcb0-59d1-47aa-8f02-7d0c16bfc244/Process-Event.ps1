[CmdletBinding()]
param (
	
	[parameter(Mandatory=$true,ValueFromPipeline=$false)]
	[AutomationMachine.Data.Plugin] $Plugin,
		
	[parameter(Mandatory=$true,ValueFromPipeline=$false)]
	[AutomationMachine.Data.Package] $Package

)

# PROCESS STARTUP EVENT FOR RDS 2012R2 Session Host

#During startup on this platform (SBC) we will simply execute all packages
Invoke-AMPluginExecution -Package $Package -Plugin $Plugin
