[CmdletBinding()]
param (
	
	[parameter(Mandatory=$true,ValueFromPipeline=$false)]
	[AutomationMachine.Data.Plugin] $Plugin,
		
	[parameter(Mandatory=$true,ValueFromPipeline=$false)]
	[AutomationMachine.Data.Package] $Package

)

# PROCESS LOGOFF EVENT FOR XenApp 6.5 Session Host
