[CmdletBinding()]
param (
	
	[parameter(Mandatory=$true,ValueFromPipeline=$false)]
	[AutomationMachine.Data.Plugin] $Plugin,
		
	[parameter(Mandatory=$true,ValueFromPipeline=$false)]
	[AutomationMachine.Data.Package] $Package

)

# EXEC SEAL Event on Generic Server

#During startup on this platform (SBC) we will simply execute all packages
#if ($am_col_template -eq $env:COMPUTERNAME)
#{
    Invoke-AMPluginExecution -Package $Package -Plugin $Plugin
#}