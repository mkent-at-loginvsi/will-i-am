param(
	[parameter(Mandatory=$true,ValueFromPipeline=$false)]
	[AutomationMachine.Data.Plugin] $Plugin
)

#Cleanup global vars
#Remove-Variable -name am_col_gprefix -Scope 3
#Remove-Variable -Name am_col_gsuffix -Scope 3
