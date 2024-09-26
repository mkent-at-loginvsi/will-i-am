param(
	[parameter(Mandatory=$true,ValueFromPipeline=$false)]
	[AutomationMachine.Data.Plugin] $Plugin
)

# Cleanup global plugin variables
# Get groups information
Remove-Variable -name am_col_gprefix -Scope 3
Remove-Variable -Name am_col_gsuffix -Scope 3
Remove-Variable -Name am_col_gdescription -Scope 3
Remove-Variable -Name am_col_gou -Scope 3
Remove-Variable -Name am_col_gscope -Scope 3
Remove-Variable -Name am_col_createpgroups -Scope 3
Remove-Variable -Name am_col_gou_dn -Scope 3
