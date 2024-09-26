param(
	[parameter(Mandatory=$true,ValueFromPipeline=$false)]
	[AutomationMachine.Data.Plugin] $Plugin
)

Set-Variable -name am_col_gprefix -Scope 3 -Value ([string] (Get-AMVariable -Id "00000000-0000-0000-0000-000000000014" -ParentId "896667bf-44d2-4d4d-aeb3-4ece60dfe264" -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
Set-Variable -Name am_col_gsuffix -Scope 3 -Value ([string] (Get-AMVariable -Id "00000000-0000-0000-0000-000000000018" -ParentId "896667bf-44d2-4d4d-aeb3-4ece60dfe264" -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
