param(
	[parameter(Mandatory=$true,ValueFromPipeline=$false)]
	[AutomationMachine.Data.Plugin] $Plugin
)

# Get groups information
Set-Variable -name am_col_gprefix -Scope 3 -Value ([string] (Get-AMVariable -Id "00000000-0000-0000-0000-000000000014" -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
Set-Variable -Name am_col_gsuffix -Scope 3 -Value ([string] (Get-AMVariable -Id "00000000-0000-0000-0000-000000000018" -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
Set-Variable -Name am_col_gdescription -Scope 3 -Value ([string] (Get-AMVariable -Id "00000000-0000-0000-0000-000000000024" -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)

Set-Variable -Name am_col_gou -Scope 3 -Value ([string] (Get-AMVariable -Id "00000000-0000-0000-0000-000000000013" -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)	
Set-Variable -Name am_col_gscope -Scope 3 -Value ([AutomationMachine.Plugins.ActiveDirectory.GroupScope] (Get-AMVariable -Id "00000000-0000-0000-0000-000000000019" -ParentId $Plugin.Id -CollectionId $am_col.Id).Value.ToString())
Set-Variable -Name am_col_createpgroups -Scope 3 -Value ([Boolean] (Get-AMVariable -Id "00000000-0000-0000-0000-00000000001A" -ParentId $Plugin.Id -CollectionId $am_col.Id).Value)

# OU translation
[string]  $tmp_am_col_gou_dn = ""
$am_col_gou.Split("\") | %{$tmp_am_col_gou_dn = ",ou=$($_)" + $tmp_am_col_gou_dn};
$tmp_am_col_gou_dn = $tmp_am_col_gou_dn.TrimStart(",");
Set-Variable -Name am_col_gou_dn -Scope 3 -Value $tmp_am_col_gou_dn

	
	