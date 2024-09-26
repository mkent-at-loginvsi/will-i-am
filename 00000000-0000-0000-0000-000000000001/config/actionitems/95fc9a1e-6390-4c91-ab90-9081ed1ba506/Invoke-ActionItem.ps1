<#
	.Synopsis
	Invokes the apply registry permissions action item.

	.Description
 	Invokes the specified apply registry permissions actionitem.
	
	.Parameter Actionitem
	Specifies the actionitem which to invoke.
		 
 	.Example
	$Pkg = Get-AMPackage -Name "TestPackage"
	Read-AMActionItems -Component $pkg
	$ActionSet = $Pkg.ActionSet | Select -First 1
	$ActionItem = $ActionSet.ActionItems | Select -First 1
 	Invoke-AMActionItemApplyRegistryPermissions -ActionItem $ActionItem
#>
function Invoke-AMActionItemApplyRegistryPermissions
{
	[CmdletBinding()]
	param
	(
		[parameter(Mandatory=$true,ValueFromPipeline=$true)]
		[AutomationMachine.Data.ActionItem] $ActionItem
	)
	
	Write-AMInfo "Invoking $($ActionItem.Name)"
	# Resolve the variables including the filters,
	$Variables = $ActionItem.Variables
	$Variables | % {Resolve-AMVariableFilter $_}
	$Variables | % {Resolve-AMMediaPath $_}
	
	# Get the variables from the actionitem
	$RegKey = $($Variables | ? {$_.name -eq "Registry Key"}).Value | Expand-AMEnvironmentVariables
	$Permissions = $($Variables | ? {$_.name -eq "Permissions"}).Value | Expand-AMEnvironmentVariables
	$Group = $($Variables | ? {$_.name -eq "Group"}).Value | Expand-AMEnvironmentVariables
	$Recursive = $($Variables | ? {$_.name -eq "Recursive"}).Value
	$Type = $($Variables | ? {$_.name -eq "Type"}).Value | Expand-AMEnvironmentVariables
	$Append = $($Variables | ? {$_.name -eq "Append"}).Value
	$UsePrefixSuffix = [Boolean] $($Variables | ? {$_.name -eq "AutoAdd Prefix/Suffix"}).Value
	If ($UsePrefixSuffix -eq $true)
	{
		$Group = $am_col_gprefix + $Group + $am_col_gsuffix
	}
	
	
	Set-AMPermissions -Path $RegKey -Permissions $Permissions -PrincipalName $Group -Type $Type -Recurse:$Recursive -Append:$Append
	
	
}