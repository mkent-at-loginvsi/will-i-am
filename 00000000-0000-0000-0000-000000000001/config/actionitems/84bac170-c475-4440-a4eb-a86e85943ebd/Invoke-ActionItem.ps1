<#
	.Synopsis
	Invokes the Share folder action item.

	.Description
 	Invokes the specified share folder actionitem.
	
	.Parameter Actionitem
	Specifies the actionitem which to invoke.
		 
 	.Example
	$Pkg = Get-AMPackage -Name "TestPackage"
	Read-AMActionItems -Component $pkg
	$ActionSet = $Pkg.ActionSet | Select -First 1
	$ActionItem = $ActionSet.ActionItems | Select -First 1
 	Invoke-AMActionItemShareFolder -ActionItem $ActionItem
#>
function Invoke-AMActionItemUninstallMSI
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
	$MsiPath = $($Variables | ? {$_.name -eq "Path"}).Value.Path | Expand-AMEnvironmentVariables
	$ExpectedReturnCodes = $($Variables | ? {$_.name -eq "Success return codes"}).Value | Expand-AMEnvironmentVariables
		
	UnInstall-AMMSIfile -Path "$MsiPath" -ExpectedReturnCodes $ExpectedReturnCodes
}