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
function Invoke-AMActionItemInstallMSI2
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
	$Transform = $($Variables | ? {$_.name -eq "Transform file"}).Value.Path | Expand-AMEnvironmentVariables
	$Properties = $($Variables | ? {$_.name -eq "Properties"}).Value.ToString(" ") | Expand-AMEnvironmentVariables
	$ExpectedReturnCodes = $($Variables | ? {$_.name -eq "Success return codes"}).Value | Expand-AMEnvironmentVariables 

	if ((-not [string]::IsNullOrEmpty($Properties)) -and (-not [string]::IsNullOrEmpty($Transform)))
	{
		Install-AMMSIFile -Path "$MsiPath" -Properties $Properties -Transforms "$Transform" -ExpectedReturnCodes $ExpectedReturnCodes
	} 
	elseif ((-not [string]::IsNullOrEmpty($Properties)) -and ([string]::IsNullOrEmpty($Transform)))
	{
		Install-AMMSIFile -Path "$MsiPath" -Properties $Properties -ExpectedReturnCodes $ExpectedReturnCodes
	} 
	elseif (([string]::IsNullOrEmpty($Properties)) -and (-not [string]::IsNullOrEmpty($Transform)))
	{
		Install-AMMSIFile -Path "$MsiPath" -Transforms "$Transform" -ExpectedReturnCodes $ExpectedReturnCodes
	} 
	else
	{
		Install-AMMSIFile -Path "$MsiPath" -ExpectedReturnCodes $ExpectedReturnCodes
	}
	
}