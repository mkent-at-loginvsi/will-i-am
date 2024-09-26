<#
	.Synopsis
	Invokes the 'Run Chocolatey Package' action item.

	.Description
 	Invokes the specified 'Run Chocolatey Package' actionitem.
	
	.Parameter Actionitem
	Specifies the actionitem which to invoke.
		 
 	.Example
	$Pkg = Get-AMPackage -Name "TestPackage"
	Read-AMActionItems -Component $pkg
	$ActionSet = $Pkg.ActionSet | Select -First 1
	$ActionItem = $ActionSet.ActionItems | Select -First 1
 	Invoke-AMActionItemInvokeChocolateyPackage -ActionItem $ActionItem
#>
function Invoke-AMActionItemInvokeChocolateyPackage
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
	$Variables | ForEach-Object {Resolve-AMVariableFilter $_}
	$Variables | ForEach-Object {Resolve-AMMediaPath $_}
	
	# Get the variables from the actionitem
	$Action = $($Variables | Where-Object {$_.name -eq "Action"}).Value | Expand-AMEnvironmentVariables
	$Package = $($Variables | Where-Object {$_.name -eq "Package"}).Value | Expand-AMEnvironmentVariables
	$Version = $($Variables | Where-Object {$_.name -eq "Version"}).Value | Expand-AMEnvironmentVariables
	$Force = [Boolean] $($Variables | Where-Object {$_.name -eq "Force"}).Value
	$Timeout = $($Variables | Where-Object {$_.name -eq "Timeout"}).Value | Expand-AMEnvironmentVariables
	$InstallerArguments = $($Variables | Where-Object {$_.name -eq "Installer arguments"}).Value | Expand-AMEnvironmentVariables
	$PackageParameters = $($Variables | Where-Object {$_.name -eq "Package parameters"}).Value | Expand-AMEnvironmentVariables
	$AdditionalArguments = $($Variables | Where-Object {$_.name -eq "Additional arguments"}).Value | Expand-AMEnvironmentVariables
	$SuccessReturnCodes = $($Variables | Where-Object {$_.name -eq "Success return codes"}).Value | Expand-AMEnvironmentVariables

	Invoke-AMChocolateyPackage -Action $Action -Package $Package -Version $Version -Force $Force -Timeout $Timeout -InstallerArguments $InstallerArguments -PackageParameters $PackageParameters -AdditionalArguments $AdditionalArguments -SuccessCodes $SuccessReturnCodes

}