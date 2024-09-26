<#
	.Synopsis
	Invokes the registry import2 action item

	.Description
 	Invokes the specified registry import2 actionitem.
	
	.Parameter Actionitem
	Specifies the actionitem which to invoke.
		 
 	.Example
	$Pkg = Get-AMPackage -Name "TestPackage"
	Read-AMActionItems -Component $pkg
	$ActionSet = $Pkg.ActionSet | Select -First 1
	$ActionItem = $ActionSet.ActionItems | Select -First 1
 	Invoke-AMActionItemRegImport2 -ActionItem $ActionItem
#>
function Invoke-AMActionItemRegImport2 {

	[CmdletBinding()]
	param
	(
		[parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[AutomationMachine.Data.ActionItem] $ActionItem
	)
	
	Write-AMInfo "Invoking $($ActionItem.Name)"
	# Resolve the variables including the filters,
	$Variables = $ActionItem.Variables
	$Variables | ForEach-Object { Resolve-AMVariableFilter $_ }
	$Variables | ForEach-Object { Resolve-AMMediaPath $_ }
	
	# Get the variables from the actionitem
	$RegFile = $($Variables | Where-Object { $_.name -eq "Registry File" }).Value.Path | Expand-AMEnvironmentVariables
	$Expand = $($Variables | Where-Object { $_.name -eq "Expand Environment Variables" }).Value
	
	
	If ($Expand) {
		Import-AMRegFile -Path $RegFile -ExpandEnvVars
	}
	else {
		Import-AMRegFile -Path $RegFile
	}
	
}