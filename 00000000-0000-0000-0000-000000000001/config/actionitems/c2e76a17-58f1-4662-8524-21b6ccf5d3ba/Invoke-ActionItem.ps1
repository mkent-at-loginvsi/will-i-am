<#
	.Synopsis
	Invokes the Append Registry String action item.

	.Description
 	Invokes the specified Append Registry String actionitem.
	
	.Parameter Actionitem
	Specifies the actionitem which to invoke.
		 
 	.Example
	$Pkg = Get-AMPackage -Name "TestPackage"
	Read-AMActionItems -Component $pkg
	$ActionSet = $Pkg.ActionSet | Select -First 1
	$ActionItem = $ActionSet.ActionItems | Select -First 1
 	Invoke-AMActionItemRegAppend -ActionItem $ActionItem
#>
function Invoke-AMActionItemRegAppend
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
	$RegKey = $($Variables | ? {$_.name -eq "Registry key"}).Value | Expand-AMEnvironmentVariables
	$RegValue = $($Variables | ? {$_.name -eq "Name"}).Value | Expand-AMEnvironmentVariables
	$StringToAppend = $($Variables | ? {$_.name -eq "String to append"}).Value | Expand-AMEnvironmentVariables
	If (-not (Test-Path $Regkey))
	{
		throw "The registry key: $($RegKey) does not exist, unable to append the string"
	}
	else
	{	
		$Reg = Get-Item $RegKey
		if ($Reg.GetValue($RegValue) -eq $null)
		{
			throw "The registry value: $($RegValue) doesn't exist at $($RegKey), unable to append the string"
		}
		else
		{
			Add-AMRegistryString -Path $RegKey -Name $RegValue -Value $StringToAppend 
		}
	}
	
	
	
	
}