<#
	.Synopsis
	Invokes the Filetype association action item.

	.Description
 	Invokes the specified Filetype association actionitem.
	
	.Parameter Actionitem
	Specifies the actionitem which to invoke.
		 
 	.Example
	$Pkg = Get-AMPackage -Name "TestPackage"
	Read-AMActionItems -Component $pkg
	$ActionSet = $Pkg.ActionSet | Select -First 1
	$ActionItem = $ActionSet.ActionItems | Select -First 1
 	Invoke-AMActionFileTypeAssociation -ActionItem $ActionItem
#>
function Invoke-AMActionFileTypeAssociation
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
	$Extensions = $($Variables | ? {$_.name -eq "Extensions"}).Value | Expand-AMEnvironmentVariables
	$Application = $($Variables | ? {$_.name -eq "Application"}).Value.Path | Expand-AMEnvironmentVariables
	$Scope = $($Variables | ? {$_.name -eq "Scope"}).Value | Expand-AMEnvironmentVariables
		
	# Test if application exists
	If (!(Test-Path $Application)) {throw "Could not find path $($Application), make sure it exists"}
		
	# Split extensions on ; and ,
	ForEach ($Ext in $Extensions.Split(";,"))
	{
		If (!($Ext.StartsWith("."))) {$Ext = $Ext.Insert(0,".")}
		If ($Scope -eq "Machine")
		{
			If (!(Test-AMElevation)) {throw "Process not running elevated, cannot set filetype association for machine scope"}
			Register-AMFileType -Extension $Ext -Application $Application -LocalMachine
		}
		else
		{
			Register-AMFileType -Extension $Ext -Application $Application
		}
	}
}