<#
	.Synopsis
	Invokes the registry import action item

	.Description
 	Invokes the specified registry import actionitem.
	
	.Parameter Actionitem
	Specifies the actionitem which to invoke.
		 
 	.Example
	$Pkg = Get-AMPackage -Name "TestPackage"
	Read-AMActionItems -Component $pkg
	$ActionSet = $Pkg.ActionSet | Select -First 1
	$ActionItem = $ActionSet.ActionItems | Select -First 1
 	Invoke-AMActionItemRegImport -ActionItem $ActionItem
#>
function Invoke-AMActionItemRegImport 
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
	$RegFile = $($Variables | ? {$_.name -eq "Registry File"})
	$Expand = $($Variables | ? {$_.name -eq "Expand Environment Variables in file"}).Value
	
	# Copy imported script to workfolder and stript the guid extension
	$SourceFile = Get-AMImportedFilePath $RegFile
	
	
	
	
	If ($Expand)
	{
		Import-AMRegFile -Path $SourceFile -ExpandEnvVars
	}
	else
	{
		Import-AMRegFile -Path $SourceFile
	}

	
}