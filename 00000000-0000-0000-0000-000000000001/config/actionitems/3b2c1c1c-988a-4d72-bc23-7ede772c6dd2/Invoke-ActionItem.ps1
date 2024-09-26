<#
	.Synopsis
	Invokes the Copy file2 action item.

	.Description
 	Invokes the specified Copy file2 actionitem.
	
	.Parameter Actionitem
	Specifies the actionitem which to invoke.
		 
 	.Example
	$Pkg = Get-AMPackage -Name "TestPackage"
	Read-AMActionItems -Component $pkg
	$ActionSet = $Pkg.ActionSet | Select -First 1
	$ActionItem = $ActionSet.ActionItems | Select -First 1
 	Invoke-AMActionItemCopyFile2 -ActionItem $ActionItem
#>
function Invoke-AMActionItemCopyFile2
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
	$Overwrite = $($Variables | ? {$_.name -eq "Overwrite"}).Value
	$Variables | % {Resolve-AMVariableFilter $_}
	$Variables | % {Resolve-AMMediaPath $_}
	
	# Get the variables from the actionitem
	$File = $($Variables | ? {$_.name -eq "File"}).Value.Path | Expand-AMEnvironmentVariables
	$Destination = $($Variables | ? {$_.name -eq "Destination"}).Value.Path | Expand-AMEnvironmentVariables
	
  
	
	#Test if destination exists, if not create it
	if (!(Test-Path $Destination)) {
    Write-AMInfo "Creating destination $Destination"
    [void] (New-Item -ItemType Directory -Path $Destination -Force)
  }
  
	$DestFile = Join-Path $Destination ([System.IO.Path]::GetFileName($Path))
	# Copy only if destination file does not exist or already exists and override flag is set
	if (((Test-Path $DestFile) -and $Overwrite) -or (!(Test-Path $DestFile)))
	{
		Copy-Item -Path $File -Destination $Destination -ErrorAction Stop
	}
		
	
}