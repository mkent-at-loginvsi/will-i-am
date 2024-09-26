<#
	.Synopsis
	Invokes the Copy file action item.

	.Description
 	Invokes the specified Copy file actionitem.
	
	.Parameter Actionitem
	Specifies the actionitem which to invoke.
		 
 	.Example
	$Pkg = Get-AMPackage -Name "TestPackage"
	Read-AMActionItems -Component $pkg
	$ActionSet = $Pkg.ActionSet | Select -First 1
	$ActionItem = $ActionSet.ActionItems | Select -First 1
 	Invoke-AMActionItemCopyFile -ActionItem $ActionItem
#>
function Invoke-AMActionItemCopyFile
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
	$File = $($Variables | ? {$_.name -eq "File"})
	$Destination = $($Variables | ? {$_.name -eq "Destination"}).Value.Path | Expand-AMEnvironmentVariables
	$Overwrite = $($Variables | ? {$_.name -eq "Overwrite"}).Value
	$Expand = $($Variables | ? {$_.name -eq "Expand environment variables in file"}).Value
	
	#Get the file location
	$Path = Get-AMImportedFilePath $File
	
	#Test if destination exists, if not create it
	if (!(Test-Path $Destination)) { [void] (New-Item -ItemType Directory -Path $Destination -Force) }
	#Copy the file to the destination folder
	$DestFile = Join-Path $Destination ([System.IO.Path]::GetFileName($Path))
	
	# Copy only if destination file does not exist or already exists and override flag is set
	if (((Test-Path $DestFile) -and $Overwrite) -or (!(Test-Path $DestFile)))
	{
		if (($Expand -eq $true) -and (-not [AutomationMachine.Utilities.IO.FileUtilities]::IsBinaryFile($Path)))
		{
			$Encoding = Get-AMFileEncoding -Path $Path
			$Content = ([System.IO.File]::ReadAllText($Path) | Expand-AMEnvironmentVariables -NoEscape)
			$Content | Set-Content $DestFile -Force -Encoding $Encoding
		}
		else
		{
			[void] (Copy-Item -Path $Path -Destination $DestFile -Force)
		}
	}

}
