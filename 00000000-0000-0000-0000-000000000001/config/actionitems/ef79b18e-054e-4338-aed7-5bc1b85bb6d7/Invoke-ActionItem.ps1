<#
	.Synopsis
	Invokes the custom script action item.

	.Description
 	Invokes the specified custom script actionitem.
	
	.Parameter Actionitem
	Specifies the actionitem which to invoke.
		 
 	.Example
	$Pkg = Get-AMPackage -Name "TestPackage"
	Read-AMActionItems -Component $pkg
	$ActionSet = $Pkg.ActionSet | Select -First 1
	$ActionItem = $ActionSet.ActionItems | Select -First 1
 	Invoke-AMActionItemCustomScript -ActionItem $ActionItem
#>
function Invoke-AMActionItemCustomScript 
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
	$Script = $($Variables | ? {$_.name -eq "Script"})
	$Arguments = $($Variables | ? {$_.name -eq "Arguments"}).Value | Expand-AMEnvironmentVariables
	$SuccessCodes = $($Variables | ? {$_.name -eq "Success return codes"}).Value | Expand-AMEnvironmentVariables
	
	# Copy imported script to workfolder and stript the guid extension
	$SourceFile = Get-AMImportedFilePath $Script
	
	
	# Invoke the script
	try
	{
		$TranscriptFile = $("$env:TEMP\$(Get-Date -f yyyyMMddHHmmss)-$(Get-Random).log")
		[void] (Start-Transcript -Path $TranscriptFile)
	}
	catch
	{
		Write-AMWarning "Could not start transcript for custom script, no output will be recorded in log"
	}
	Invoke-AMCustomScript -Path $SourceFile -Arguments $Arguments -ExpectedReturncodes $SuccessCodes 	
	try
	{
		[void] (Stop-Transcript)
	}
	catch
	{
	}
	If (Test-Path $TranscriptFile)
	{
		If (-not ([string]::IsNullOrEmpty($global:am_logfile)))		
		{
			try {
				Get-Content $TranscriptFile | Out-File -FilePath $global:am_logfile -Append -Encoding "utf8" -Force
			}
			catch {
				Start-Sleep -Seconds 1
				try {
					Get-Content $TranscriptFile | Out-File -FilePath $global:am_logfile -Append -Encoding "utf8" -Force
				}
				catch {
					Write-AMWarning "Failed to add custom script logging to the AM log file, try checking `"$TranscriptFile`" for an output"
				}
			}
		}
	}
	
}