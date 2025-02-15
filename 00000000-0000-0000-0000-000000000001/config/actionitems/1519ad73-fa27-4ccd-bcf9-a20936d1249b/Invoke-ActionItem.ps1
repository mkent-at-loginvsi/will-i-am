<#
	.Synopsis
	Invokes the Install MSP install action item.

	.Description
 	Invokes the specified Install MSP install action item.
	
	.Parameter Actionitem
	Specifies the actionitem which to invoke.
		 
 	.Example
	$Pkg = Get-AMPackage -Name "TestPackage"
	Read-AMActionItems -Component $pkg
	$ActionSet = $Pkg.ActionSet | Select -First 1
	$ActionItem = $ActionSet.ActionItems | Select -First 1
 	Invoke-AMActionItemInstallMSP -ActionItem $ActionItem
#>
function Invoke-AMActionItemInstallMSP
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
	$MspPath = $($Variables | ? {$_.name -eq "Path"}).Value.Path | Expand-AMEnvironmentVariables
	$Parameters = $($Variables | ? {$_.name -eq "Parameters"}).Value | Expand-AMEnvironmentVariables
	$ExpectedReturnCode = $($Variables | ? {$_.name -eq "Success return codes"}).Value | Expand-AMEnvironmentVariables

	$argumentlist = "/p `"" + $MspPath + "`" " + $parameters
	[System.Diagnostics.Process] $Process = New-Object System.Diagnostics.Process
	[System.Diagnostics.ProcessStartInfo] $StartInfo = New-Object System.Diagnostics.ProcessStartInfo
	
	$StartInfo.FileName = "msiexec.exe"
	$StartInfo.Arguments = $argumentlist
	$StartInfo.UseShellExecute = $false
	$StartInfo.RedirectStandardOutput = $false
	$StartInfo.RedirectStandardError = $false
	$StartInfo.RedirectStandardInput = $false
		
	$Process.StartInfo = $StartInfo
	[void] $Process.Start()
		
	$ProcessID = $Process.Id
	if ([string]::IsNullOrEmpty($ProcessID))
	{
		throw "Process launch of msiexec.exe failed for unknown reasons"
	}
	else
	{
		Write-AMInfo "Started process with id $ProcessID (msiexec.exe)"
		Write-AMInfo "Command: msiexec.exe $($StartInfo.Arguments)"
	}
		
	[void] $Process.WaitForExit()
	Write-AMInfo "Process with id $ProcessID (msiexec.exe) exited with ExitCode $($Process.ExitCode)"
	
	If (!$($ExpectedReturnCode.Split().Contains($Process.ExitCode.ToString())))
	{
		Test-AMMsiExecResult -ExitCode $Process.ExitCode
	}
    else
	{		
		Write-AMInfo "MSIEXEC: installed successfully with expected return code: $($Process.ExitCode)"
		if ($Process.Exitcode -eq 3010)
		{
			$AMDataManager.RebootNeeded = $true
		}        		
	}	
}
