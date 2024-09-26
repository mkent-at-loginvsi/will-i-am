<#
	.Synopsis
	Invokes the msu install action item.

	.Description
 	Invokes the specified msu install actionitem.
	
	.Parameter Actionitem
	Specifies the actionitem which to invoke.
		 
 	.Example
	$Pkg = Get-AMPackage -Name "TestPackage"
	Read-AMActionItems -Component $pkg
	$ActionSet = $Pkg.ActionSet | Select -First 1
	$ActionItem = $ActionSet.ActionItems | Select -First 1
 	Invoke-AMActionItemInstallMSU -ActionItem $ActionItem
#>


function Invoke-AMActionItemInstallMSU
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
	
	# Check the WUA service
	$WUA = gwmi win32_service | ? {$_.name -eq "wuauserv"}
	$Stop = $false
	$Disable = $false
	If ($WUA.Started -ne $true)
	{
		$Stop = $true
		If ($WUA.StartMode -eq "Disabled")
		{
			$Disable = $true
			$Return = $WUA.ChangeStartMode("Manual")
			If ($Return -ne 0)
			{
				throw "Unable to change start mode for WUA service"
			}
		}
		$Return = $WUA.StartService()
		if ($Return -ne 0)
		{
			throw "Unable to start WUA service"
		}
	}
	
	
	
	
	# Get the variables from the actionitem
	$MSUPath = $($Variables | ? {$_.name -eq "Path"}).Value.Path | Expand-AMEnvironmentVariables
	$ExpectedReturnCodes = $($Variables | ? {$_.name -eq "Success return codes"}).Value | Expand-AMEnvironmentVariables 
	
	$LogFile = Join-Path $am_workfolder "MSUinstall_$([Guid]::NewGuid().ToString()).log"
	Start-AMProcess -Path "$env:systemroot\system32\wusa.exe"  -Arguments "`"$MSUPath`" /quiet /norestart /log:`"$($LogFile)`"" -ExpectedReturncode $ExpectedReturnCodes 
	
	If ($Stop -eq $true)
	{
		$Return = $WUA.StopService()
		If ($Return -ne 0)
		{
			throw "Unable to stop WUA service"
		}
		If ($Disable -eq $true)
		{
			$Return = $WUA.ChangeStartMode("Disabled")
			If ($Return -ne 0)
			{
				"Unable to disable WUA service"
			}
		}
	}

	
}