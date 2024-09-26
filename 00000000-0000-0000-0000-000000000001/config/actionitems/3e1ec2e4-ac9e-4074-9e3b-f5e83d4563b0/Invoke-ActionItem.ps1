<#
	.Synopsis
	Invokes the apply file permissions action item.

	.Description
 	Invokes the specified install true type fonts actionitem.
	
	.Parameter Actionitem
	Specifies the actionitem which to invoke.
		 
 	.Example
	$Pkg = Get-AMPackage -Name "TestPackage"
	Read-AMActionItems -Component $pkg
	$ActionSet = $Pkg.ActionSet | Select -First 1
	$ActionItem = $ActionSet.ActionItems | Select -First 1
 	Invoke-AMActionItemInstallTTF -ActionItem $ActionItem
#>
function Invoke-AMActionItemCheckForFile

{
	[CmdletBinding()]
	param
	(
		[parameter(Mandatory=$true,ValueFromPipeline=$true)]
		[AutomationMachine.Data.ActionItem] $ActionItem
	)
	
	Write-AMInfo "Invoking $($ActionItem.ActionItemTemplate.Name)"
	# Resolve the variables including the filters,
	$Variables = $ActionItem.Variables
	$Variables | % {Resolve-AMVariableFilter $_}
	$Variables | % {Resolve-AMMediaPath $_}
	
	# Get the variables from the actionitem
	$FileName = $($Variables | ? {$_.name -eq "Path"}).Value | Expand-AMEnvironmentVariables
	$Timer = $($Variables | ? {$_.name -eq "Poll interval"}).Value | Expand-AMEnvironmentVariables
	$MaxTime = $($Variables | ? {$_.name -eq "Max time to wait"}).Value | Expand-AMEnvironmentVariables

	$FileOK = $false
	
	$retry = $true
	$done = $false
	$TimeWaited = 0
	
	While ($retry -eq $true) 
	{
		
        Try 
		{
			$FileOK = Test-path $FileName
        } 
		Catch 
		{
			$FileOk = $false
		}
        if ($FileOK -eq $false)
		{
                Write-AMInfo "$filename does not exist yet,  waiting for $timer"
 
				Sleep -seconds $timer
				$TimeWaited += $timer
				If ($TimeWaited -ge $MaxTime)
				{
					$retry = $false
				}
		} 
		else 
		{
                Write-AMInfo "File $filename exists, continue now"
				$done = $true
				$retry = $false
        }

		
	}

	If ($done -eq $false)
	{
		throw "Waited $($MaxTime) seconds for $filename to become available, finish waiting now"
	}

}





