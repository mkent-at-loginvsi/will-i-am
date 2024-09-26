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
function Invoke-AMActionItemCheckForRemoteService

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
	$ServiceName = $($Variables | ? {$_.name -eq "Service Name"}).Value | Expand-AMEnvironmentVariables
	$Timer = $($Variables | ? {$_.name -eq "Poll interval"}).Value | Expand-AMEnvironmentVariables
	$remotecomps = $($Variables | ? {$_.name -eq "Computer Name"}).Value | Expand-AMEnvironmentVariables
	$requiredServiceStatus = $($Variables | ? {$_.name -eq "required Service Status"}).Value | Expand-AMEnvironmentVariables
	$MaxTime = $($Variables | ? {$_.name -eq "Max time to wait"}).Value | Expand-AMEnvironmentVariables

	$serviceOK = $false
	
	$retry = $true
	$done = $false
	$TimeWaited = 0
	
	foreach ($remotecomp in $remotecomps.Split())
	{
		While ($retry -eq $true) 
		{
			
			Try 
			{
				$ServiceStatus = Get-Service -ComputerName $remotecomp -Name $ServiceName
				IF ($ServiceStatus.status -eq $requiredServiceStatus){$serviceOK = $true}
			} 
			Catch {}
			if ($serviceOK -eq $false)
			{
					Write-AMInfo "Service $Servicename on computer $RemoteComp has not the state $requiredServiceStatus waiting for $timer"
	 
					Sleep -seconds $timer
					$TimeWaited += $timer
					If ($TimeWaited -ge $MaxTime)
					{
						$retry = $false
					}
			} 
			else 
			{
					Write-AMInfo "Service $Servicename on computer $RemoteComp has the state $requiredServiceStatus"
					$done = $true
					$retry = $false
			}

			
		}

		If ($done -eq $false)
		{
			throw "Waited $($MaxTime) seconds for port $($Port) to become available on $($remotecomp), but still unreachable"
		}
		$retry = $true
	}

}





