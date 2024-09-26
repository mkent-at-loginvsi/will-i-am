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
function Invoke-AMActionItemCheckForPort

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
	$Port = $($Variables | ? {$_.name -eq "Port"}).Value | Expand-AMEnvironmentVariables
	$Timer = $($Variables | ? {$_.name -eq "Poll interval"}).Value | Expand-AMEnvironmentVariables
	$remotecomps = $($Variables | ? {$_.name -eq "Computer Name"}).Value | Expand-AMEnvironmentVariables
	$PortOpen = $false
	[int] $MaxTime = $($Variables | ? {$_.name -eq "Max time to wait"}).Value | Expand-AMEnvironmentVariables

	$retry = $true
	$done = $false
	$TimeWaited = 0
	
    foreach ($remotecomp in $remotecomps.Split())
    {
	    While ($retry -eq $true) 
	    {
		    $Socket = New-Object System.Net.Sockets.TCPClient
            Try 
		    {
		        [void] $socket.connect($remotecomp, $port)
		        $PortOpen = $Socket.Connected
            } 
		    Catch {}
            if ($portOpen -eq $false)
		    {
                    Write-AMInfo "Port $Port on Computer $RemoteComp not reachable, waiting $Timer seconds"
 
				    Sleep -seconds $timer
				    $TimeWaited += $timer
				    If ($TimeWaited -ge $MaxTime)
				    {
					    $retry = $false
				    }
		    } 
		    else 
		    {
                    Write-AMInfo "Port $Port on Computer $RemoteComp reachable."
				    $done = $true
				    $retry = $false
            }

		    $Socket.Close()
	    }

	    If ($done -eq $false)
	    {
		    throw "Waited $($MaxTime) seconds for port $($Port) to become available on $($remotecomp), but still unreachable"
	    }
		$retry = $true 
    }

}





