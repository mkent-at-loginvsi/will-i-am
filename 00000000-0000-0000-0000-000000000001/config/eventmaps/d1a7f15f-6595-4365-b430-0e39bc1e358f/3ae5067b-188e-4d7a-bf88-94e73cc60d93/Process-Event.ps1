[CmdletBinding()]
param (
	
	[parameter(Mandatory=$true,ValueFromPipeline=$false)]
	[AutomationMachine.Data.Plugin] $Plugin,
		
	[parameter(Mandatory=$true,ValueFromPipeline=$false)]
	[AutomationMachine.Data.Package] $Package

)

# PROCESS SYSTEM SCHEDULED EVENT FOR Generic Server

[Boolean] $EnableSchedule = (Get-AMVariable -Id 00000000-0000-0000-0000-00000000000F -ParentId $Plugin.Id -CollectionId $am_col.Id).Value
if ($EnableSchedule -eq $true)
{
	# During scheduled execution, we should only execute select configurations.
	[Boolean] $ShouldBeProcessedInBackground = [Boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-00000000000B -ParentId $Plugin.Id -CollectionId $am_col.Id -ComponentId $Package.Id).Value
	if ($ShouldBeProcessedInBackground -eq $true)
	{
		[Boolean] $AreRemoteUsersOnline = $false
		[Boolean] $CanBeAppliedWhenUsersAreOnline = [Boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-00000000000A -ParentId $Plugin.Id -CollectionId $am_col.Id -ComponentId $Package.Id).Value

#region Check for remotely logged-on users

if ((Get-AMLoggedOnUsers | Measure-Object).Count -gt 0) {
	Write-AMInfo "Logged on users detected"
	$AreRemoteUsersOnline = $true
}

#endregion
	
		if (($AreRemoteUsersOnline -eq $false) -or (($AreRemoteUsersOnline -eq $true) -and ($CanBeAppliedWhenUsersAreOnline -eq $true)))
		{
			
			Write-AMInfo "Background processing $($Package.Name)"
			Invoke-AMPluginExecution -Package $Package -Plugin $Plugin
		}
		else
		{
			Write-AMInfo "Background processing of $($Package.Name) while users are online is not allowed"
		}
	}
	else
	{
		Write-AMInfo "Background processing of $($Package.Name) is not allowed"
	}
}
else
{
	Write-AMInfo "Background processing disabled on collection"
}