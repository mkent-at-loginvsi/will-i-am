$TaskName = "Automation Machine Scheduled System Configuration"
$PluginID = Split-Path (Split-Path (Split-Path $script:MyInvocation.MyCommand.Path -Parent) -Parent) -Leaf
$Plugin = Get-AMPlugin -Id $PluginId
Set-Variable -Name PluginEnabled -Value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000001 -ParentId $PluginID -CollectionId $am_col.Id).Value)


If ($am_aborting -eq $true)
{
	Write-AMInfo "System is going down for reboot, not removing background tasks"
}
else
{
	# Remove scheduled tasks
	$TaskService = New-Object -com Schedule.Service
	$TaskService.Connect()
	$RootFolder = $TaskService.GetFolder("\")
	$AMFolder = $RootFolder.GetFolders(1) | ? {$_.Name -eq "Automation Machine"}
	If ($AMFolder -is [object])
	{
		try	
		{
			$AMFolder.GetTask("Automation Machine Scheduled System Configuration") | % {$AMFolder.DeleteTask($_.name,0)}
		}
		catch
		{
				Write-AMWarning "Unable to remove scheduled background task"
		}
	}	
}