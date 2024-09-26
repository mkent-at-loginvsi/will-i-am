param(
	[parameter(Mandatory=$true,ValueFromPipeline=$false)]
	[AutomationMachine.Data.Plugin] $Plugin
)
If ((Test-AMOSVersion -OSVersion "6.3.*") -eq $true)
{
	Import-Module ScheduledTasks
}
#region Get plugin variables


Set-Variable -name am_col_createou -Scope 3 -Value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-00000000000C -ParentId $Plugin.Id -CollectionId $am_col.Id).Value)
Set-Variable -Name am_col_ou -Scope 3 -Value ([string]  (Get-AMVariable -Id 00000000-0000-0000-0000-00000000000D -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
Set-Variable -Name am_col_movecomputers -Scope 3 -Value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-00000000000E -ParentId $Plugin.Id -CollectionId $am_col.Id).Value)
Set-Variable -Name am_col_enableschedule -Scope 3 -Value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-00000000000F -ParentId $Plugin.Id -CollectionId $am_col.Id).Value)
Set-Variable -Name am_col_autorename -Scope 3 -Value ([string]  (Get-AMVariable -Id 00000000-0000-0000-0000-000000000020 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
Set-Variable -Name am_col_renamescript -Scope 3 -Value ([AutomationMachine.Data.Types.ImportedFile]  (Get-AMVariable -Id 00000000-0000-0000-0000-000000000021 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value)
Set-Variable -Name am_col_autoadd -Scope 3 -Value ([string]  (Get-AMVariable -Id 00000000-0000-0000-0000-000000000022 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
Set-Variable -Name am_col_scheduletimer -Scope 3 -Value([string] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000010 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value)


[string]  $tmp_am_col_ou_dn = ""
$am_col_ou.Split("\") | %{$tmp_am_col_ou_dn = ",ou=$($_)" + $tmp_am_col_ou_dn};
$tmp_am_col_ou_dn = $tmp_am_col_ou_dn.TrimStart(",");
Set-Variable -Name am_col_ou_dn -Scope 3 -Value $tmp_am_col_ou_dn


#endregion

Set-Variable -Name am_col_matchvm -Scope 3 -Value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000020 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value)

#region Setup environment variables

[System.Environment]::SetEnvironmentVariable("am_col_createou",($am_col_createou.ToString()),[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_col_ou",$am_col_ou,[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_col_ou_dn",$am_col_ou_dn,[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_col_movecomputers",($am_col_movecomputers.ToString()),[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_col_enableschedule",($am_col_enableschedule.ToString()),[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_col_scheduletimer",($am_col_scheduletimer.ToString()),[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_col_matchvm",($am_col_matchvm.ToString()),[System.EnvironmentVariableTarget]::Process)

#endregion