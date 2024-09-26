param(
	[parameter(Mandatory=$true,ValueFromPipeline=$false)]
	[AutomationMachine.Data.Plugin] $Plugin
)

#region Get plugin variables

Set-Variable -name am_col_template -Scope 3 -Value ([string] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000006 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value) | Expand-AMEnvironmentVariables
Set-Variable -Name am_col_sealcmd -Scope 3 -Value ([string]  (Get-AMVariable -Id 00000000-0000-0000-0000-000000000007 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
Set-Variable -Name am_col_sealargs -Scope 3 -Value ([string]  (Get-AMVariable -Id 00000000-0000-0000-0000-00000000001C -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
Set-Variable -Name am_col_removeam -Scope 3 -Value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000005 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value)
Set-Variable -Name am_col_waitforsealcmd -Scope 3 -Value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000061 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value)
Set-Variable -Name am_col_sealcmdreturn -Scope 3 -Value ([string] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000062 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)


[System.Environment]::SetEnvironmentVariable("am_col_template",$am_col_template,[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_col_sealcmd",$am_col_sealcmd,[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_col_sealargs",$am_col_sealargs,[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_col_removeam",($am_col_removeam.ToString()),[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_col_waitforsealcmd",($am_col_waitforsealcmd.ToString()),[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_col_sealcmdreturn",($am_col_sealcmdreturn.ToString()),[System.EnvironmentVariableTarget]::Process)

#endregion