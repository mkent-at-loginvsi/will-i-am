$PluginID = Split-Path (Split-Path (Split-Path $script:MyInvocation.MyCommand.Path -Parent) -Parent) -Leaf
$Plugin = Get-AMPlugin -Id $PluginId

Set-Variable -Name am_col_sealcmd -Scope 3 -Value ([string]  (Get-AMVariable -Id 00000000-0000-0000-0000-000000000007 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)

if (![string]::IsNullOrEmpty($am_col_sealcmd)) {
    
    Set-Variable -Name PluginEnabled -Value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000001 -ParentId $PluginID -CollectionId $am_col.Id).Value)
    Set-Variable -name am_col_template -Scope 3 -Value ([string] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000006 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value) | Expand-AMEnvironmentVariables
    Set-Variable -Name am_col_sealargs -Scope 3 -Value ([string]  (Get-AMVariable -Id 00000000-0000-0000-0000-00000000001C -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
    Set-Variable -Name am_col_removeam -Scope 3 -Value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000005 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value)
    Set-Variable -Name am_col_waitforsealcmd -Scope 3 -Value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000061 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value)
    Set-Variable -Name am_col_sealcmdreturn -Scope 3 -Value ([string] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000062 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
    Set-Variable -Name am_col_imaging_shutdown -Scope 3 -Value ([boolean] (Get-AMVariable -Id 5f8d3df9-b5ab-4e4d-8449-d4fb507592a2 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value)
    
    If ($am_aborting -eq $true)
    {
	    Write-AMInfo "System is going down for reboot, not sealing image"
    }
    elseif (((Test-AMImageDeploymentFlag) -eq $true) -or (($pluginenabled -eq $true) -and ($env:COMPUTERNAME -like $am_col_template)))
    {
        Write-AMInfo "Sealing image for distribution"
	    if ($am_col_waitforsealcmd -eq $true)
	    {
            Start-AMProcess -Path $am_col_sealcmd -Arguments $am_col_sealargs -ExpectedReturnCodes $am_col_sealcmdreturn
            if ($am_col_imaging_shutdown -eq $true) {
                shutdown.exe /s /t 30
            }
	    }
	    else
	    {
		    Start-AMProcess -Path $am_col_sealcmd -Arguments $am_col_sealargs -NoWait
	    }
    }
}