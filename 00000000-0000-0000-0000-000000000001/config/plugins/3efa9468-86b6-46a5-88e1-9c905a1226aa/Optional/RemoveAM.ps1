Param(

    [Parameter(Mandatory = $false)] 
    [Switch]$Force = $false
 
)

$PluginID = Split-Path (Split-Path (Split-Path $script:MyInvocation.MyCommand.Path -Parent) -Parent) -Leaf
Set-Variable -Name PluginEnabled -Value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000001 -ParentId $PluginID -CollectionId $am_col.Id).Value)
Set-Variable -Name removeam -Value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000005 -ParentId 3efa9468-86b6-46a5-88e1-9c905a1226aa -CollectionId $am_col.Id).Value)
if (-not (Test-Path variables:\am_col_removeam)) {
    Set-Variable -Name am_col_removeam -Value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000005 -ParentId 3efa9468-86b6-46a5-88e1-9c905a1226aa -CollectionId $am_col.Id).Value)
}

$FirstBoot = $False
try {
    $FirstBoot = [boolean] (Get-ItemProperty -Path "HKLM:\SOFTWARE\Automation Machine\Status" -Name FirstBootAfterSeal -ErrorAction SilentlyContinue).FirstBootAfterSeal
    
}
catch {}

if ((($am_aborting -ne $true) -and ($pluginenabled -eq $true) -and ($am_col_removeam -eq $true) -and ($FirstBoot -eq $true)) -or $Force) {
    Write-AMInfo "Removing AM from computer"
    
    # Remove scheduled tasks
    $TaskService = New-Object -com Schedule.Service
    $TaskService.Connect()
    $RootFolder = $TaskService.GetFolder("\")
    $AMFolder = $RootFolder.GetFolders(1) | Where-Object { $_.Name -eq "Automation Machine" }
    If ($AMFolder -is [object]) {
        $AMFolder.GetTasks(1) | ForEach-Object { $AMFolder.DeleteTask($_.name, 0) }
        $RootFolder.DeleteFolder($AMFolder.Name, 0)
    }

    # Stop AM processes and services
    Stop-AMProcess -Name "AMUsageReporter" -Retry 20
    Stop-AMService -Name "AMAppUsage" -Wait -Seconds 30
    Stop-AMService -Name "Login AM App Store Service" -Wait -Seconds 30

    try {
        sc.exe delete "AMAppUsage"
        sc.exe delete "Login AM App Store Service"
    } 
    catch {}
    
    # Remove cache folders
    if (!(Test-Path $am_cache)) {
        $am_cache = Join-Path -Path $env:ProgramData -ChildPath 'Automation Machine'
    }
    $LogPath = Join-Path -Path $am_cache -ChildPath 'Logging'

    if (Test-Path $am_cache) {
        Get-ChildItem -Path $am_cache -Recurse |
        Select-Object -ExpandProperty FullName |
        Where-Object { $_ -notlike "$LogPath*" } |
        Sort-Object length -Descending |
        Remove-Item -Recurse -Force -ErrorAction Ignore
    }

    # Remove module
    Remove-Item -Path "$($pshome)\modules\amclient" -Recurse -Force -ErrorAction Ignore

    # Remove registry keys
    Remove-Item -Path 'HKLM:\SOFTWARE\Automation Machine' -Recurse -Force -ErrorAction Ignore
    Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\LoginAM Client' -Recurse -Force -ErrorAction Ignore

    # Remove environment variables
    [System.Environment]::SetEnvironmentVariable("am_env_files", "", [System.EnvironmentVariableTarget]::Machine)
    [System.Environment]::SetEnvironmentVariable("am_env_files", "", [System.EnvironmentVariableTarget]::Machine)
    [System.Environment]::SetEnvironmentVariable("am_env_name", "", [System.EnvironmentVariableTarget]::Machine)
    [System.Environment]::SetEnvironmentVariable("am_env_prefix", "", [System.EnvironmentVariableTarget]::Machine)
    [System.Environment]::SetEnvironmentVariable("am_files", "", [System.EnvironmentVariableTarget]::Machine)
    [System.Environment]::SetEnvironmentVariable("am_shell", "", [System.EnvironmentVariableTarget]::Machine)
    
    #$global:am_aborting = $true
    exit 3010
}
else {
    Write-AMInfo "Plugin is disabled, Remove AM is not enabled or it isn't the computer's first boot"	
}