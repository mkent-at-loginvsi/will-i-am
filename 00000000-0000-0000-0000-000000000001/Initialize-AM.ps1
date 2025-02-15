<#
	.Synopsis
	Initializes Automation Machine.

	.Description
 	Initializes Automation Machine on a machine where the script was invoked.

	.Example
	\\server\\AMShare\EnvironmentId\Initialize-AM.ps1
#>

[CmdletBinding()]
param(
    [switch]$NoReboot,
    [int] $ProcessToKill = -1,
    [switch] $ImageManagementDeployment,
    [switch] $AddTaskPrefix
)

$VerboseMode = $MyInvocation.BoundParameters.ContainsKey("Verbose")
$ScriptPath = Split-Path $MyInvocation.MyCommand.Definition -Parent

$TranscriptFolder = "$env:programdata\Automation Machine\Logging"
$TranscriptFileName = "Initialization_$(Get-Date -f yyyyMMddHHmmss)-$(Get-Random).log"
$TranscriptPath = Join-Path -Path $TranscriptFolder -ChildPath $TranscriptFileName

if (!(Test-Path $TranscriptFolder)) {
    New-Item -ItemType "directory" -Path $TranscriptFolder
}
Start-Transcript -Path $TranscriptPath -Force

if ($ProcessToKill -ne -1) {
    Stop-Process -Id $ProcessToKill -Force
    try {
        Wait-Process -Id $ProcessToKill -Timeout 30 -ErrorAction Stop
    }
    catch {
        Write-Verbose $_.Message
    }
}

Set-Location $env:systemdrive

Write-Host "Initializing AM for computer: $env:computername"

& (Join-Path $ScriptPath "Initialize-AMFunctions.ps1")

Initialize-AMTask "Checking for elevation" {
    If (!(Test-AMElevation)) { throw "Process is not running elevated, unable to initialize" }
}

Initialize-AMTask "Checking .NET & powershell version" {
    Try {
        $Version = (Get-ItemProperty ‘HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full’).Release
        If (-not($Version -ge 379893)) { throw "Microsoft .NET 4.5.2 is not installed, unable to initialize" }
    }
    catch {
        throw "Microsoft .NET 4.5.2 is not installed, unable to initialize"
    }
    If (-not (Test-Path variable:PSSenderInfo)) {
        If (-not ($host.Version.Major -ge 3)) {
            throw "Powershell v3 or higher is required for AM, detected version: $($host.Version)"
        }
    }
}

$script:ErrorActionPreference = "Stop"
$global:AmInitializationMode = $true

$Module = Get-Module -Name "AMClient"
if ($Module -is [object]) {
    Write-Verbose "Unloading client module"
    Remove-Module -Name "AMClient" -Force
}

$ScriptPath = Split-Path $MyInvocation.MyCommand.Definition -Parent
$AMCentralPath = Split-Path $ScriptPath -Parent
Write-Verbose "Central path: $AMCentralPath"
$AMLocalPath = Join-Path $Env:ALLUSERSPROFILE "Automation Machine"
Write-Verbose "Local path: $AMLocalPath"
$AMEnvironmentFolder = Split-Path $ScriptPath -Leaf
Write-Verbose "Environment: $AMEnvironmentFolder"
$AMRegKeyRoot = "HKLM:\SOFTWARE\Automation Machine"
Write-Verbose "Registry location: $AMRegKeyRoot"
$CentralBin = Join-Path $ScriptPath "bin"
$LocalBin = Join-Path $AMLocalPath "Bin"

& (Join-Path $ScriptPath "Initialize-AMFunctions.ps1")

if (-not (Test-Path $AMLocalPath)) {
    Initialize-AMTask "Creating AM Local Path" {
        [void] (New-Item -ItemType Directory -Path $AMLocalPath -Force)
    }
}
$ServiceHost = (New-Object System.Uri($AMCentralPath)).Host
$ServiceBaseAddress = [string]::Format("http://{0}:{1}/", "localhost", 80)
if (![string]::IsNullOrEmpty($ServiceHost)) {
    $ServiceBaseAddress = [string]::Format("http://{0}:{1}/", $ServiceHost, 80)
}

#region uninstall AppStore service
Initialize-AMTask "Removing old AppStore service instances" {
    $Service = Get-WmiObject win32_service | Where-Object { $_.name -eq "Automation Machine App Store Service" }
    If ($Service -ne $null) {
        Invoke-Expression "& '$($Service.PathName)' -uninstall"
    }
}

#endregion

#region Create registry keys
Initialize-AMTask "Creating registry keys" {
    if (-not (Test-Path $AMRegKeyRoot)) {
        Write-Verbose "Creating registry key for Automation Machine:`n    $AMRegKeyRoot"
        [void] (New-Item -Path $AMRegKeyRoot -Force)
    }
    Write-Verbose "Setting registry value for AMCentralPath"
    Set-ItemProperty -Path "$AMRegKeyRoot" -Name "AMCentralPath" -Value $AMCentralPath -Force
    Write-Verbose "Setting registry value for AMLocalPath"
    Set-ItemProperty -Path "$AMRegKeyRoot" -Name "AMLocalPath" -Value $AMLocalPath -Force
    Write-Verbose "Setting registry value for AMEnvironment"
    Set-ItemProperty -Path "$AMRegKeyRoot" -Name "AMEnvironment" -Value $AMEnvironmentFolder -Force
    Write-Verbose "Setting registry value for ServiceBaseAddress"
    Set-ItemProperty -Path "$AMRegKeyRoot" -Name "ServiceBaseAddress" -Value $ServiceBaseAddress -Force
    if ($ImageManagementDeployment -eq $true) {
        Write-Verbose "Setting registry value for ImageManagementDeployment"
        Set-ItemProperty -Path "$AMRegKeyRoot" -Name "ImageManagementDeployment" -Value "True" -Force
    }
}
#endregion

#region Load AM admin module and get collection for computer
Initialize-AMTask "Checking computer/collection configuration" {
    Write-Host ""
    Import-Module "$CentralBin\modules\admin\Automation Machine.psm1" -Force
    Write-AMStatus "Initializing"
    $Collection = Get-AMCollection -Current

    if ($Collection -isnot [object]) {
        throw "Could not determine collection"
    }

    #region Validate user credentials

    $ServiceAccount = Get-AMServiceAccount
    $domain = Get-AMDomain
    $username = $ServiceAccount.UserName.Split('\\')[1]
    $password = $ServiceAccount.Password

    try {
        [AutomationMachine.Utilities.Windows.Authentication]::ValidateUser($username, $password, $domain)
    }
    catch {
        throw "Unable to authenticate service account with AD"
    }
    #endregion

    #Write-AMInfo "This computer was assigned to collection: $($Collection.Name) in the central configuration"
    If ($Collection.Id) { Set-ItemProperty -Path "$AMRegKeyRoot" -Name "AMCollectionID" -Value $Collection.Id -Force }

}
#endregion

#region Stopping services
Initialize-AMTask "Stopping services" {

    #Remove-AMScheduledTask "Automation Machine User Count"
    $ScheduleService = Get-ScheduleService
    $TaskFolder = Get-CleanAMScheduledTaskFolder "Automation Machine User Count" $ScheduleService

    #region The above scheduled task periodically starts the following process, it could still be running, that's why we attempt to close it
    $AmUserCountProcessName = "AMUsageReporter"
    $IsAmUserCountProcessRunning = $false
    $retryCount = 0
    $maxRetryCount = 120
    do {
        $AmUserCountProcess = Get-Process -Name $AmUserCountProcessName -ErrorAction Ignore
        $IsAmUserCountProcessRunning = $AmUserCountProcess -ne $null
        if ($IsAmUserCountProcessRunning) {
            $retryCount++
            Write-Verbose "Stopping $AmUserCountProcessName. Attempt $retryCount"
            if ($retryCount -ge $maxRetryCount) {
                Stop-Process -Id $AmUserCountProcess.Id -Force
                try {
                    Wait-Process -Id $AmUserCountProcess.Id -Timeout 30 -ErrorAction Stop
                }
                catch {
                    Write-Verbose $_.Message
                }
                break
            }
            else {
                Start-Sleep -Seconds 1
            }
        }
    }
    while ($IsAmUserCountProcessRunning)
    #endregion

    Stop-AMServiceAndWait -Name "AMAppUsage"
    Stop-AMServiceAndWait -Name "Login AM App Store Service"
}
#endregion

#region Copy binary files
Initialize-AMTask "Copying binary files" {
    $LocalBin = Join-Path $AMLocalPath "Bin"
    $CentralBin = Join-Path $ScriptPath "bin"
    if (-not (Test-Path $LocalBin)) {
        [void] (New-Item -ItemType Directory -Path $LocalBin -Force)
    }
    else {
        Write-Verbose "Removing old binaries from:`n    $LocalBin"
        try {
            Remove-Item -Path "$LocalBin\*" -Recurse -Force
        }
        catch [Exception] {
            throw "Could not initialize AM because of file-locking issues, make sure that the client module and/or GUI is not in use on the system:`n$($_.Exception.Message)"
        }
    }
    #region Copy client module
    $script:LocalClientModule = Join-Path $LocalBin "modules\client"
    [void] (New-Item -ItemType Directory -Path $LocalClientModule -Force)
    $CentralClientModule = Join-Path $CentralBin "modules\client"
    Write-Verbose "Copying client module`n  from:`n    $CentralClientModule `n  to:`n    $LocalClientModule"
    #Copy-AMSDirectory -Path "$CentralClientModule" -Destination $LocalClientModule
    Copy-Item -Path "$CentralClientModule\*" -Destination $LocalClientModule -Force -Recurse
    #endregion

    #region Copying service/schtask files (utility folder)
    $UtilitiesFolderName = "utilities"
    $LocalUtilitiesFolder = Join-Path $LocalBin $UtilitiesFolderName
    [void] (New-Item -ItemType Directory -Path $LocalUtilitiesFolder -Force)
    $CentralUtilitiesFolder = Join-Path $CentralBin $UtilitiesFolderName
    Write-Verbose "Copying utility services and tasks`n from:`n  $CentralUtilitiesFolder `n to: `n $LocalUtilitiesFolder"
    Copy-Item -Path "$CentralUtilitiesFolder\*" -Destination $LocalUtilitiesFolder -Force -Recurse
    #endregion

    #Write-Verbose "Copying binaries`n  from:`n    $CentralBin `n  to:`n    $LocalBin"
    #Get-ChildItem -Path $CentralBin -Recurse -Exclude @(".svn") | Copy-Item -Destination {Join-Path $LocalBin $_.FullName.Substring($CentralBin.Length)} -Force
    # Utilities (AM User Count Client)
    #$LocalUtilitiesPath = Join-Path $LocalBin "utilities"
    #New-Item -ItemType Directory -Path $LocalUtilitiesPath -Force | Out-Null
    #$CentralUtilitiesPath = Join-Path $CentralBin "utilities"
    #Write-Verbose "Copying utilities directory`n  from:`n    $CentralUtilitiesPath `n  to:`n    $LocalUtilitiesPath"
    #Copy-AMSDirectory -Path "$CentralUtilitiesPath" -Destination $LocalUtilitiesPath | Out-Null
    #Copy-Item -Path "$CentralUtilitiesPath\*" -Destination $LocalUtilitiesPath -Force -Recurse
}
#endregion

#region Copy initial cache
Initialize-AMTask "Creating initial cache" {
    $LocalCacheRoot = Join-Path $AMLocalPath "Cache"
    if (Test-Path $LocalCacheRoot) {
        Write-Verbose "Removing old cache from:`n    $LocalCacheRoot"
        $CurrentCache = $(Join-Path "$LocalCacheRoot" "CurrentCache")
        If (Test-Path $CurrentCache) {
            cmd /c rmdir $CurrentCache
        }
        Remove-Item -Path "$LocalCacheRoot\*" -Recurse -Force
    }
    $LocalCache = Join-Path $LocalCacheRoot "InitialCache"
    $script:LocalCacheEnv = Join-Path $LocalCache $AMEnvironmentFolder
    if (-not (Test-Path $LocalCacheEnv)) {
        [void] (New-Item -ItemType Directory -Path $LocalCacheEnv -Force)
    }
    Write-Verbose "Copying initial cache`n  from:`n    $ScriptPath `n  to:`n    $LocalCacheEnv"
    #Copy-AMSDirectory -Path "$ScriptPath" -Destination $LocalCacheEnv | Out-Null
    Copy-Item -Path "$ScriptPath\*" -Destination $LocalCacheEnv -Recurse -Force -Include @("config")
    $SymLinkPath = Join-Path $LocalCacheRoot "CurrentCache"
    Write-Verbose "Creating symbolic link for the current cache"
    Write-Host "symlink: $(Test-Path $SymLinkPath)"
    Write-Host "target: $(Test-Path $LocalCache)"
    [void] (New-AMSymbolicLink -Link "$SymLinkPath" -Target "$LocalCache" -Junction)
    $StatusXmlContent = "<Cache><Status>{0}</Status></Cache>"
    [xml] $StatusXml = [string]::Format($StatusXmlContent, "Current")
    $StatusXml.Save($(Join-Path $LocalCache "status.xml"))
}
#endregion

#region Install client module wrapper
Initialize-AMTask "Installing client module wrapper" {
    $ClientModulePsm = Join-Path $LocalClientModule "Automation Machine Client.psm1"
    If (!(Test-Path $(Join-Path $PSHOME "Modules\AMClient"))) { [void] (New-Item -ItemType Directory -Force  -Path $(Join-Path $PSHOME "Modules\AMClient")) }
    $sb = New-Object System.Text.StringBuilder
    [Void]$sb.Append("Param ")
    [Void]$sb.Append("( ")
    [Void]$sb.Append("[string]`$EnvironmentID,")
    [Void]$sb.Append("[boolean]`$NoTranscript = `$false")
    [Void]$sb.Append(") ")

    [Void]$sb.Append("Import-Module `"$ClientModulePsm`" -ArgumentList @(`$EnvironmentID,`$NoTranscript)")
    [Void]$sb.Append("`n").Append("Export-ModuleMember -Variable `"*`"")
    [Void]$sb.Append("`n").Append("Export-ModuleMember -Function `"*`"")

    $Author = "Login AM"
    $CompanyName = "Login AM"
    $Copyright = "Copyright © $((Get-Date).Year) Login AM. All rights reserved."

    New-ModuleManifest -Author "$Author" -CompanyName "$CompanyName" -Copyright "$Copyright" -ModuleToProcess "AMClient.psm1" -Guid  "842495fd-d8a1-4f35-a349-a874e28f7e75" -PowerShellVersion "3.0" -Path $(Join-Path $PSHOME "Modules\AMClient\AMClient.psd1") -Description "Automation Machine client module wrapper" -ModuleVersion "1.0.0.0" -NestedModules @() -TypesToProcess @() -FormatsToProcess @() -RequiredAssemblies @() -FileList @() -ErrorAction Stop
    Set-Content -Path $(Join-Path $PSHOME "Modules\AMClient\AMClient.psm1") -Value $sb
}
#endregion
#


#region Create AM eventlog
Initialize-AMTask "Creating AM eventlog" {
    # Legacy (remove old event log, otherwise Windows will not allow to create a new one with which is starting with "Automati"
    if ([System.Diagnostics.EventLog]::Exists("AutomationMachine")) {
        Remove-EventLog -LogName "AutomationMachine"
    }
    $EventLogName = "AM"
    $EventSource = "Automation Machine"
    if (-not [System.Diagnostics.EventLog]::Exists($EventLogName)) {
        New-EventLog -LogName $EventLogName -Source $EventSource
    }
}
#endregion

#region Create AM User Count scheduled task
Initialize-AMTask "Creating AM User Count and monitoring scheduled task" {
    Install-AMUserUsageTask
}
#endregion

#region Check for computer/collection configuration
Initialize-AMTask "Applying permissions to cache folder " {
    $LocalCacheRoot = Join-Path $AMLocalPath "Cache"
    #S-1-5-11 = Authenticated Users
    Set-AMPermissions -Path $LocalCacheRoot -Permissions ReadAndExecute -PrincipalName "S-1-5-11" -Type Allow -Recurse
    $ACL = Get-Acl $LocalCacheRoot
    $SchTaskUserName = $AMEnvironment.ServiceAccount.UserName
    if ($SchTaskUserName.StartsWith(".\")) {	$SchTaskUserName = $SchTaskUserName.Replace(".\", $env:COMPUTERNAME + "\") }
    $SID = Get-AMSID -Name $SchTaskUserName
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($SID, "FullControl", $([System.Security.AccessControl.InheritanceFlags]::ContainerInherit, [System.Security.AccessControl.InheritanceFlags]::ObjectInherit), [System.Security.AccessControl.PropagationFlags]::None, "Allow")
    $ACL.AddAccessRule($accessRule)
    $ACL | Set-Acl -Path $LocalCacheRoot

    #Set-AMCacheSecurity
}
#endregion

#region Create AM scheduled startup task
Initialize-AMTask "Creating AM scheduled startup task" {
    Install-AMStartupTask
}
#endregion

#region Create AM Logshipping & monitoring scheduled task
Initialize-AMTask "Creating AM logshipping and monitoring scheduled task" {
    Install-AMLogshippingTask
}
#endregion

<#
#region Check for Re-Init Task
$StatusPath = Join-Path $([AutomationMachine.Data.DataFilePath]::REGISTRY_KEY_ROOT).Replace("HKEY_LOCAL_MACHINE","HKLM:") "Status"
$InitRequired = ((Get-ItemProperty -Path $StatusPath -Name InitRequired -ErrorAction SilentlyContinue).InitRequired)
if ($InitRequired -ne $null)
{
	if ($InitRequired -eq $True)
	{
		Initialize-AMTask "Deleting Re-Init task" {
			$SchTaskName = "Automation Machine Re-Init"
			$ScheduleService = New-Object -ComObject "Schedule.Service"
			$ScheduleService.Connect()
			$TaskFolder = $ScheduleService.GetFolder("\Automation Machine") # root folder
			try
			{
				$ReInitTask = $TaskFolder.GetTask("Automation Machine Re-Init")
			}
			catch
			{
				Throw $_
			}
			finally
			{
				$TaskFolder.DeleteTask($ReInitTask.name,0)
				Set-ItemProperty -Path $StatusPath -Name InitRequired -Value $false -Force
			}
		}
	}
}
#endregion
#>

#region Set default machine env vars
Initialize-AMTask "Setting up machine environment variables" {

    #$AMEnvFiles = $(Join-Path $AMCentralPath $AMEnvironmentFolder)
    $Workfolder = Join-Path $AMLocalPath "Workfolder"

    $AMShell = "%windir%\system32\windowspowershell\v1.0\powershell.exe -noexit -command import-module AMClient" | Expand-AMEnvironmentVariables
    [System.Environment]::SetEnvironmentVariable("am_files", $am_files, [System.EnvironmentVariableTarget]::Machine)
    [System.Environment]::SetEnvironmentVariable("am_workfolder", $workfolder, [System.EnvironmentVariableTarget]::Machine)
    [System.Environment]::SetEnvironmentVariable("am_shell", $AMShell, [System.EnvironmentVariableTarget]::Machine)
    [System.Environment]::SetEnvironmentVariable("am_env_files", $am_env_files, [System.EnvironmentVariableTarget]::Machine)
    [System.Environment]::SetEnvironmentVariable("am_env_name", $($AMDataManager.Environment.Name), [System.EnvironmentVariableTarget]::Machine)
    [System.Environment]::SetEnvironmentVariable("am_env_prefix", $($AMDataManager.Environment.Prefix), [System.EnvironmentVariableTarget]::Machine)
    [System.Environment]::SetEnvironmentVariable("am_logpath", $am_logpath, [System.EnvironmentVariableTarget]::Machine)
    [System.Environment]::SetEnvironmentVariable("am_cache", $am_cache, [System.EnvironmentVariableTarget]::Machine)
    [System.Environment]::SetEnvironmentVariable("am_env_prefix", $am_env_prefix, [System.EnvironmentVariableTarget]::Machine)

    [System.Environment]::SetEnvironmentVariable("am_files", $am_files, [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable("am_workfolder", $workfolder, [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable("am_shell", $AMShell, [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable("am_env_files", $am_env_files, [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable("am_env_name", $($AMDataManager.Environment.Name), [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable("am_env_prefix", $($AMDataManager.Environment.Prefix), [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable("am_logpath", $am_logpath, [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable("am_cache", $am_cache, [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable("am_env_prefix", $am_env_prefix, [System.EnvironmentVariableTarget]::Process)
}
#endregion

#region Install AppStore service
If ((Get-AMEventMap -Current).Id.ToString() -eq "117c19d5-b6ab-4289-9f72-6450a89ca6f1") {
    Initialize-AMTask "Installing AppStore and Service" {
        $LocalBin = Join-Path $AMLocalPath "Bin\appstore"
        $CentralBin = Join-Path $ScriptPath "bin\appstore"
        If ((Get-Service "App Store Service" -ea silent) -and (Test-Path $LocalBin\AppStoreService.exe)) {
            Invoke-Expression "& '$LocalBin\AppStoreService.exe' -uninstall"
        }

        if (-not (Test-Path $LocalBin)) {
            [void] (New-Item -ItemType Directory -Path $LocalBin -Force)
        }
        else {
            Write-Verbose "Removing old binaries from:`n    $LocalBin"
            try {
                Remove-Item -Path "$LocalBin\*" -Recurse -Force
            }
            catch [Exception] {
                throw "Could not initialize AM because of file-locking issues, make sure that the client module and/or GUI is not in use on the system:`n$($_.Exception.Message)"
            }
        }
        Write-Verbose "Copying binaries`n  from:`n    $CentralBin `n  to:`n    $LocalBin"
        Get-ChildItem -Path $CentralBin -Recurse -Exclude @(".svn") | Copy-Item -Destination { Join-Path $LocalBin $_.FullName.Substring($CentralBin.Length) } -Force

        Invoke-Expression "& '$LocalBin\AppStoreService.exe' -install -username $($AMEnvironment.ServiceAccount.UserName) -password $($AMEnvironment.ServiceAccount.Password)"

        $ShortcutFolder = Join-Path $([System.Environment]::GetFolderPath($([Environment+SpecialFolder]::CommonPrograms))) "Automation Machine"
        If (!(Test-Path $ShortcutFolder)) { [void] (New-Item $ShortcutFolder -Force -ItemType Directory) }
        New-AMShortcut -Path $ShortcutFolder -Name "Automation Machine AppStore.lnk" -Target (Join-Path $LocalBin "Automation Machine App Store.exe") -Description "Provides access to application for optional installation"

    }
}
#endregion
<# Moved to Invoke-AMEvent Reboot event
#region appusage service
Write-Verbose "Creating AppUsage service"
$AppUsageExe = "$env:programdata\Automation Machine\bin\utilities\AppUsage\AM.Reporting.AppUsage.Client.ConsoleApp.exe"
$AppUsageService = "AMAppUsage"
$ServiceFriendlyName = "LoginAM Application Usage"
$ServiceDescription = "LoginAM uses this service to gather application usage statistics from the LoginAM client machines"
if (!(Get-Service $AppUsageService -ErrorAction SilentlyContinue))
{
	New-Service -Name $AppUsageService -DisplayName $ServiceFriendlyName -BinaryPathName $AppUsageExe -StartupType Automatic -Description $ServiceDescription | Out-Null
	Start-Service -Name $AppUsageService
	if (Get-Service $AppUsageService -ErrorAction SilentlyContinue)
	{
		Write-Verbose "AppUsage service is created"
	}
}
else
{
	Write-Verbose "AppUsage already created, skipping..."
}
#endregion
#>
Remove-Module "Automation Machine"
Import-Module AMClient -Force
Set-AMClientUninstallData

Remove-Variable -Name "AmInitializationMode" -Force -ErrorAction SilentlyContinue

If ($NoReboot) {
    Write-Host "Initialization done. Reboot needed."
    Write-AMStatus "Initialization done, reboot needed"
}
else {
    Initialize-AMTask "Rebooting computer" {
        Invoke-AMEvent -Name Reboot
    }
}

Stop-Transcript