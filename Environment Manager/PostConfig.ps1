param (
    $InstallDir,
    [switch] $Update
)
Start-Transcript "$($env:temp)\AMPostConfig.log"
if (-not (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell -ea silent).ExecutionPolicy) {
    Set-Executionpolicy Bypass -Force
}

function Set-AMCentralShare {
    param (
        [CmdletBinding()]
        [parameter(mandatory = $true, ValueFromPipeline = $false, Position = 0)]
        [string]
        $Name,

        [parameter(mandatory = $true, ValueFromPipeline = $false, Position = 1)]
        [string]
        $Path,

        [parameter(mandatory = $false, ValueFromPipeline = $false, Position = 2)]
        [string]
        $Description,

        [parameter(mandatory = $false, ValueFromPipeline = $false, Position = 3)]
        [int]
        $MaxConnections = 16777216,

        [parameter(mandatory = $false, ValueFromPipeline = $false, Position = 4)]
        [string]
        $Cache = "None"
    )

    if (Test-Path $Path) {
        # Check if share name already exists
        if ((Get-WmiObject -Class Win32_Share -Filter "Name='$Name'") -ne $null) {
            $ExistingShare = Get-WmiObject -Class Win32_Share -Filter "Name='$Name'"

            $ExistingSharePath = $ExistingShare.Path
            Write-Host "Share already existed with path: $($ExistingSharePath), removing the existing share."
            $ExistingShare.Delete() | Out-Null
        }

        $WMIObject = [wmiClass]"Win32_Share"

        $Trustee = ([wmiclass]'Win32_trustee').psbase.CreateInstance()
        $Trustee.SIDString = "S-1-1-0" #SID for everyone

        # Accessmask values
        # Fullcontrol = 2032127
        # Change = 1245631
        # Read = 1179785

        #Create access-list
        $ACE = ([wmiclass]'Win32_ACE').psbase.CreateInstance()
        $ACE.AccessMask = 2032127
        $ACE.AceFlags = 3
        $ACE.AceType = 0
        $ACE.Trustee = $Trustee

        #Securitydescriptor containting access
        $SD = ([wmiclass]'Win32_SecurityDescriptor').psbase.CreateInstance()
        $SD.ControlFlags = 4
        $SD.DACL = $ace
        $SD.group = $trustee
        $SD.owner = $trustee

        $CreateResult = ($WMIObject.Create("$Path", "$Name", 0, $MaxConnections, "$Description", "", $sd)).ReturnValue
        if ($CreateResult -ne 0) {
            switch ($CreateResult) {
                2 { $ErrMsg = "Access Denied" }
                8 { $ErrMsg = "Unknown Failure" }
                9 { $ErrMsg = "Invalid Name" }
                10 { $ErrMsg = "Invalid Level" }
                21 { $ErrMsg = "Invalid Parameter" }
                22 { $ErrMsg = "Duplicate Share" }
                23 { $ErrMsg = "Redirected Path" }
                24 { $ErrMsg = "Unknown Device or Directory" }
                25 { $ErrMsg = "Net Name Not Found" }
                default { $ErrMsg = "$($CreateResult): Unknown error code" }
            }

            throw $ErrMsg
        }
        else {
            # Set cache
            $Net = "$env:SystemRoot\system32\net.exe"
            Start-Process -FilePath $Net -ArgumentList "share $Name /CACHE:$Cache"
        }
    }
    else {
        throw "The folder $($Path) does not exist, cannot share a non-existing folder."
    }
}

function Create-AMShortcut {
    param (
        [parameter(mandatory = $true, ValueFromPipeline = $false, Position = 0)]
        [string]
        $TargetFile,

        [parameter(mandatory = $true, ValueFromPipeline = $false, Position = 1)]
        [string]
        $ShortcutFile,

        [parameter(mandatory = $false, ValueFromPipeline = $false, Position = 2)]
        [string]
        $Description,

        [parameter(mandatory = $false, ValueFromPipeline = $false, Position = 3)]
        [string]
        $IconLocation
    )

    $WScriptShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
    $Shortcut.TargetPath = $TargetFile
    $Shortcut.IconLocation = $IconLocation
    $Shortcut.Description = $Description
    $Shortcut.Save()
}

# function Set-AMIISUser
# {
# 	param
# 	(
# 		[parameter(mandatory=$true,ValueFromPipeline=$false,Position=0)]
#         [string]
#         $Path
# 	)

# 	$Acl = (Get-Item $Path).GetAccessControl('Access')
# 	if ((($acl.Access | Where-Object {$_.IdentityReference -like "IIS*"}).IDentityReference.Value) -ne "IIS APPPOOL\DefaultAppPool")
# 	{
# 		$Ace = New-Object System.Security.AccessControl.FileSystemAccessRule("IIS AppPool\DefaultAppPool", 'Modify','ContainerInherit,ObjectInherit', 'InheritOnly', 'Allow')
# 		$Acl.SetAccessRule($Ace)
# 		Set-Acl -path $Path -AclObject $Acl
# 	}
# }

function Stop-AMWebsite {
    param (
        [parameter(mandatory = $true, ValueFromPipeline = $false, Position = 0)]
        [System.Object]
        $Site
    )

    $Site | Stop-Website -ea silent
    $Port = ($site | get-webbinding).bindingInformation.split(":")[1]
    $Site | Remove-Website
    return $Port
}

function Set-AMwwwrootUser {
    param (
        [parameter(mandatory = $true, ValueFromPipeline = $false, Position = 0)]
        [string]
        $InstallDir
    )

    $ACL = Get-Acl $InstallDir
    $SID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-568") # "S-1-5-32-568" = IIS_IUSRS
    $rule = new-object System.Security.AccessControl.FileSystemAccessRule($SID, "ReadAndExecute", "Allow")
    $acl.AddAccessRule($rule)
    $acl | Set-Acl -Path $InstallDir
}

function Restart-AMIIS {
    Stop-Service W3SVC | Out-Null
    Start-Service W3SVC | Out-Null
}

function Insert-AMUserToDb {
    param (
        [parameter(mandatory = $true, ValueFromPipeline = $false, Position = 0)]
        [string]
        $InstallDir,

        [parameter(mandatory = $true, ValueFromPipeline = $false, Position = 1)]
        [string]
        $SQLite
    )

    $DBLocation = Join-Path $InstallDir "db\users.db"
    $AdminRoleId = "Select Id from AspNetRoles WHERE NormalizedName = 'ADMINISTRATORS';" | . $SQLite $DBLocation
    $UserId = [Guid]::NewGuid().ToString()
    $UserName = "$($env:userdomain)\$($env:Username)"
    $NTAccount = New-Object System.Security.Principal.NTAccount($UserName)
    $UserSID = $NTAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
    $ExistingUser = "Select UserSid from AspNetUsers WHERE UserSid = '$($UserSid)';" | . $SQLite $DBLocation
    $UserString = "INSERT INTO AspNetUsers (Id,AccessFailedCount,ConcurrencyStamp,Email,EmailConfirmed,FullName,LockoutEnabled,NormalizedEmail,NormalizedUserName,PhoneNumberConfirmed,SecurityStamp,TwoFactorEnabled,UserName,UserSid) VALUES('$($UserId)',0,'$([guid]::newguid().ToString())','admin@automation.machine',0,'$($UserName)',1,'ADMIN@AUTOMATION.MACHINE','$($UserName.ToUpper())',0,'$([guid]::NewGuid().ToString())',0,'$UserName','$UserSID');"
    $RoleString = "INSERT INTO AspNetUserRoles (UserId,RoleId) VALUES ('$($UserId)','$($AdminRoleId)');"
    if ([string]::IsNullOrEmpty($ExistingUser)) {
        $UserString | . $SQLite $DBLocation
        $RoleString | . $SQLite $DBLocation
    }

    Write-Verbose "UserString: $($Userstring)"
    Write-Verbose "RoleString: $($RoleString)"
}

function Get-ExistingServerUrl {
    $ServiceBaseAddressKey = Get-Item "HKLM:\Software\Automation Machine"
    [string] $ServiceBaseAddress = $ServiceBaseAddressKey.GetValue("ServiceBaseAddress", $null)
    [System.Uri] $ServerUri = $null
    if (![string]::IsNullOrEmpty($ServiceBaseAddress)) {
        $ServerUri = New-Object System.Uri($ServiceBaseAddress)
    }
    return $ServerUri
}

try {
    $InstallDir = $InstallDir.TrimEnd('\" ')
    $AMWebsiteName = "Automation Machine"
    $Port = 80
    $AMWebUrl = "http://localhost"

    $ServerUri = Get-ExistingServerUrl
    if ($null -ne $ServerUri) {
        $Port = $ServerUri.Port
        $AMWebUrl = "$($ServerUri.Scheme)://$($ServerUri.Host):$($ServerUri.Port)"
    }

    # Create share based on the Set-AMCentralShare function
    Write-Host "Sharing folder $InstallDir as AM$..." -NoNewLine
    Set-AMCentralShare -Name "AM$" -Path $InstallDir -ea Stop
    Write-Host "[OK]" -ForegroundColor Green

    # Write-Host "Securing $InstallDir folder with IIS user..." -NoNewLine
    # Set-AMIISUser -Path $InstallDir
    # Write-Host "[OK]" -ForegroundColor Green

    # Create the site, remove any old sites if needed
    Write-Host "Checking for existing websites..." -NoNewLine
    Import-Module WebAdministration
    $Site = Get-Website -Name $AMWebsiteName -ErrorAction SilentlyContinue
    Write-Host "[OK]" -ForegroundColor Green

    if ($Site -ne $null) {
        Write-Host "Existing website found, stopping and removing..." -NoNewLine
        $Port = Stop-AMWebsite -Site $Site
        Write-Host "[OK]" -ForegroundColor Green
    }

    # Remove webbindings of port 80 and port 1991
    #Write-Host "Setting permissions for wwwroot..." -NoNewLine
    #Set-AMwwwrootUser -InstallDir $InstallDir
    #Write-Host "[OK]" -ForegroundColor Green

    Write-Host "Removing binding of port $Port of any existing site..." -NoNewLine
    Remove-Webbinding -Port $Port -ErrorAction SilentlyContinue
    Write-Host "[OK]" -ForegroundColor Green

    Write-Host "Restarting IIS..." -NoNewLine
    Restart-AMIIS
    Write-Host "[OK]" -ForegroundColor Green

    Write-Host "Creating new Automation Machine website..." -NoNewLine
    New-Website -Name $AMWebsiteName -Port $Port -PhysicalPath "$($InstallDir)\web" | Start-Website
    Write-Host "[OK]" -ForegroundColor Green

    Set-ItemProperty 'HKLM:\Software\Automation Machine' -Name ServiceBaseAddress -Value "$AMWebUrl"
    Start-Process "c:\windows\system32\inetsrv\appcmd.exe" -ArgumentList "set config -section:applicationPools `"/[name='DefaultAppPool'].processModel.loadUserProfile:true`""

    # Run webrequest to website to ensure it's working and that startup tasks are executed
    Write-Host "Creating website user for currently logged on user...." -NoNewLine
    $WebRequest = Invoke-WebRequest -Uri $AMWebUrl -UseBasicParsing
    If ($WebRequest.StatusCode -ne 200) { throw "Unable to contact $AMWebUrl" }
    # Insert currently logged on user in users.db
    $SQLite = (Get-Item (Join-Path (Split-Path $Script:MyInvocation.MyCommand.Path -Parent) "sqlite3.exe")).FullName
    Insert-AMUserToDb -InstallDir $InstallDir -SQLite $SQLite
    Write-Host "[OK]" -ForegroundColor Green
    Remove-Item $SQLite -Force

    # Set shortcut for web ui
    $TargetFile = $AMWebUrl
    $ShortcutFile = "$env:Public\Desktop\LoginAM Web Interface.lnk"
    $ShortcutDescription = "LoginAM Web UI"
    $ShortcutIcon = Join-Path $InstallDir "Web\wwwroot\images\favicon.ico"
    Create-AMShortcut -TargetFile $TargetFile -ShortcutFile $ShortcutFile -Description $ShortcutDescription -IconLocation $ShortcutIcon

    # Set shortcut for environment manager
    $TargetFile = Join-Path $InstallDir "Environment Manager\EnvironmentManager.exe"
    $ShortcutFile = "$env:Public\Desktop\LoginAM Environment Manager.lnk"
    $ShortcutDescription = "Starts the AM environment manager"
    Create-AMShortcut -TargetFile $TargetFile -ShortcutFile $ShortcutFile -Description $ShortcutDescription -IconLocation $TargetFile
}
catch {
    Write-Host "[ERROR]" -ForegroundColor Red
    Write-Host $_ -ForegroundColor red
    throw $_
}
Stop-Transcript