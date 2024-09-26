<#
	.Synopsis
	Invokes the Publish Desktop action item.

	.Description
 	Invokes the specified Publish Desktop actionitem.
	
	.Parameter Actionitem
	Specifies the action item to invoke.
#>
function Invoke-AMActionItemPublishDesktop {
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [AutomationMachine.Data.ActionItem] $ActionItem
    )

    Write-AMInfo "Invoking $($ActionItem.Name)"

   	# Resolve the variables including the filters
    $Variables = $ActionItem.Variables
    $Variables | ForEach-Object {Resolve-AMVariableFilter $_}
    $Variables | ForEach-Object {Resolve-AMMediaPath $_}

    # Get the variables from the actionitem
    [string] $Name = $($Variables | Where-Object {$_.Id -eq "b891deb7-8fe0-4d2f-9921-3231fb55e276"}).Value | Expand-AMEnvironmentVariables
	[string] $Description = $($Variables | Where-Object {$_.Id -eq "0431a6a7-100f-447c-b1e4-6f587d8a9d1b"}).Value | Expand-AMEnvironmentVariables
    [string] $Group = $($Variables | Where-Object {$_.Id -eq "1efa5077-3389-4d62-b7aa-525e3a6add88"}).Value | Expand-AMEnvironmentVariables
    [boolean] $UsePreSuffix = $($Variables | Where-Object {$_.Id -eq "51614929-4e34-451d-94d7-96c3b4d2abfe"}).Value

    if (($UsePreSuffix -eq $true) -and ([string]::IsNullOrEmpty($Group) -eq $false))
	{
        # Security plugin "Groups prefix" variable
        Set-Variable -name am_col_gprefix -Value ([string] (Get-AMVariable -Id "00000000-0000-0000-0000-000000000014" -ParentId "896667bf-44d2-4d4d-aeb3-4ece60dfe264" -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
        # Security plugin "Groups suffix" variable
		Set-Variable -Name am_col_gsuffix -Value ([string] (Get-AMVariable -Id "00000000-0000-0000-0000-000000000018" -ParentId "896667bf-44d2-4d4d-aeb3-4ece60dfe264" -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
		$Group = $am_col_gprefix + $Group + $am_col_gsuffix
	}

    $PATrackingFolder = "$($AMCentralPath)\$($AMEnvironment.Id)\monitoring\XenApp7\$($am_col_path)"

    If (-not(Test-Path $PATrackingFolder))
    {
        [void] (New-Item -ItemType Directory -Path $PATrackingFolder -Force)
    }

    $DesktopCreated = $false
    $DesktopUuid = $null

    Write-Verbose "Check if the desktop was already created"
    $Package = Get-AMPackage -Name $env:am_pkg_name | Select-Object -First 1
    $PKGTrackingPath = Join-Path $PATrackingFolder $Package.Name
    if (-not(Test-Path $PKGTrackingPath)) { [void] (New-Item -Type Directory -Path $PKGTrackingPath) }
    $AITrackingPath = Join-Path $PKGTrackingPath "$($ActionItem.Name)_$($ActionItem.Id).txt"
    $DesktopCreated = Test-Path $AITrackingPath

    if ($DesktopCreated -eq $true)
    {
        $AITrackingFileContent = Get-Content -Path $AITrackingPath
        # Check if package revision was changed compared to last update of app
        $LastUpdateRevision = $AITrackingFileContent[0]
        $DesktopUuid = $AITrackingFileContent[1]
        if ($Package.Version.VersionNumber -le $LastUpdateRevision.Split(".")[0])
        {
            Write-Verbose "Published desktop $Name was already created, and no modifications were detected, not updating the desktop"
            # Nothing to do. Exit the function.
            break
        }
        else
        {
            Write-Verbose "Published desktop $Name was already created, but modifications were detected, updating the desktop"
        }
    }

    Write-Verbose "Getting the desktop group UUID from registry"
    $DesktopGroupUuid = Get-AMXADesktopGroupUuid
    if ($DesktopGroupUuid -eq $null) {
        Write-AMWarning "Unable to detect virtual desktop agent state information, unable to publish application"
        break
    }

    $ActiveBroker = Get-AMXAActiveBroker
    if ($ActiveBroker -eq $null) {
        Write-AMWarning "Unable to detect active controller for this machine, unable to publish application"
        break
    }

    Write-Verbose "Publishing desktop using broker: $ActiveBroker"

    if ($DesktopCreated -eq $false) { # Create a new desktop
        try {
            $Desktop = New-AMXADesktop -Name $Name -Description $Description -Group $Group -DesktopGroupUuid $DesktopGroupUuid -ActiveBroker $ActiveBroker
            $DesktopUuid = $Desktop.UUID
        }
        catch {
            Write-AMWarning $_.Exception.Message
            break
        }
        Write-Verbose "Desktop with UUIID $DesktopUuid has been created"
    }
    else { # modify existing desktop
        try {
            Edit-AMXADesktop -Uuid $DesktopUuid -Name $Name -Description $Description -Group $Group -ActiveBroker $ActiveBroker
        }
        catch {
            Write-AMWarning $_.Exception.Message
            break
        }
        Write-Verbose "Desktop with UUIID $DesktopUuid has been modified"
    }

    # Save package revision number and desktop UUID to the action item tracking file
    Write-Verbose "Setting package revision number and desktop UUID in $AITrackingPath"
    $NewTrackingFileContent = @($Package.Version, $DesktopUuid)
    Set-Content -Path $AITrackingPath -Value $NewTrackingFileContent -Force
}
