<#
	.Synopsis
	Invokes the create shortcut action item.

	.Description
 	Invokes the specified create shortcut actionitem.
	
	.Parameter Actionitem
	Specifies the actionitem which to invoke.
		 
 	.Example
	$Pkg = Get-AMPackage -Name "TestPackage"
	Read-AMActionItems -Component $pkg
	$ActionSet = $Pkg.ActionSet | Select -First 1
	$ActionItem = $ActionSet.ActionItems | Select -First 1
 	Invoke-AMActionItemShareFolder -ActionItem $ActionItem
#>
function Invoke-AMActionItemCreateWeblinkShortcut
{
	[CmdletBinding()]
	param
	(
		[parameter(Mandatory=$true,ValueFromPipeline=$true)]
		[AutomationMachine.Data.ActionItem] $ActionItem
	)

	Write-AMInfo "Invoking $($ActionItem.Name)"
	# Resolve the variables including the filters,
	$Variables = $ActionItem.Variables
	$Variables | % {Resolve-AMVariableFilter $_}
	$Variables | % {Resolve-AMMediaPath $_}
	
	# Get the variables from the actionitem
	[String] $Name = $($Variables | ? {$_.name -eq "Name"}).Value | Expand-AMEnvironmentVariables
	[String] $Description = $($Variables | ? {$_.name -eq "Description"}).Value | Expand-AMEnvironmentVariables
	[String] $TargetUrl = $($Variables | ? {$_.name -eq "TargetUrl"}).Value | Expand-AMEnvironmentVariables
	[Boolean] $PublishStartMenu = $($Variables | ? {$_.name -eq "Publish in Startmenu"}).Value
	[Boolean] $PublishDesktop = $($Variables | ? {$_.name -eq "Publish on Desktop"}).Value
	[Boolean] $PublishAllUsers = $($Variables | ? {$_.name -eq "Publish for all users"}).Value
	[String] $Folder = $($Variables | ? {$_.name -eq "Folder"}).Value | Expand-AMEnvironmentVariables
	[String] $Group = $($Variables | ? {$_.name -eq "Group"}).Value | Expand-AMEnvironmentVariables
	[Boolean] $UsePreSuffix = $($Variables | ? {$_.name -eq "AutoAdd group prefix/suffix"}).Value
	$Icon = $($Variables | ? {$_.name -eq "Icon"})

	If ([string]::IsNullOrEmpty($Icon.Value.Name))
	{
		try
		{
            [System.Uri]$Url = $TargetUrl
			$Scheme = $Url.Scheme
			$Domain = $Url.Host
			if([string]::IsNullOrEmpty($Scheme))
			{
				$Scheme = "http"
			}
			if([string]::IsNullOrEmpty($Domain))
			{
				$Domain = $TargetUrl
			}
			$FavIconSource = "$($Scheme)://$($Domain)/favicon.ico"
            $FavIconSource = "$($Scheme)://$($Url.Host)/favicon.ico"
            $TempDestination = "$env:temp\ $Name.ico"
            $wc = New-Object System.Net.WebClient
            $wc.DownloadFile($FavIconSource, $TempDestination)
            $IconName = (Get-Item $TempDestination).Name
		    $IconPath = Join-Path $am_workfolder $IconName
		    Copy-Item $TempDestination $IconPath -Force
		}
		catch
		{
			$IconPath = [string]::Empty
		}		
	}
	else
	{
		$TempPath = Get-AMImportedFilePath $Icon
		$IconName = (Get-Item $TempPath).Name
		$IconPath = Join-Path $am_workfolder $IconName
		Copy-Item $TempPath $IconPath -Force
	}

	if ([string]::IsNullOrEmpty($IconPath)) {
		$IconPathFileInfo = $null
	}
	else {
		$IconPathFileInfo = New-Object System.IO.FileInfo($IconPath)
	}

	If ($UsePreSuffix -eq $true)
	{
		Set-Variable -name am_col_gprefix -Value ([string] (Get-AMVariable -Id "00000000-0000-0000-0000-000000000014" -ParentId "896667bf-44d2-4d4d-aeb3-4ece60dfe264" -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
		Set-Variable -Name am_col_gsuffix -Value ([string] (Get-AMVariable -Id "00000000-0000-0000-0000-000000000018" -ParentId "896667bf-44d2-4d4d-aeb3-4ece60dfe264" -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
		$Group = $am_col_gprefix + $Group + $am_col_gsuffix
	}
	
	If ($am_col_enable_startmenu_publish -eq $true)
	{
		If ($PublishStartMenu -eq $true)
		{
			If ($PublishAllUsers -ne $true)
			{

				If ((Get-AMLDAPPath $Group) -eq $null)
				{
					throw "Unable to find group: $group"
				}
				# Create new shortcut in amworkfolder
				$ShortcutFolder = Join-Path (Join-Path $am_workfolder "Shortcuts\Startmenu") $Folder
				#$ShortcutPath = Join-Path $ShortcutFolder "$Name.lnk"
				If (!(Test-Path $ShortcutFolder)) {[void] (New-Item $ShortcutFolder -Force -ItemType Directory) }
				New-AMWebShortcut -Path $ShortcutFolder -Name "$Name.lnk" -TargetUrl $TargetUrl -Description $Description -IconPath $IconPathFileInfo
				# Apply NTFS permissions to shortcut	
				
				Set-AMPermissions -Path "$ShortcutFolder\$Name.lnk" -PrincipalName $group -Permissions "ReadAndExecute" -Type Allow
				
				If (-not [string]::IsNullOrEmpty($IconPath))
				{
                    if (-Not($IconPath -Like "*.ico"))
                    {
					    Set-AMPermissions -Path "$IconPath" -PrincipalName $group -Permissions "ReadAndExecute" -Type Allow
                    }
				}
				
				# NOTE: Optional Shortcuts script ensures that shortcuts are being copied during LOGON event
			}
			Else
			{
				$ShortcutFolder = Join-Path $([System.Environment]::GetFolderPath($([Environment+SpecialFolder]::CommonPrograms))) $Folder
				If (!(Test-Path $ShortcutFolder)) { [void] (New-Item $ShortcutFolder -Force -ItemType Directory) }
				New-AMWebShortcut -Path $ShortcutFolder -Name "$Name.lnk" -TargetUrl $TargetUrl -Description $Description -IconPath $IconPathFileInfo
				
				Set-AMPermissions -Path "$ShortcutFolder\$Name.lnk" -PrincipalName "Everyone" -Permissions "ReadAndExecute" -Type Allow		
				If (-not [string]::IsNullOrEmpty($IconPath))
				{
                    if (-Not($IconPath -Like "*.ico"))
                    {
					    Set-AMPermissions -Path "$IconPath" -PrincipalName "Everyone" -Permissions "ReadAndExecute" -Type Allow
                    }
				}
				
			}
		}
		Else
		{
			Write-AMInfo "Publishing shortcuts to start menu is disabled on the actionitem"
		}
	}
	Else
	{
		Write-AMInfo "Publishing shortcuts to start menu is disabled on the collection"
	}


	
	If ($am_col_enable_desktop_publish -eq $true)
	{
		If ($PublishDesktop -eq $true)
		{
			If ($PublishAllUsers -ne $true)
			{			
					
				If ((Get-AMLDAPPath $Group) -eq $null)
				{
					throw "Unable to find group: $group"
				}
				# Create new shortcut in amworkfolder
				$ShortcutFolder = Join-Path $am_workfolder "Shortcuts\Desktop"
				#$ShortcutPath = Join-Path $ShortcutFolder "$Name.lnk"
				If (!(Test-Path $ShortcutFolder)) { [void] (New-Item $ShortcutFolder -Force -ItemType Directory) }	
				New-AMWebShortcut -Path $ShortcutFolder -Name "$Name.lnk" -TargetUrl $TargetUrl -Description $Description -IconPath $IconPathFileInfo
				# Apply NTFS permissions to shortcut	
				
				Set-AMPermissions -Path "$ShortcutFolder\$Name.lnk" -PrincipalName $group -Permissions "ReadAndExecute" -Type Allow
				
				If (-not [string]::IsNullOrEmpty($IconPath))
				{
                    if (-Not($IconPath -Like "*.ico"))
                    {
					    Set-AMPermissions -Path "$IconPath" -PrincipalName $group -Permissions "ReadAndExecute" -Type Allow
                    }
				}
				
				# NOTE: Optional Shortcuts script ensures that shortcuts are being copied during LOGON event
			}
			Else
			{
				$ShortcutFolder =  $([System.Environment]::GetFolderPath($([Environment+SpecialFolder]::CommonDesktopDirectory)))			
				New-AMWebShortcut -Path $ShortcutFolder -Name "$Name.lnk" -TargetUrl $TargetUrl -Description $Description -IconPath $IconPathFileInfo
				
				Set-AMPermissions -Path "$ShortcutFolder\$Name.lnk" -PrincipalName "Everyone" -Permissions "ReadAndExecute" -Type Allow		
				If (-not [string]::IsNullOrEmpty($IconPath))
				{
                    if (-Not($IconPath -Like "*.ico"))
                    {
					    Set-AMPermissions -Path "$IconPath" -PrincipalName "Everyone" -Permissions "ReadAndExecute" -Type Allow
                    }
				}
				
			}
		}
		Else
		{
			Write-AMInfo "Publishing shortcuts to the desktop is disabled on the actionitem"
		}
	}
	Else
	{
		Write-AMInfo "Publishing shortcuts to the desktop is disabled on the collection"
	}			
}