<#
	.Synopsis
	Invokes the apply file permissions action item.

	.Description
 	Invokes the specified install true type fonts actionitem.
	
	.Parameter Actionitem
	Specifies the actionitem which to invoke.
		 
 	.Example
	$Pkg = Get-AMPackage -Name "TestPackage"
	Read-AMActionItems -Component $pkg
	$ActionSet = $Pkg.ActionSet | Select -First 1
	$ActionItem = $ActionSet.ActionItems | Select -First 1
 	Invoke-AMActionItemInstallTTF -ActionItem $ActionItem
#>
function Invoke-AMActionItemInstallTTF {
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AutomationMachine.Data.ActionItem] $ActionItem
    )
	
    Write-AMInfo "Invoking $($ActionItem.ActionItemTemplate.Name)"
    # Resolve the variables including the filters,
    $Variables = $ActionItem.Variables
    $Variables | ForEach-Object { Resolve-AMVariableFilter $_ }
    $Variables | ForEach-Object { Resolve-AMMediaPath $_ }

    # Get the variables from the actionitem
    $File = $($Variables | Where-Object { $_.name -eq "File" })

    # Copy imported script to workfolder and stript the guid extension
    $SourceFile = Get-AMImportedFilePath $File
    
    $Win1809Verion = New-Object System.Version("10.0.17763")
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
    if ([System.Environment]::OSVersion.Version -ge $Win1809Verion) {
        $FilePath = $SourceFile
        $SupportedExtensions = ('.fon', '.otf', '.ttc', '.ttf')

        $FontFile = Get-Item -Path $FilePath
        if ($FontFile.Extension -notin $SupportedExtensions) {
            throw "The specified file is not supported."
        }

        $FontObj = New-Object System.Drawing.Text.PrivateFontCollection
        $FontObj.AddFontFile($FilePath)
        $FontName = $FontObj.Families[0].Name
    
        Write-Host "Stopping Windows Font Cache Service"

        $FontCacheService = Get-Service -Name "FontCache"
        $FontCacheService3 = Get-Service -Name "FontCache3.0.0.0" -ErrorAction SilentlyContinue

        $FontCacheServiceStartupType = $FontCacheService.StartType
        $FontCacheService | Stop-AMService -Wait
        if ($null -ne $FontCacheService3) {
            $IsFontCacheService3StatusStarted = $FontCacheService3.Status -eq "Started"
            $FontCacheService3StartupType = $FontCacheService3.StartType
            if ($IsFontCacheService3StatusStarted) {
                $FontCacheService3 | Set-Service -StartType Disabled
                $FontCacheService3 | Stop-AMService
            }
        }

        $SystemFontsDirectory = Join-Path $env:windir "Fonts"
        Write-Host "Installing font `"$FontName ($($FontFile.Name))`""
        Copy-Item -Path $FilePath -Destination $SystemFontsDirectory -Force
        if (($FontFile.Extension -eq ".ttf") -or ($FontFile.Extension -eq ".ttc") -or ($FontFile.Extension -eq ".otf")) {
            $FontName += " (TrueType)"
        }

        $FontsRegistryKey = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Fonts"
        $property = Get-ItemProperty -Name $FontName -Path $FontsRegistryKey -ErrorAction SilentlyContinue
        if ($null -ne $property) {
            [void] (Set-ItemProperty -Name $FontName -Path $FontsRegistryKey -Value $FontFile.Name)
        }
        else {
            [void] (New-ItemProperty -Name $FontName -Path $FontsRegistryKey -PropertyType string -Value $FontFile.Name)
        }

        Write-Host "Cleaning Windows Font Cache"
        $FontsCacheFile = "C:\Windows\System32\FNTCACHE.DAT"
        if ((Test-Path $FontsCacheFile)) {
            Remove-Item -Path $FontsCacheFile -Force
        }

        Write-Host "Starting Windows Font Cache Service"

        $FontCacheService | Set-Service -StartupType $FontCacheServiceStartupType
        $FontCacheService | Start-AMService -Wait
        if ($null -ne $FontCacheService3) {
            $FontCacheService3 | Set-Service -StartupType $FontCacheService3StartupType
            if ($IsFontCacheService3StatusStarted) {
                $FontCacheService3 | Start-AMService -Wait
            }
        }
    }
    else { # Older than Windows 10 1809
        # Get fonts shell object
        $FONTS = 0x14 
        $objShell = New-Object -ComObject Shell.Application
        $objFolder = $objShell.Namespace($FONTS)

        # check for Font Family Name, only possible with truetype
        $isThere = $false
        $objNewFont = New-Object System.Drawing.Text.PrivateFontCollection
        $objNewFont.addfontfile($SourceFile)
        $FontFamily = $objNewFont.families
      
        foreach ($newFont in $fontfamily) {
            $fontFamilyName = $newfont.name
        }
        $objFonts = New-Object System.Drawing.Text.InstalledFontCollection
        $colFonts = $objFonts.Families
        foreach ($Font in $colFonts) {
            if ($FontfamilyName -eq $($font.Name)) {$isThere = $true; Continue }
        }
        if ($isThere -eq $false) {
            Write-Host "Installing font `"$($fontFamilyName)`""
            $objFolder.CopyHere($SourceFile)
        }
        else {
            Write-Host "Font `"$($fontFamilyName)`" is already installed"
        }
    }
}