try {
    Write-AMInfo "Copying desktop shortcuts"

    # Remove all "AM" marked shortcuts from the desktop
    $ShortcutFolder = Join-Path $am_workfolder "Shortcuts\Desktop"
		
    foreach ($Shortcut in (Get-ChildItem $ShortcutFolder | ? { -not ($_.PSIsContainer -eq $true) })) {
        try {
            Copy-Item $Shortcut.Fullname -Destination $([System.Environment]::GetFolderPath($([Environment+SpecialFolder]::Desktop))) 		
        }
        catch { }
    }		
}
catch {
    Write-AMWarning "Error occured during copying of shortcuts to dekstop: $_"
}	
