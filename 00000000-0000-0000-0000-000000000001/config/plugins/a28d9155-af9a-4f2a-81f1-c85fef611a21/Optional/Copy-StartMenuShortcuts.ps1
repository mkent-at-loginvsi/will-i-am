try {
    Write-AMInfo "Copying startmenu shortcuts"
    $SpecialPaths = New-Object System.Collections.ArrayList

    foreach ($name in $([Environment+SpecialFolder]::GetNames([Environment+SpecialFolder]))) {
        [void] $SpecialPaths.Add($([Environment]::GetFolderPath($name)))
    }

    $ShortcutFolder = Join-Path $am_workfolder "Shortcuts\Startmenu"
    foreach ($Folder in (Get-ChildItem $ShortcutFolder | ? { $_.PSIsContainer -eq $true })) {
        # Remove folder if it already exists
        $DestinationFolder = Join-Path $([System.Environment]::GetFolderPath($([Environment+SpecialFolder]::Programs))) $Folder.Name
        if (Test-Path $DestinationFolder) {
            Remove-Item $DestinationFolder -Recurse -Force
        }
        # Copy the shortcuts to start menu
        try {
            Copy-Item $Folder.Fullname -Destination $([System.Environment]::GetFolderPath($([Environment+SpecialFolder]::Programs))) -Recurse -Force -ErrorAction Continue
        }
        catch { }
    }

    foreach ($Shortcut in (Get-ChildItem $ShortcutFolder | ? { -not ($_.PSIsContainer -eq $true) })) {
        try {
            Copy-Item $Shortcut.Fullname -Destination $([System.Environment]::GetFolderPath($([Environment+SpecialFolder]::Programs))) 		
        }
        catch { }
    }

    # Remove any empty folder from the startmenu
    foreach ($dir in $(get-childitem $([System.Environment]::GetFolderPath($([Environment+SpecialFolder]::Programs))) -recurse | ? { $_.PSIsContainer -eq $true } | sort-object { $_.FullName.Length } -descending)) {
        # Check if dir is a specialfolder, if so skip it
        if ($SpecialPaths.Contains($dir.fullname)) { continue }
        if ($dir.GetFilesystemInfos().Count -eq 0) {
            Remove-Item $dir.Fullname
        }
    }
}	
catch {
    Write-AMWarning "Error occured during copying of shortcuts to start menu: $_"
}	
