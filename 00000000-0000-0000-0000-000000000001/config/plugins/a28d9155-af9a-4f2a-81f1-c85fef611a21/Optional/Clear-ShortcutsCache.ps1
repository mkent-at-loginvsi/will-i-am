Set-Variable -Name PluginEnabled -Value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000001 -ParentId $AmWellKnown::Plugins.Shortcuts.Id -CollectionId $am_col.Id).Value)

if ($PluginEnabled -eq $true)
{
	Write-AMInfo "Clearing existing shortcuts"
	If (Test-Path $am_workfolder\Shortcuts)
	{
		# A workaround is used, because -Recurse parameter is bugged on PowerShell and not always removes all contents of a folder. 
		# You have to do GCI -> RM first and then remove the folder
		$ShortcutsFolderContents = ([array] (Get-ChildItem -Path "$am_workfolder\Shortcuts" -Recurse -Force))
        if ($ShortcutsFolderContents) {
            $null = $ShortcutsFolderContents | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        }
        $null = Remove-Item -Path "$am_workfolder\Shortcuts" -Force -Recurse -ErrorAction SilentlyContinue
	}
}