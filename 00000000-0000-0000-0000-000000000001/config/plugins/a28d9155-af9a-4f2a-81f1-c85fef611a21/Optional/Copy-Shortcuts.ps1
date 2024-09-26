$IsShortcutsPluginEnabled = [boolean] ((Get-AMVariable -Id 00000000-0000-0000-0000-000000000001 -ParentId $AmWellKnown::Plugins.Shortcuts.Id -CollectionId $am_col.Id).Value)
if ($IsShortcutsPluginEnabled -eq $true) {
    & "$am_env_files\config\plugins\a28d9155-af9a-4f2a-81f1-c85fef611a21\Optional\Copy-StartMenuShortcuts.ps1" # Copy startmenu shortcuts
    & "$am_env_files\config\plugins\a28d9155-af9a-4f2a-81f1-c85fef611a21\Optional\Copy-DesktopShortcuts.ps1" # Copy desktop shortcuts
}