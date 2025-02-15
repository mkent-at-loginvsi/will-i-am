$PluginID = $AmWellKnown::Plugins.Imaging.Id    
Set-Variable -Name PluginEnabled -Value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000001 -ParentId $PluginID -CollectionId $am_col.Id).Value)

if ($am_aborting -eq $true)
{
	Write-AMInfo "System is going down for reboot, not setting first boot flag"
}
elseif ($pluginenabled -eq $true)
{
    Write-AMInfo "Setting first boot flag"
    $FirstBootFlagKey = "HKLM:\Software\Automation Machine\Status"
    if (test-path $FirstBootFlagKey)
    {
        $key = Get-Item -Path $FirstBootFlagKey
    }
    else
    {
        $key = New-Item -Path $FirstBootFlagKey -Force 
    }

    [void] ($key | New-ItemProperty -name 'FirstBootAfterSeal' -Value $true -Force)
}