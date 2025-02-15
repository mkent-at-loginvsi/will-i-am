$PluginID = Split-Path (Split-Path (Split-Path $script:MyInvocation.MyCommand.Path -Parent) -Parent) -Leaf
$Plugin = Get-AMPlugin -Id $PluginId
Set-Variable -Name PluginEnabled -Value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000001 -ParentId $PluginID -CollectionId $am_col.Id).Value)
Set-Variable -name am_col_template -Value ([string] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000006 -ParentId 3efa9468-86b6-46a5-88e1-9c905a1226aa -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
Set-Variable -Name am_col_autorename -Value ([string]  (Get-AMVariable -Id 00000000-0000-0000-0000-000000000020 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
Set-Variable -Name am_col_renamescript -Value (Get-AMVariable -Id 00000000-0000-0000-0000-000000000021 -ParentId $Plugin.Id -CollectionId $am_col.Id)

# checking for imaging variable here. Not nice but inevitable as we don't want the template computer to rename itself and stop begin the template machine
$ShouldNotRunOnComputerWithName = ""
if (Test-Path variable:am_col_template)
{
	$ShouldNotRunOnComputerWithName = $am_col_template
}

if (($pluginenabled -eq $true) -and ($am_col_autorename -ne "No Rename") -and ($global:am_aborting -ne $true) -and ($ShouldNotRunOnComputerWithName -ne $env:computername ))
{
    [string] $NewName = ""

    switch ($am_col_autorename)
    {
        "No rename"
        {
            $NewName = $env:COMPUTERNAME
            break;
        }
        "Hyper-V VM name"
        {
            $NewName = (get-item "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters").GetValue("VirtualMachineName")            
            break;
        }
        "Custom script"
        {
            $SourceFile = Get-AMImportedFilePath $am_col_renamescript      				
			$NewName = & $SourceFile
			
			
            break;
        }
        default 
        {
            $NewName = $env:COMPUTERNAME
        }
    }
    
    #Remove unsupported characters and trim to max 15 characters
    $NewName = [Regex]::Replace($NewName,"\W","-")
    $NewName = $NewName.Substring(0,[System.Math]::Min(15, $NewName.Length))

    if ($env:COMPUTERNAME -ne $NewName)
    {
        try
        {
			Write-AMInfo "Renaming computer $($env:computername) to $($NewName)"
            Rename-Computer -NewName $NewName -Force
            $AMDataManager.RebootNeeded = $true
            $global:am_aborting = $true
        }
        catch [Exception]
        {
            Write-AMError -Error $_
        }
    }
}