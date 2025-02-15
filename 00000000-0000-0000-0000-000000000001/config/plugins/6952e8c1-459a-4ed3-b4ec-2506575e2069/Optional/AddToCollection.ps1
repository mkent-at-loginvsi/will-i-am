$PluginId = $AmWellKnown::Plugins.SystemConfiguration.Id
Set-Variable -Name PluginEnabled -Value ([boolean] (Get-AMVariable -Id $AmWellKnown::Plugins.SystemConfiguration.EnableSystemConfigurationVariable.Id -ParentId $PluginId -CollectionId $am_col.Id).Value)
Set-Variable -Name am_col_autoadd -Value ([string]  (Get-AMVariable -Id $AmWellKnown::Plugins.SystemConfiguration.AutoaddUnknownComputersVariable.Id -ParentId $PluginId -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)

If ($am_aborting -eq $true)
{
	Write-AMInfo "System is going down for reboot, not adding computer to collection"
}
elseif (($pluginenabled -eq $true) -and ($am_col_autoadd -eq $true))
{
    $am_cpu = Get-AMComputer -Name $env:COMPUTERNAME | Select-Object -First 1
    if ($am_cpu -isnot [object])
    {
        Write-AMInfo "Auto adding the computer $($env:COMPUTERNAME) to the collection $($am_col.Name)"
        $GUID = [Guid]::NewGuid()
		$ComputerXMLPath = "$($am_files)\$($AmEnvironment.Id)\config\systems\$($GUID).xml"
		$ComputerXMLLocalPath = Join-Path $am_env_files "config\systems\$($GUID).xml"
		$ComputerXML = New-Object System.Xml.XmlDocument
		$XMLDeclaration = $ComputerXML.CreateXmlDeclaration("1.0", 'UTF-16', $null)
		$RootElement = $ComputerXML.CreateElement("Computer")
		$ComputerXML.InsertBefore($XMLDeclaration, $ComputerXML.DocumentElement)
		[void] $ComputerXML.AppendChild($RootElement)
				
		$XmlNode = $ComputerXML.CreateElement("Id")
		$XmlNode.InnerText = $GUID
		[void] $RootElement.AppendChild($XmlNode)
        Write-AMInfo "The new computer ID is $GUID"
        			
		$XmlNode = $ComputerXML.CreateElement("Name")
		$XmlNode.InnerText = $env:COMPUTERNAME
		[void] $RootElement.AppendChild($XmlNode)
        				
		$XmlNode = $ComputerXML.CreateElement("CollectionId")
		$XmlNode.InnerText = $am_col.Id
		[void] $RootElement.AppendChild($XmlNode)
        Write-AMInfo "The computer's collection ID is $($am_col.Id)" 
				
		$XmlNode = $ComputerXML.CreateElement("OverriddenVariabes")
		[void] $RootElement.AppendChild($XmlNode)
				
		$ComputerXML.Save($ComputerXMLPath)
		$ComputerXML.Save($ComputerXMLLocalPath)
        Write-AMInfo "The computer $($env:COMPUTERNAME) has been added to the collection $($am_col.Name)"
        Read-AMEnvironment
    }
}