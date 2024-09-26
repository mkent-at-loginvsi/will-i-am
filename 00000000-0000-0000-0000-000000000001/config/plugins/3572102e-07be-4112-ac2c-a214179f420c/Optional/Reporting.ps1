# Set variables
$PluginID = Split-Path (Split-Path (Split-Path $script:MyInvocation.MyCommand.Path -Parent) -Parent) -Leaf
If (-not (Test-Path variable:am_col)) {
    Set-Variable -Name am_col -Scope Global -Value (Get-AMCollection -Current)
}
Set-Variable -Name PluginEnabled -Value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000001 -ParentId $PluginID -CollectionId $am_col.Id).Value)
Set-Variable -Name am_maint_reporting_enable -Value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000043 -ParentId $PluginID -CollectionId $am_col.Id).Value)

Set-Variable -Name am_maint_statuspath -Value "$AMCentralPath\$($AMEnvironment.id)\monitoring\maintenance"

#Get reporting vars like mailto address etc
Set-Variable -Name am_maint_reporting_to -Value ([string] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000044 -ParentId $PluginID -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
Set-Variable -Name am_maint_reporting_port -Value ([string] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000050 -ParentId $PluginID -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
Set-Variable -Name am_maint_reporting_ssl -Value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000049 -ParentId $PluginID -CollectionId $am_col.Id).Value)
Set-Variable -Name am_maint_reporting_cred -Value ([AutomationMachine.Data.Types.Credentials] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000048 -ParentId $PluginID -CollectionId $am_col.Id).Value)
Set-Variable -Name am_maint_reporting_smtp -Value ([string] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000047 -ParentId $PluginID -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
Set-Variable -Name am_maint_reporting_subject -Value ([string] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000046 -ParentId $PluginID -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
Set-Variable -Name am_maint_reporting_from -Value ([string] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000045 -ParentId $PluginID -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)

function Send-AMMailMessage {
    param
    (
        [PSCredential]
        $Credentials,

        [string]
        $Body				
    )
	
    $SmtpClient = new-object system.net.mail.smtpClient
    $MailMessage = New-Object system.net.mail.mailmessage
    $SmtpClient.Host = $am_maint_reporting_smtp
    $Smtpclient.EnableSsl = $am_maint_reporting_ssl
    $SmtpClient.Port = $am_maint_reporting_port

    If ($Credentials) {
        $SmtpClient.Credentials = $Credentials
    }
    
    $MailMessage.from = $am_maint_reporting_from
    $am_maint_reporting_to.Split(";") | ForEach-Object { $MailMessage.To.add($_) }
    $MailMessage.Subject = $am_maint_reporting_subject
    $MailMessage.IsBodyHtml = $true
    $MailMessage.Body = $Body
    $SmtpClient.Send($MailMessage)
}

If (($am_maint_reporting_enable -eq $true) -and ($PluginEnabled -eq $true)) {
    # Get mutex
    $Mutex = Get-AMMutex -Name "MaintenanceReport"
    #$Mutex = $true
    If ($Mutex -eq $true) {
        # Get the template
        $templatePath = Join-Path (Split-Path $script:MyInvocation.MyCommand.Path -Parent) "template.html"
        $template = Get-Content $templatePath

        # Get the maintenance results
        $CollectionSummary = ""
        $ComputerSummary = ""
        # Process collection summary
        if (Test-Path $am_maint_statuspath) {
            $MaintenanceItems = Get-ChildItem -Path $am_maint_statuspath | ? { $_.psiscontainer }
            Foreach ($CollectionId in $MaintenanceItems) {
                $Collection = Get-AMCollection -Id $CollectionId.Name
                $Color = "black"
                $LastError = ""
                
                $file = Get-ChildItem -Path "$am_maint_statuspath\$($CollectionId.Name)" | Sort-Object LastWriteTime -Descending | Select-Object -first 1
                
                # See if collection was started, failed or finished
                If ($file.Name -eq "Started") {
                    $Text = "Started"
                }
                ElseIf ($file.Name -eq "Failed") {
                    $Color = "red"
                    $Text = "Failed"
                }
                ElseIf ($file.Name -eq "Finished") {
					$Color = "green"
                    $Text = "Finished"
                }
                $CollectionSummary += "<tr><td>$($Collection.Name)</td><td width=20 ><font color=`"$($Color)`">$($Text)</font></td></tr>"

                # Process computer summary
                $ComputerSummary += "<tr><th align=left>$($Collection.Name)</th></tr><tr><td colspan=3 width=640><hr></td></tr><tr><th align=left>Computer name</th><th align=left>Result</th><th align=left>Last error</th></tr>"
                ForEach ($ComputerID in (Get-ChildItem $CollectionId.FullName | ? { $_.psiscontainer })) {
                    $Computer = Get-AMComputer -Id $ComputerId.Name
                    
                    $file = Get-ChildItem -Path "$am_maint_statuspath\$($CollectionId.Name)\$($ComputerID.Name)" | Sort-Object LastWriteTime -Descending | Select-Object -first 1
                    
                    If ($file.Name -eq "Skipped") {
                        $Text = "Skipped"
                        $Color = "blue"
                    }
                    ElseIf ($file.Name -eq "Started") {
                        $Text = "Started"
                    }
                    ElseIf ($file.Name -eq "Failed") {
                        $ErrorPath = [String]::Format([AutomationMachine.Data.DataFilePath]::COMPUTER_ERRORS_DIRECTORY, $AMCentralPath, $AMEnvironment.Id.ToString(), $ComputerID.Name)
                        If (Test-Path $ErrorPath) {
                            [xml]$LastXML = Get-Content (Get-ChildItem $ErrorPath | ? { $_.PSIsContainer -eq $false } | Sort -Property LastWriteTime | Select -Last 1).FullName
                            $LastError = $LastXML.DashboardStatus.Value
                        }						
                        $Text = "Failed"
                        $Color = "red"
                    }
                    ElseIf ($file.Name -eq "Queued") {
                        $Text = "Queued"
                    }
                    ElseIf ($file.Name -eq "Finished") {
                        $Text = "Finished"
                        $Color = "green"
                    }
					
                    $ComputerSummary += "<tr><td>$($Computer.Name)</td><td><font color=`"$($color)`">$($Text)</font></td><td width=50%>$($LastError)</td></tr>"
                }
                $ComputerSummary += "<tr><td colspan=3 width=640><hr></td></tr>"
            }

            # Replace placeholders
            $template = $template.replace("{COLLECTIONSUMMARY}", $CollectionSummary)
            $template = $template.replace("{COMPUTERSUMMARY}", $ComputerSummary)

            # Get the start of first collection_start
            $FirstStart = $MaintenanceItems | % { $_.GetFiles("Started") } | Sort-Object -Property LastWriteTime | Select -First 1
            $LastFinish = $MaintenanceItems | % { $_.GetFiles("Finished") } | Sort-Object -Property LastWriteTime | Select -Last 1
            If ($Null -ne $FirstStart) {
                $env:maint_starttime = $FirstStart.LastWriteTime
            }
            else {
                $env:maint_starttime = "N/A"
            }
            If ($Null -ne $LastFinish) {
                $env:maint_finishtime = $LastFinish.LastWriteTime
            }
            Else {
                $env:maint_finishtime = "N/A"
            }
            $env:logopath = (Split-Path $script:MyInvocation.MyCommand.Path -Parent)

            # Expand environment variables in template
            $template = [System.Environment]::ExpandEnvironmentVariables($template)

            # Mail the report
            If (-not ([string]::IsNullOrEmpty($am_maint_reporting_cred.Username))) {
                $cred = New-Object PSCredential($am_maint_reporting_cred.Username, $(ConvertTo-SecureString -Force -AsPlainText -String $am_maint_reporting_cred.Password))
                Write-AMInfo "Sending mailmessage: -BodyAsHtml -Body $template -To $am_maint_reporting_to -From $am_maint_reporting_from -Subject $am_maint_reporting_subject -SmtpServer $am_maint_reporting_smtp -Port $am_maint_reporting_port -UseSSL:$am_maint_reporting_ssl -Credential $cred"
                #Send-MailMessage -BodyAsHtml -Body $template -To ($am_maint_reporting_to.Split(";")) -From $am_maint_reporting_from -Subject $am_maint_reporting_subject -SmtpServer $am_maint_reporting_smtp -Port $am_maint_reporting_port -UseSSL:$am_maint_reporting_ssl -Credential $cred
                Send-AMMailMessage -Body $template -Credentials $cred               
            }
            else {
                Write-AMInfo "Sending mailmessage: -BodyAsHtml -Body $template -To $am_maint_reporting_to -From $am_maint_reporting_from -Subject $am_maint_reporting_subject -SmtpServer $am_maint_reporting_smtp -Port $am_maint_reporting_port -UseSSL:$am_maint_reporting_ssl"
                #Send-MailMessage -BodyAsHtml -Body $template -To ($am_maint_reporting_to.Split(";")) -From $am_maint_reporting_from -Subject $am_maint_reporting_subject -SmtpServer $am_maint_reporting_smtp -Port $am_maint_reporting_port -UseSSL:$am_maint_reporting_ssl
                Send-AMMailMessage -Body $template				
            }		
			
        }
        else {
            Write-AMInfo "No maintenance status path found, unable to send maintenance report"
        }
    }
}
else {
    Write-AMInfo "Maintenance plugin is not enabled, or reporting is not enabled"
}