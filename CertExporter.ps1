<#
.SYNOPSIS
    PowerShell certificate exporter for the main SSW certificate.
.DESCRIPTION
    PowerShell certificate exporter for the main SSW certificate.
    It exports the main SSW certificate after it is renewed by the application to different locations: Reverse Proxy, ADFS server and IIS servers.
.EXAMPLE
    This script is triggered after the renewal process is complete at Certify The Web application. To set it, go to Certify The Web | Select the correct site | Show Advanced Options | Scripting | Post-request PS Script.
.INPUTS
    Configuration file: Config.psd1
.OUTPUTS
    Exported certificate, thumbprint, certificate name and password on the defined location in Config.psd1.
.NOTES
    It will not overwrite any certificate in the folder, only add new ones.
    LE = Let's Encrypt
    WUG = WhatsApp Gold

    Created by Kaique "Kiki" Biancatti for SSW.
#>

# Importing the configuration file
$config = Import-PowerShellDataFile $PSScriptRoot\Config.PSD1

# Importing the SSW Write-Log module
Import-Module -Name $config.LogModuleLocation

# Creating variables to determine magic strings and getting them from the configuration file
$LECertFolder = $config.LECertFolder
$LECertThumbprint = $config.LECertThumbprint
$LECertName = $config.LECertName
$LECertPass = $config.LECertPass
$LECertKey = $config.LECertKey
$WapxUser = $config.WapxUser
$WapxPass = $config.WapxPass
$LogFile = $config.LogFile
$WapxServer = $config.WapxServer
$AdfsServer = $config.AdfsServer
$RulesServer = $config.RulesServer
$WugServer = $config.WugServer
$CrmWebHookServer = $config.CrmWebHookServer
$OriginEmail = $config.OriginEmail
$TargetEmail = $config.TargetEmail


# Creating error variables that will be used at the end
$Script:ExportSSWCertError = $false
$Script:SetWapxCertsError = $false
$Script:SetAdfsCertsError = $false
$Script:SetSswRulesCertError = $false
$Script:SetWugCertError = $false
$Script:SetCrmWebHookCertError = $false

<#
.SYNOPSIS
Export certificate to File Server to be used by other functions.

.EXAMPLE
PS> Export-SSWCert -CertKey (get-content $LECertKey) -CertFolder $LECertFolder -CertThumbprint $LECertThumbprint -CertName $LECertName -LogFile $LogFile -CertPass (Get-Content $LECertPass)

.DESCRIPTION
Export certificate to File Server to be used by other functions.
Uses an encrypted password file to be the certificate password, writes the latest thumbprint to File Server for use with other functions.

.PARAMETER CertThumbprint
The location the certificate thumbprint will be exported to.

.PARAMETER CertName
The location the certificate name will be exported to.

.PARAMETER CertPass
The password to be set on the exported certificate.

.PARAMETER CertKey
The decryption key to be used on the exported pass.

.PARAMETER CertFolder
The root folder the certificate will be exported to.

.PARAMETER LogFile
The location of the logfile.
#>
function Export-SSWCert {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $CertThumbprint,
        [Parameter(Mandatory)]
        $CertName,
        [Parameter(Mandatory)]
        $CertPass,
        [Parameter(Mandatory)]
        $CertKey,
        [Parameter(Mandatory)]
        $CertFolder,
        [Parameter(Mandatory)]
        $LogFile
    )

    try {
        # Setting the Certificate password
        $mypwd = $CertPass | ConvertTo-SecureString -Key $CertKey
    
        # Get all certs in the machine where the issuer is let's encrypt and export them
        $item = get-childitem -path Cert:\LocalMachine\My
        $CurrentDate = Get-Date -Format "dd-MM-yyyy"
        $item = $item | where-object { $_.Issuer -eq "CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US" -and $_.NotBefore.ToString("dd-MM-yyyy") -eq $CurrentDate } 
        $item | foreach { $NewCertName = $item.Subject.Substring(3, 10) + "-From" + $_.NotBefore.ToString("dd-MM-yyyy") + "-To" + $_.NotAfter.ToString("dd-MM-yyyy") + ".pfx" }
        $item | foreach { Export-PfxCertificate -cert $_ -FilePath "$CertFolder\$NewCertName" -Password $mypwd -NoClobber }    
        $SSWThumbprint = $item.Thumbprint 

        Set-Content -Path $CertThumbprint -Value $SSWThumbprint
        Set-Content -Path $CertName -Value $NewCertName

        Write-Log -File $LogFile -Message "Certificate thumbprint $SSWThumbprint and name $NewCertName exported to $CertThumbprint and $CertName..."
    }
    catch {
        $Script:ExportSSWCertError = $true
        $RecentError = $Error[0]
        Write-Log -File $LogFile -Message "ERROR on function Export-SSWCert - $RecentError"
    }
}

<#
.SYNOPSIS
Set the new exported certificate to be the Reverse Proxy's web application certificates.

.DESCRIPTION
Set the new exported certificate to be the Reverse Proxy's web application certificates.
Imports the new certificate, gets the thumbprint from File Server and set it on most sites.

.PARAMETER CertThumbprint
The actual certificate thumbprint, location taken from the configuration file and imported to the function on runtime.

.PARAMETER CertName
The actual certificate name, location taken from the configuration file and imported to the function on runtime.

.PARAMETER CertPass
The actual certificate password, location taken from the configuration file and imported to the function on runtime.

.PARAMETER CertKey
The decryption key to be used on the exported pass.

.PARAMETER CertFolder
The root folder of the certificate.

.PARAMETER WapxUser
The username for the Wapx Server.

.PARAMETER WapxPass
The password for the Wapx Server.

.PARAMETER LogFile
The location of the logfile.

.PARAMETER WapxServer
The name of the Wapx Server.

.EXAMPLE
PS> Set-WapxCerts -CertThumbprint (Get-Content $LECertThumbprint) -CertName (Get-Content $LECertName) -CertPass (Get-Content $LECertPass) -CertKey (get-content $LECertKey) -WapxUser $WapxUser -WapxPass $WapxPass -CertFolder $LECertFolder -LogFile $LogFile -WapxServer $WapxServer
#>
function Set-WapxCerts { 
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $CertThumbprint,
        [Parameter(Mandatory)]
        $CertName,
        [Parameter(Mandatory)]
        $CertPass,
        [Parameter(Mandatory)]
        $CertKey,
        [Parameter(Mandatory)]
        $WapxUser,
        [Parameter(Mandatory)]
        $WapxPass,
        [Parameter(Mandatory)]
        $CertFolder,
        [Parameter(Mandatory)]
        $LogFile,
        [Parameter(Mandatory)]
        $WapxServer
    )
    
    try {
        # Get the encrypted username and password files
        $password = $WapxPass | ConvertTo-SecureString -Key $CertKey
        $credentials = New-Object System.Management.Automation.PsCredential($WapxUser, $password)
    
        Invoke-Command -ComputerName $WapxServer -Credential $Credentials -Authentication Credssp -ArgumentList $CertThumbprint, $CertName, $CertPass, $CertKey, $CertFolder -ScriptBlock {
            $CertThumbprint = $args[0]
            $CertName = $args[1]
            $FullCertFolder = ($args[4]) + "\" + $CertName
            $mypwd = $args[2] | ConvertTo-SecureString -Key $args[3]
            Import-PfxCertificate -FilePath $FullCertFolder -CertStoreLocation Cert:\LocalMachine\My -Password $mypwd
            
            $certs = get-WebApplicationProxyApplication | where externalurl -like *.ssw.com.au* | where externalurl -notlike *crm* | where externalurl -notlike *sts2* | set-WebApplicationProxyApplication -ExternalCertificateThumbprint $CertThumbprint
            
        }
        
        # I am calling this again so the thumbprint is updated real-time
        $SSWThumbprint = Get-Content $LECertThumbprint
        Write-Log -File $LogFile -Message "Certificate thumbprint $SSWThumbprint set on WAPX sites..."
    }
    catch {
        $Script:SetWapxCertsError = $true
        $RecentError = $Error[0]
        Write-Log -File $LogFile -Message "ERROR on function Set-WapxCerts - $RecentError"
    }
}

<#
.SYNOPSIS
Set the new exported certificate to be the ADFS's certificates.

.DESCRIPTION
Set the new exported certificate to be the ADFS's certificates.
Imports the new certificate, gets the thumbprint from File Server and set the following certificates:
- WAPX Server: Web Application Proxy Ssl Certificate (needs to be the same as the ADFS SSL certificate)
- ADFS Server: Adfs Certificate for Service-Communications only
- ADFS Server: Adfs SSL Certificate (same as WAPX SSL certificate)

.PARAMETER CertThumbprint
The actual certificate thumbprint, location taken from the configuration file and imported to the function on runtime.

.PARAMETER CertName
The actual certificate name, location taken from the configuration file and imported to the function on runtime.

.PARAMETER CertPass
The actual certificate password, location taken from the configuration file and imported to the function on runtime.

.PARAMETER CertKey
The decryption key to be used on the exported pass.

.PARAMETER CertFolder
The root folder of the certificate.

.PARAMETER WapxUser
The username for the Wapx Server.

.PARAMETER WapxPass
The password for the Wapx Server.

.PARAMETER LogFile
The location of the logfile.

.PARAMETER WapxServer
The name of the Wapx Server.

.PARAMETER AdfsServer
The name of the ADFS Server.

.EXAMPLE
PS> Set-AdfsCert -CertThumbprint (Get-Content $LECertThumbprint) -CertName (Get-Content $LECertName) -CertPass (Get-Content $LECertPass) -CertKey (get-content $LECertKey) -WapxUser $WapxUser -WapxPass $WapxPass -CertFolder $LECertFolder -LogFile $LogFile -AdfsServer $AdfsServer -WapxServer $WapxServer

#>
function Set-AdfsCert {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $CertThumbprint,
        [Parameter(Mandatory)]
        $CertName,
        [Parameter(Mandatory)]
        $CertPass,
        [Parameter(Mandatory)]
        $CertKey,
        [Parameter(Mandatory)]
        $WapxUser,
        [Parameter(Mandatory)]
        $WapxPass,
        [Parameter(Mandatory)]
        $CertFolder,
        [Parameter(Mandatory)]
        $LogFile,
        [Parameter(Mandatory)]
        $AdfsServer,
        [Parameter(Mandatory)]
        $WapxServer
    )

    try {
        # Get the encrypted username and password files
        $password = $WapxPass | ConvertTo-SecureString -Key $CertKey
        $credentials = New-Object System.Management.Automation.PsCredential($WapxUser, $password)
    
        Invoke-Command -ComputerName $AdfsServer -Credential $Credentials -Authentication Credssp -ArgumentList $CertThumbprint, $CertName, $CertPass, $CertKey, $CertFolder -ScriptBlock {
            $CertThumbprint = $args[0]
            $CertName = $args[1]
            $FullCertFolder = ($args[4]) + "\" + $CertName
            $mypwd = $args[2] | ConvertTo-SecureString -Key $args[3]
            Import-PfxCertificate -FilePath $FullCertFolder -CertStoreLocation Cert:\LocalMachine\My -Password $mypwd
            
            Set-AdfsCertificate -CertificateType "Service-Communications" -Thumbprint $CertThumbprint
            Set-AdfsSslCertificate -Thumbprint $CertThumbprint
            Restart-Service adfssrv
        }

        Invoke-Command -ComputerName $WapxServer -Credential $Credentials -Authentication Credssp -ArgumentList $CertThumbprint, $CertName, $CertPass, $CertKey, $CertFolder -ScriptBlock {
            $CertThumbprint = $args[0]
            $CertName = $args[1]
            $FullCertFolder = ($args[4]) + "\" + $CertName
            $mypwd = $args[2] | ConvertTo-SecureString -Key $args[3]
            Import-PfxCertificate -FilePath $FullCertFolder -CertStoreLocation Cert:\LocalMachine\My -Password $mypwd
            
            Set-WebApplicationProxySslCertificate -Thumbprint $CertThumbprint            
        }

        Write-Log -File $LogFile -Message "Exported certificate to $AdfsServer and $WapxServer, set Service Communications, ADFS SSL and Web Application Proxy Ssl cert to $CertThumbprint..."
    }
    catch {
        $Script:SetAdfsCertsError = $true
        $RecentError = $Error[0]
        Write-Log -File $LogFile -Message "ERROR on function Set-AdfsCert - $RecentError"
    }

}

<#
.SYNOPSIS
Set the new exported certificate to be the SSW Rules page server certificate.

.DESCRIPTION
Set the new exported certificate to be the SSW Rules page server certificate.

.PARAMETER CertThumbprint
The actual certificate thumbprint, location taken from the configuration file and imported to the function on runtime.

.PARAMETER CertName
The actual certificate name, location taken from the configuration file and imported to the function on runtime.

.PARAMETER CertPass
The actual certificate password, location taken from the configuration file and imported to the function on runtime.

.PARAMETER CertKey
The decryption key to be used on the exported pass.

.PARAMETER CertFolder
The root folder of the certificate.

.PARAMETER WapxUser
The username for the Wapx Server.

.PARAMETER WapxPass
The password for the Wapx Server.

.PARAMETER LogFile
The location of the logfile.

.PARAMETER RulesServer
The name of the server that the Rules website is sitting in.

.EXAMPLE
PS> Set-SswRulesCert -CertThumbprint (Get-Content $LECertThumbprint) -CertName (Get-Content $LECertName) -CertPass (Get-Content $LECertPass) -CertKey (get-content $LECertKey) -WapxUser $WapxUser -WapxPass $WapxPass -CertFolder $LECertFolder -LogFile $LogFile -RulesServer $RulesServer

#>
function Set-SswRulesCert {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $CertThumbprint,
        [Parameter(Mandatory)]
        $CertName,
        [Parameter(Mandatory)]
        $CertPass,
        [Parameter(Mandatory)]
        $CertKey,
        [Parameter(Mandatory)]
        $WapxUser,
        [Parameter(Mandatory)]
        $WapxPass,
        [Parameter(Mandatory)]
        $CertFolder,
        [Parameter(Mandatory)]
        $LogFile,
        [Parameter(Mandatory)]
        $RulesServer
    )

    try {
        # Get the encrypted username and password files
        $password = $WapxPass | ConvertTo-SecureString -Key $CertKey
        $credentials = New-Object System.Management.Automation.PsCredential($WapxUser, $password)
    
        Invoke-Command -ComputerName $RulesServer -Credential $Credentials -Authentication Credssp -ArgumentList $CertThumbprint, $CertName, $CertPass, $CertKey, $CertFolder -ScriptBlock {
            $CertThumbprint = $args[0]
            $CertName = $args[1]
            $FullCertFolder = ($args[4]) + "\" + $CertName
            $mypwd = $args[2] | ConvertTo-SecureString -Key $args[3]
            Import-PfxCertificate -FilePath $FullCertFolder -CertStoreLocation Cert:\LocalMachine\My -Password $mypwd

            netsh http delete sslcert hostnameport="rules.ssw.com.au:443"
            netsh http delete sslcert hostnameport="Sharepoint.ssw.com.au:443"

            $guid1 = [guid]::NewGuid().ToString("B")
            $guid2 = [guid]::NewGuid().ToString("B")
            netsh http add sslcert hostnameport="rules.ssw.com.au:443" certhash=$CertThumbprint certstorename=MY appid="$guid1"
            netsh http add sslcert hostnameport="Sharepoint.ssw.com.au:443" certhash=$CertThumbprint certstorename=MY appid="$guid2"

            $binding1 = Get-WebBinding -hostheader "Sharepoint.ssw.com.au" -Port 443
            $binding1.AddSslCertificate($CertThumbprint, "my")

            $binding2 = Get-WebBinding -hostheader "rules.ssw.com.au" -Port 443
            $binding2.AddSslCertificate($CertThumbprint, "my")
        }
        Write-Log -File $LogFile -Message "Exported certificate to $RulesServer, set Sharepoint.ssw.com.au and rules.ssw.com.au cert to $CertThumbprint..."
    }
    catch {
        $Script:SetSswRulesCertError = $true
        $RecentError = $Error[0]
        Write-Log -File $LogFile -Message "ERROR on function Set-SswRulesCert - $RecentError"
    }   

}

<#
.SYNOPSIS
Set the new exported certificate to be the WUG server certificate.

.DESCRIPTION
Set the new exported certificate to be the WUG server certificate.

.PARAMETER CertThumbprint
The actual certificate thumbprint, location taken from the configuration file and imported to the function on runtime.

.PARAMETER CertName
The actual certificate name, location taken from the configuration file and imported to the function on runtime.

.PARAMETER CertPass
The actual certificate password, location taken from the configuration file and imported to the function on runtime.

.PARAMETER CertKey
The decryption key to be used on the exported pass.

.PARAMETER CertFolder
The root folder of the certificate.

.PARAMETER WapxUser
The username for the Wapx Server.

.PARAMETER WapxPass
The password for the Wapx Server.

.PARAMETER LogFile
The location of the logfile.

.PARAMETER WugServer
The name of the server that WUG website is sitting in.

.EXAMPLE
PS> Set-WugCert -CertThumbprint (Get-Content $LECertThumbprint) -CertName (Get-Content $LECertName) -CertPass (Get-Content $LECertPass) -CertKey (get-content $LECertKey) -WapxUser $WapxUser -WapxPass $WapxPass -CertFolder $LECertFolder -LogFile $LogFile -WugServer $WugServer

#>
function Set-WugCert {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $CertThumbprint,
        [Parameter(Mandatory)]
        $CertName,
        [Parameter(Mandatory)]
        $CertPass,
        [Parameter(Mandatory)]
        $CertKey,
        [Parameter(Mandatory)]
        $WapxUser,
        [Parameter(Mandatory)]
        $WapxPass,
        [Parameter(Mandatory)]
        $CertFolder,
        [Parameter(Mandatory)]
        $LogFile,
        [Parameter(Mandatory)]
        $WugServer
    )

    try {
        # Get the encrypted username and password files
        $password = $WapxPass | ConvertTo-SecureString -Key $CertKey
        $credentials = New-Object System.Management.Automation.PsCredential($WapxUser, $password)
    
        Invoke-Command -ComputerName $WugServer -Credential $Credentials -Authentication Credssp -ArgumentList $CertThumbprint, $CertName, $CertPass, $CertKey, $CertFolder -ScriptBlock {
            $CertThumbprint = $args[0]
            $CertName = $args[1]
            $FullCertFolder = ($args[4]) + "\" + $CertName
            $mypwd = $args[2] | ConvertTo-SecureString -Key $args[3]
            Import-PfxCertificate -FilePath $FullCertFolder -CertStoreLocation Cert:\LocalMachine\My -Password $mypwd

            $guid1 = [guid]::NewGuid().ToString("B")
            netsh http add sslcert hostnameport="*:443" certhash=$CertThumbprint certstorename=MY appid="$guid1"          
            $binding1 = Get-WebBinding -hostheader "*" -Port 443
            $binding1.AddSslCertificate($CertThumbprint, "my")          
        }
        Write-Log -File $LogFile -Message "Exported certificate to $WugServer, set WUG cert to $CertThumbprint..."
    }
    catch {
        $Script:SetWugCertError = $true
        $RecentError = $Error[0]
        Write-Log -File $LogFile -Message "ERROR on function Set-WugCert - $RecentError"
    }
}

<#
.SYNOPSIS
Set the new exported certificate to be the CRM Web Hook certificate.

.DESCRIPTION
Set the new exported certificate to be the CRM Web Hook certificate.

.PARAMETER CertThumbprint
The actual certificate thumbprint, location taken from the configuration file and imported to the function on runtime.

.PARAMETER CertName
The actual certificate name, location taken from the configuration file and imported to the function on runtime.

.PARAMETER CertPass
The actual certificate password, location taken from the configuration file and imported to the function on runtime.

.PARAMETER CertKey
The decryption key to be used on the exported pass.

.PARAMETER CertFolder
The root folder of the certificate.

.PARAMETER WapxUser
The username for the Wapx Server.

.PARAMETER WapxPass
The password for the Wapx Server.

.PARAMETER LogFile
The location of the logfile.

.PARAMETER CrmWebHookServer
The name of the server that WUG website is sitting in.

.EXAMPLE
PS> Set-CrmWebHookCert -CertThumbprint (Get-Content $LECertThumbprint) -CertName (Get-Content $LECertName) -CertPass (Get-Content $LECertPass) -CertKey (get-content $LECertKey) -WapxUser $WapxUser -WapxPass $WapxPass -CertFolder $LECertFolder -LogFile $LogFile -CrmWebHookServer $CrmWebHookServer

#>
function Set-CrmWebHookCert {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $CertThumbprint,
        [Parameter(Mandatory)]
        $CertName,
        [Parameter(Mandatory)]
        $CertPass,
        [Parameter(Mandatory)]
        $CertKey,
        [Parameter(Mandatory)]
        $WapxUser,
        [Parameter(Mandatory)]
        $WapxPass,
        [Parameter(Mandatory)]
        $CertFolder,
        [Parameter(Mandatory)]
        $LogFile,
        [Parameter(Mandatory)]
        $CrmWebHookServer
    )

    try {
        # Get the encrypted username and password files
        $password = $WapxPass | ConvertTo-SecureString -Key $CertKey
        $credentials = New-Object System.Management.Automation.PsCredential($WapxUser, $password)
    
        Invoke-Command -ComputerName $CrmWebHookServer -Credential $Credentials -Authentication Credssp -ArgumentList $CertThumbprint, $CertName, $CertPass, $CertKey, $CertFolder -ScriptBlock {
            $CertThumbprint = $args[0]
            $CertName = $args[1]
            $FullCertFolder = ($args[4]) + "\" + $CertName
            $mypwd = $args[2] | ConvertTo-SecureString -Key $args[3]
            Import-PfxCertificate -FilePath $FullCertFolder -CertStoreLocation Cert:\LocalMachine\My -Password $mypwd

            netsh http delete sslcert hostnameport="CRMWebhook.ssw.com.au:443"
            $guid1 = [guid]::NewGuid().ToString("B")
            netsh http add sslcert hostnameport="CRMWebhook.ssw.com.au:443" certhash=$CertThumbprint certstorename=MY appid="$guid1"          
            $binding1 = Get-WebBinding -hostheader "CRMWebhook.ssw.com.au" -Port 443
            $binding1.AddSslCertificate($CertThumbprint, "my")          
        }
        Write-Log -File $LogFile -Message "Exported certificate to $CrmWebHookServer, set WUG cert to $CertThumbprint..."
    }
    catch {
        $Script:SetCrmWebHookCertError = $true
        $RecentError = $Error[0]
        Write-Log -File $LogFile -Message "ERROR on function Set-CrmWebHookCert - $RecentError"
    }
}

<#
.SYNOPSIS
Function to build the email to be sent in real time.

.DESCRIPTION
Function to build the email to be sent in real time.

.EXAMPLE
PS> New-EmailMessage

#>
function New-EmailMessage {
    
    if ($Script:ExportSSWCertError -eq $true) {
        $ErroredActions += "<li style=color:red;>$env:computername - <strong>ERROR</strong> on exporting the renewed certificate | Check the log at $LogFile</li>"
    }
    else {
        $CoolActions += "<li style=color:green;>$env:computername - <strong>SUCCESS</strong> on exporting the renewed certificate</li>"
    }
    if ($Script:SetWapxCertsError -eq $true) {
        $ErroredActions += "<li style=color:red;>$WapxServer - <strong>ERROR</strong> on setting Wapx Certificates | Check the log at $LogFile</li>"
    }
    else {
        $CoolActions += "<li style=color:green;>$WapxServer - <strong>SUCCESS</strong> on setting Wapx Certificates</li>"
    }
    if ($Script:SetAdfsCertsError -eq $true) {
        $ErroredActions += "<li style=color:red;>$AdfsServer - <strong>ERROR</strong> on setting ADFS certificates | Check the log at $LogFile | Alternatively, use this guide <a href=https://purple.telstra.com.au/blog/adfs-service-communication-certificate-renewal-steps>here<a> (run the commands, they show different results than the GUI)</li>"
    }
    else {
        $CoolActions += "<li style=color:green;>$AdfsServer - <strong>SUCCESS</strong> on setting ADFS certificates</li>"
    }
    if ($Script:SetSswRulesCertError -eq $true) {
        $ErroredActions += "<li style=color:red;>$RulesServer - <strong>ERROR</strong> on setting rules certificate | Check the log at $LogFile</li>"
    }
    else {
        $CoolActions += "<li style=color:green;>$RulesServer - <strong>SUCCESS</strong> on setting rules certificate</li>"
    }
    if ($Script:SetWugCertError -eq $true) {
        $ErroredActions += "<li style=color:red;>$WugServer - <strong>ERROR</strong> on setting the WUG certificate | Check the log at $LogFile</li>"
    }
    else {
        $CoolActions += "<li style=color:green;>$WugServer - <strong>SUCCESS</strong> on setting the WUG certificate</li>"
    }
    if ($SetCrmWebHookCertError -eq $true) {
        $ErroredActions += "<li style=color:red;>$CrmWebHookServer - <strong>ERROR</strong> on setting the CRM Webhook certificate | Check the log at $LogFile</li>"
    }
    else {
        $CoolActions += "<li style=color:green;>$CrmWebHookServer - <strong>SUCCESS</strong> on setting the CRM Webhook certificate</li>"
    }

    $Script:bodyhtml = @"
<div style='font-family:Calibri'>
<p><h3>To SSWSysAdmins,</h3>
<p>If this email has been sent, it means Certify The Web has renewed the main SSW certificate in SYDIISP03 (a PS script is triggered by the application after renewal is successful).<br>
The following was done:<ol> 
"@
    $Script:bodyhtml += $CoolActions
    $Script:bodyhtml += $ErroredActions
    $Script:bodyhtml += @"
</ol>
<p>Now do the following:</p>
<ol>
<li>Go to https://ssw.com.au | Check the certificate | Ensure certificate is renewed
<ul><li>If not, go to $env:computername | Check "Certify the Web" application</li></ul>
<li>Go to ASDM | Install new certificate (can be found in $LECertFolder) </li>
<li>Go to Skype for Business Servers | Install new certificate (can be found in $LECertFolder) | Set the correct certificates (you can follow this <a href="https://uclobby.com/2015/05/15/request-renewing-skype-for-business-server-2015-certificates/">guide</a>) </li>
</ol>

<p>-- Powered by SSWSysAdmins.SSWCertExporter<br>GitHub: <a href="https://github.com/SSWConsulting/SSWSysAdmins.CertExporter">SSWSysAdmins.CertExporter</a><br>
Server: $env:computername </p></div>
"@
}

# Let's run the commands one by one
Export-SSWCert -CertKey (get-content $LECertKey) -CertFolder $LECertFolder -CertThumbprint $LECertThumbprint -CertName $LECertName -LogFile $LogFile -CertPass (Get-Content $LECertPass)
Set-WapxCerts -CertThumbprint (Get-Content $LECertThumbprint) -CertName (Get-Content $LECertName) -CertPass (Get-Content $LECertPass) -CertKey (get-content $LECertKey) -WapxUser $WapxUser -WapxPass $WapxPass -CertFolder $LECertFolder -LogFile $LogFile -WapxServer $WapxServer
Set-AdfsCert -CertThumbprint (Get-Content $LECertThumbprint) -CertName (Get-Content $LECertName) -CertPass (Get-Content $LECertPass) -CertKey (get-content $LECertKey) -WapxUser $WapxUser -WapxPass $WapxPass -CertFolder $LECertFolder -LogFile $LogFile -AdfsServer $AdfsServer -WapxServer $WapxServer
Set-SswRulesCert -CertThumbprint (Get-Content $LECertThumbprint) -CertName (Get-Content $LECertName) -CertPass (Get-Content $LECertPass) -CertKey (get-content $LECertKey) -WapxUser $WapxUser -WapxPass $WapxPass -CertFolder $LECertFolder -LogFile $LogFile -RulesServer $RulesServer
Set-WugCert -CertThumbprint (Get-Content $LECertThumbprint) -CertName (Get-Content $LECertName) -CertPass (Get-Content $LECertPass) -CertKey (get-content $LECertKey) -WapxUser $WapxUser -WapxPass $WapxPass -CertFolder $LECertFolder -LogFile $LogFile -WugServer $WugServer
Set-CrmWebHookCert -CertThumbprint (Get-Content $LECertThumbprint) -CertName (Get-Content $LECertName) -CertPass (Get-Content $LECertPass) -CertKey (get-content $LECertKey) -WapxUser $WapxUser -WapxPass $WapxPass -CertFolder $LECertFolder -LogFile $LogFile -CrmWebHookServer $CrmWebHookServer
New-EmailMessage

Send-MailMessage -From $OriginEmail -to $TargetEmail -Subject "Main SSW Certificate Renewed - Further Manual Action Needed" -Body $Script:bodyhtml -SmtpServer "ssw-com-au.mail.protection.outlook.com" -BodyAsHtml