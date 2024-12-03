<#
.SYNOPSIS
    PowerShell certificate exporter for the main SSW certificate.
.DESCRIPTION
    PowerShell certificate exporter for the main SSW certificate.
    It exports the main SSW certificate after it is renewed by win-acme to different locations.
.EXAMPLE
    This script is triggered after the renewal process is complete in win-acme.
.INPUTS
    Configuration file: Config.psd1
.OUTPUTS
    Thumbprint, certificate name and password on the defined location in Config.psd1.
.NOTES
    LE = Let's Encrypt
    WUG = WhatsApp Gold

    Created by Kaique "Kiki" Biancatti & Chris Schultz for SSW.
#>

# Importing the configuration file
$config = Import-PowerShellDataFile $PSScriptRoot\Config.PSD1

# Creating variables to determine magic strings and getting them from the configuration file
$LECertFolder = $config.LECertFolder
$LECertThumbprint = $config.LECertThumbprint
$LECertName = $config.LECertName
$LECertPass = $config.LECertPass
$LECertKey = $config.LECertKey
$LogFile = $config.LogFile
$CertServer = $config.CertServer
$WugServer = $config.WugServer
$ContServer = $Config.ContServer
$RDServer = $Config.RDServer
$OriginEmail = $config.OriginEmail
$TargetEmail = $config.TargetEmail
$LogModuleLocation = $config.LogModuleLocation

# Importing the SSW Write-Log module
Import-Module -Name Write-Log

# Creating error variables that will be used at the end
$Script:GetThumbprintError = $false
$Script:ExportSSWCertError = $false
$Script:SetWugCertError = $false
$Script:SetContServerError = $false

# Get the new certificate's thumbprint
Function Get-Thumbprint {
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
    Try {
        $item = get-childitem -path Cert:\LocalMachine\My
        $CurrentDate = Get-Date -Format "dd-MM-yyyy"
        $item = $item | where-object { $_.Issuer -eq "CN=R11, O=Let's Encrypt, C=US" -and $_.NotBefore.ToString("dd-MM-yyyy") -eq $CurrentDate }
        Set-Content -Path $CertThumbprint -Value $item.Thumbprint -ErrorAction Stop
        Write-Log -errorLevel SUCCESS -Message "New Thumbprint written to $CertThumbprint"
    }
    Catch {
        $Script:GetThumbprintError = $true
        $RecentError = $Error[0]
        Write-Log -errorLevel ERROR $LogFile -Message "ERROR on function Get-Thumbprint - $RecentError"
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
        $CertFolder,
        [Parameter(Mandatory)]
        $LogFile,
        [Parameter(Mandatory)]
        $WugServer
    )

    try {
        Copy-Item "$LECertFolder\$CertName" -Destination "\\$WugServer\C$\temp"
        Invoke-Command -ComputerName $WugServer -ArgumentList $CertThumbprint, $CertName, $CertPass, $CertKey, $CertFolder -erroraction Stop -ScriptBlock {
            $CertThumbprint = $args[0]
            $CertName = $args[1]
            $FullCertFolder = "C:\temp\ssw.com.au.pfx"
            $mypwd = $args[2] | ConvertTo-SecureString -Key $args[3]
            Import-PfxCertificate -FilePath $FullCertFolder -CertStoreLocation Cert:\LocalMachine\My -Password $mypwd

            $guid1 = [guid]::NewGuid().ToString("B")
            netsh http add sslcert hostnameport="*:443" certhash=$CertThumbprint certstorename=MY appid="$guid1"          
            $binding1 = Get-WebBinding -hostheader "*" -Port 443
            $binding1.AddSslCertificate($CertThumbprint, "my")          
        }
        Write-Log -errorLevel SUCCESS -Message "Exported certificate to $WugServer, certificate thumbprint is $CertThumbprint..."
    }
    catch {
        $Script:SetWugCertError = $true
        $RecentError = $Error[0]
        Write-Log -errorLevel ERROR -Message "ERROR on function Set-WugCert - $RecentError"
    }
}

<#
.SYNOPSIS
Copy the new exported certificate to WiFi controller/seq.

.DESCRIPTION
Copy the new exported certificate to WiFi controller/seq.

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

.PARAMETER ContServer
The name of the server that WiFi controller/seq are on.

.EXAMPLE
PS> Set-ContCert -CertThumbprint (Get-Content $LECertThumbprint) -CertName (Get-Content $LECertName) -CertPass (Get-Content $LECertPass) -CertKey (get-content $LECertKey) -WapxUser $WapxUser -WapxPass $WapxPass -CertFolder $LECertFolder -LogFile $LogFile -ContServer $ContServer

#>

function Set-ContCert {
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
        $LogFile,
        [Parameter(Mandatory)]
        $ContServer
    )

    try {
        Copy-Item "$LECertFolder\$CertName" -Destination "\\$ContServer\C$\temp"
        Invoke-Command -ComputerName $ContServer -ArgumentList $CertThumbprint, $CertName, $CertPass, $CertKey, $CertFolder -erroraction Stop -ScriptBlock {
            $CertThumbprint = $args[0]
            $CertName = $args[1]
            $FullCertFolder = "C:\temp\ssw.com.au.pfx"
            $mypwd = $args[2] | ConvertTo-SecureString -Key $args[3]
            Import-PfxCertificate -FilePath $FullCertFolder -CertStoreLocation Cert:\LocalMachine\My -Password $mypwd      
        }
        Write-Log -errorLevel SUCCESS -Message "Exported certificate to $ContServer, certificate thumbprint is $CertThumbprint..."
    }
    catch {
        $Script:SetStagingServerError = $true
        $RecentError = $Error[0]
        Write-Log -errorLevel ERROR -Message "ERROR on function Set-ContCert - $RecentError"
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
        $ErroredActions += "<li style=color:red;>&#9940; $CertServer - <strong>ERROR</strong> on exporting the certificate | Check the log at $LogFile</li>"
    }
    else {
        $CoolActions += "<li style=color:green;>&#9989; $CertServer - <strong>SUCCESS</strong> on exporting the certificate</li>"
    }
    if ($Script:SetWugCertError -eq $true) {
        $ErroredActions += "<li style=color:red;>&#9940; $WugServer - <strong>ERROR</strong> on setting the WUG certificate | Check the log at $LogFile</li>"
    }
    else {
        $CoolActions += "<li style=color:green;>&#9989; $WugServer - <strong>SUCCESS</strong> on setting the WUG certificate</li>"
    }
    if ($Script:SetContServerError -eq $true) {
        $ErroredActions += "<li style=color:red;>&#9940; $ContServer - <strong>ERROR</strong> on copying the Controller server certificate | Check the log at $LogFile</li>"
    }
    else {
        $CoolActions += "<li style=color:green;>&#9989; $ContServer - <strong>SUCCESS</strong> on copying the Controller server certificate</li>"
    }    

    $Script:bodyhtml = @"
    <div style='font-family:Calibri'>
    <p><h3>To SSWSysAdmins,</h3>
    <p>SSL Certificates are a pain and can be expensive. They can, however, be free if you leverage the power of <a href="https://letsencrypt.org/">Let's Encrypt</a>, which is a nonprofit Certificate Authority that provides free SSL certificates. <br>
    The only downside is that they need to be renewed every 3 months - SSW.CertExporter takes the pain out of it, used in conjunction with <a href="https://www.win-acme.com/">win-acme</a>, it can automatically export the renewed certificate and import and set them on your websites and applications in different servers.<p>As per rule: <a href="https://rules.ssw.com.au/do-you-use-free-or-paid-ssl-certificates">Do you use free or paid SSL certificates?</a></p>
    
    <p>If this email has been sent, it means <a href="https://www.win-acme.com/">win-acme</a> has renewed the SSW certificate in $CertServer, and SSW.CertExporter PowerShell script ran.
    <p><h4>win-acme did the following:</h4>
    <ol>
    <li>Sucessfully renewed the ssw.com.au SSL certificate
    <li>A <a href="https://www.win-acme.com/reference/plugins/installation/script">Post-Request Script</a> executed this SSW.CertExporter PowerShell script
    </ol>
    <p><h4>SSW.CertExporter did the following:</h4><ol> 
"@
    $Script:bodyhtml += $CoolActions
    $Script:bodyhtml += $ErroredActions
    $Script:bodyhtml += @"
    </ol>
    <p><h4>Now manually action:</p></h4>
    <ol>
        <li>Go to ASDM | Follow this <a href="https://sswcom.sharepoint.com/:w:/r/SysAdmin/SharedDocuments/Procedures/HowTos-ChangeASDMCertificate.docx?d=w5a3cb2870d31441593d09dcb3391757e&csf=1&web=1&e=Bl9eW2">guide</a> | Install new certificate (can be found in $LECertFolder) </li>
        <li>Go to $ContServer and install the certificate in Unifi and Seq</li>
        <ul>
            <li><a href = "https://sswcom.sharepoint.com/:w:/r/sites/SSWSysAdmins/Shared%20Documents/General/Certificates/HowTos-Install-Replace-SSL-Certificate-on-Unifi-Controller.docx?d=w6a26c0eaf9b64adaa41a98cd95da3294&csf=1&web=1&e=vuEDSU">Unifi instructions here</a></li>
            <li><a href = "https://docs.datalust.co/docs/ssl">Seq instructions here</a></li>
        </ul>
        <li>Go to all Domain Controllers and check that the NPS certificate is current (i.e. not expiring in the next 30 days):</li>
        <ul>
            <li>Go to <b>NPS | Policies | Network Policies | Secure Wireless Connections | Constraints | Edit</b> and check the date</li>
            <li>Select a new certificate if required</li>
            <li>Click <b>OK | OK</b> (even if the date was already OK)</li>
        </ul>
        </ul>
        <li>Go to $RDServer and change the Remote Desktop Gateway certificate for all 4 roles
        <ul>
            <li><a href="https://sswcom.sharepoint.com/:w:/r/sites/SSWSysAdmins/Shared%20Documents/General/CyberSecurity/HowTos-Remote-Desktop-Gateway.docx?d=wa13f5559789e4a418a7caea0eb8a0a87&csf=1&web=1&e=AXPuJm">RD Gateway instructions here | Section "Certificate Management"</a></li>
        </ul>
        </li>
    </ol>
    
    <p>-- Powered by SSWSysAdmins.SSWCertExporter<br>
    <br>GitHub: <a href="https://github.com/SSWConsulting/SSWSysAdmins.CertExporter">SSWSysAdmins.CertExporter</a><br>
    Server: $WebServer <br>
    Folder: $PSScriptRoot</p></div>
"@
}

# Let's run the commands one by one
Get-Thumbprint -CertKey (get-content $LECertKey) -CertFolder $LECertFolder -CertThumbprint $LECertThumbprint -CertName (Get-Content $LECertName) -LogFile $LogFile -CertPass (Get-Content $LECertPass)
Set-WugCert -CertThumbprint (Get-Content $LECertThumbprint) -CertName (Get-Content $LECertName) -CertPass (Get-Content $LECertPass) -CertKey (get-content $LECertKey) -CertFolder $LECertFolder -LogFile $LogFile -WugServer $WugServer
Set-ContCert -CertThumbprint (Get-Content $LECertThumbprint) -CertName (Get-Content $LECertName) -CertPass (Get-Content $LECertPass) -CertKey (get-content $LECertKey) -CertFolder $LECertFolder -LogFile $LogFile -ContServer $ContServer
New-EmailMessage
Send-MailMessage -From $OriginEmail -to $TargetEmail -Subject "SSW.Certificates - Main SSW Certificate Renewed - Further manual action required" -Body $Script:bodyhtml -SmtpServer "ssw-com-au.mail.protection.outlook.com" -BodyAsHtml
