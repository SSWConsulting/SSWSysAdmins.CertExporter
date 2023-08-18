# This script is run automatically after win.acme renews the certifcate. It updates the certificate bindings for SSRS.
# Based on this: https://ruiromanoblog.wordpress.com/2010/05/08/configure-reporting-services-ssl-binding-with-wmi-powershell/

param($newthumb, $oldthumb)

$newthumb = $newthumb.ToLower()
$oldthumb = $oldthumb.ToLower()

# Importing the configuration file
$config = Import-PowerShellDataFile $PSScriptRoot\Config.PSD1

# Creating variables to determine magic strings and getting them from the configuration file
$serverName = $config.ServerName
$certSubject = $config.certSubject
$ssrsServerName = $config.ssrsServerName
$httpsPort = $config.httpsPort
$ipAddress = $config.ipAddress
$emailTo = $config.emailTo
$emailFrom = $config.emailFrom
$emailSmtp = $config.emailSmtp
$logLocation = $config.logLocation

$errors = ""

# Get a timestamp for logging
function Get-TimeStamp
{    
    return "[{0:yyyy/MM/dd} {0:HH:mm:ss}]" -f (Get-Date)   
}

$wmiName = (Get-WmiObject -namespace root\Microsoft\SqlServer\ReportServer -Filter "Name='$ssrsServerName'"  -class __Namespace).Name
$version = (Get-WmiObject -namespace root\Microsoft\SqlServer\ReportServer\$wmiName  -class __Namespace).Name
$rsConfig = Get-WmiObject -namespace "root\Microsoft\SqlServer\ReportServer\$wmiName\$version\Admin" -class MSReportServer_ConfigurationSetting

if ($oldthumb -ne $newthumb) {
    $r = $rsConfig.RemoveSSLCertificateBindings('ReportManager', $oldthumb, $ipAddress, $httpsport, 1033)
    if (!($r.HRESULT -eq 0)) {
        $errors = $r.Error
    }
    $r = $rsConfig.RemoveSSLCertificateBindings('ReportServerWebService', $oldthumb, $ipAddress, $httpsport, 1033)
    if (!($r.HRESULT -eq 0)) {
        $errors = $errors + "`r`n" + $r.Error
    }
    $r = $rsConfig.CreateSSLCertificateBinding('ReportManager', $newthumb, $ipAddress, $httpsport, 1033)
    if (!($r.HRESULT -eq 0)) {
        $errors = $errors + "`r`n" + $r.Error
    }
    $r = $rsConfig.CreateSSLCertificateBinding('ReportServerWebService', $newthumb, $ipAddress, $httpsport, 1033)
    if (!($r.HRESULT -eq 0)) {
        $errors = $errors + $r.Error
    }
}

# Set up the error alert email
$emailBody = @"
    <H3>Hi SysAdmins,</H3>
    <p>We have a script that runs on $ServerName to update the SSL certificate for reports.ssw.com.au.</br>
    The script has failed :(.</p>
    <ol>
        <li>Please check the log file in $logLocation, investigate and fix.</li>
    </ol>
    <p>Thanks!</p>
    <p>Powered by $PSScriptRoot\update-ssrs-cert.ps1 on $ServerName</p>
"@

$emailParams = @{
    From = $emailFrom
    To = $emailTo
    Subject = "Certificate update failed on $ServerName"
    Body = $emailBody
    SmtpServer = $emailSmtp
}

If ($errors) {
    Write-Output "`r`n $(Get-TimeStamp) `r`n $errors" | Out-File $logLocation -Append
    Send-MailMessage @emailParams -BodyAsHtml
}
Else {
    Write-Output "`r`n $(Get-TimeStamp) Certificate replaced successfully." | Out-File $logLocation -Append
}