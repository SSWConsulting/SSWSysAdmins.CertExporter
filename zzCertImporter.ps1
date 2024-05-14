### No longer in use.
### This script imports our certificate to all DCs, to be used by NPS (RADIUS auth for WiFi).

# Importing the configuration file
$config = Import-PowerShellDataFile $PSScriptRoot\Config.PSD1

# Creating variables to determine magic strings and getting them from the configuration file
$filePath = $config.filePath
$certStoreLocation = $config.certStoreLocation
$certPass = Get-Content $config.certPass
$certKey = Get-Content $config.certKey
$password = $certPass | ConvertTo-SecureString -Key $certKey
$PDC = $config.PDC
$DCs = $config.DCs
$logLocation = $config.logLocation
$emailFrom = $config.emailFrom
$emailTo = $config.emailTo
$emailSmtp = $config.emailSmtp
$failedDCs = ""

# Get a timestamp for logging
function Get-TimeStamp
{    
    return "[{0:yyyy/MM/dd} {0:HH:mm:ss}]" -f (Get-Date)   
}

Try
{
    # Import PFX to PDC
    Import-PfxCertificate -FilePath $filePath -CertStoreLocation $certStoreLocation -Password $password -ErrorAction Stop
    Write-Output "$(Get-TimeStamp) Certificate successfully imported on $PDC" | Out-File $logLocation -Append
}
Catch
{
    Write-Output "$(Get-TimeStamp) $PDC`: $_" | Out-File $logLocation -Append
    $failedDCs = $failedDCs + $PDC
}

# Copy PFX to each DC and Import
ForEach ($DC in $DCs) {
    Try
    {
        Copy-Item $filePath -Destination "\\$dc\c$\DataImportant\CertImporter" -ErrorAction Stop
        Invoke-Command -ComputerName "$dc" -ArgumentList $filePath, $certStoreLocation, $password -ErrorAction Stop -ScriptBlock {
            $filePath = $args[0]
            $certStoreLocation = $args[1]
            $password = $args[2]
            Import-PfxCertificate -FilePath $filePath -CertStoreLocation $certStoreLocation -Password $password
            Restart-Service -Name "IAS"
        }
        Write-Output "$(Get-TimeStamp) Certificate successfully imported on $DC" | Out-File $logLocation -Append
    }
    Catch
    {
        Write-Output "$(Get-TimeStamp) $DC`: $_" | Out-File $logLocation -Append
        $failedDCs = $failedDCs + ", $DC"
    }
}

# Set up the error alert email
$emailBody = @"
    <H3>Hi SysAdmins,</H3>
    <p>We have a script that runs on $PDC to import our wildcard certificate on all DCs for RADIUS auth for Wifi.</br>
    This script has failed on $failedDCs.</p>
    <ol>
        <li>Please check the log file on $PDC in C:\DataImportant\CertImporter, investigate and fix.</li>
    </ol>
    <p>Thanks!</p>
    <p>Powered by C:\DataImportant\CertImporter\CertImporter.ps1 pn $PDC</p>
"@

$emailParams = @{
    From = $emailFrom
    To = $emailTo
    Subject = "Certificate import failed on $failedDCs"
    Body = $emailBody
    SmtpServer = $emailSmtp
}

# If any DCs errored, send the email
If ($failedDCs)
{
    Send-MailMessage @emailParams -BodyAsHtml
}
