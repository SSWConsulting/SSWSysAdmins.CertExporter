# No need to run me manually - I run automatically when the ssw.com.au certificate is updated.

param($CertThumbprint)

netsh http delete sslcert hostnameport="reports.ssw.com.au:443"

netsh http delete sslcert hostnameport="snipe.ssw.com.au:443"

netsh http delete sslcert hostnameport="octopus.ssw.com.au:443"

netsh http delete sslcert hostnameport="clicks.ssw.com.au:443"


$guid1 = [guid]::NewGuid().ToString("B")

netsh http add sslcert hostnameport="reports.ssw.com.au:443" certhash=$CertThumbprint certstorename=MY appid="$guid1"



$guid2 = [guid]::NewGuid().ToString("B")

netsh http add sslcert hostnameport="snipe.ssw.com.au:443" certhash=$CertThumbprint certstorename=MY appid="$guid2"



$guid3 = [guid]::NewGuid().ToString("B")

netsh http add sslcert hostnameport="octopus.ssw.com.au:443" certhash=$CertThumbprint certstorename=MY appid="$guid3"


$guid4 = [guid]::NewGuid().ToString("B")

netsh http add sslcert hostnameport="clicks.ssw.com.au:443" certhash=$CertThumbprint certstorename=MY appid="$guid4"




$binding1 = Get-WebBinding -hostheader "reports.ssw.com.au" -Port 443

$binding1.AddSslCertificate($CertThumbprint, "my")


$binding2 = Get-WebBinding -hostheader "snipe.ssw.com.au" -Port 443

$binding2.AddSslCertificate($CertThumbprint, "my")


$binding3 = Get-WebBinding -hostheader "octopus.ssw.com.au" -Port 443

$binding3.AddSslCertificate($CertThumbprint, "my")


$binding4 = Get-WebBinding -hostheader "clicks.ssw.com.au" -Port 443

$binding4.AddSslCertificate($CertThumbprint, "my")