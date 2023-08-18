#don't run me unless you're sure you need to - I run automatically when the certificate is renewed :)
#if you do need to run me manually, add the thumbprint as a parameter - i.e. run c:\scripts\fix-certs-timepro.ps1 -CertThumbprint {{ thumbprint }}

param ($CertThumbprint)

netsh http delete sslcert hostnameport="*.sswtimepro.com:443"

$guid1 = [guid]::NewGuid().ToString("B")

netsh http add sslcert hostnameport="*.sswtimepro.com:443" certhash=$CertThumbprint certstorename=MY appid="$guid1"

$binding1 = Get-WebBinding -hostheader "*.sswtimepro.com" -Port 443

$binding1.AddSslCertificate($CertThumbprint, "my")