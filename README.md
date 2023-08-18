# SSWSysAdmins.CertExporter
SSW Certificate Exporter for various SSW-owned websites and servers.

This script exports newly renewed certificate to various servers and website, and automatically sets it as the main certificate.
Also sends an email at the end with failures and successes.

We now have extra scripts to automate more of our certificate tasks alongside CertExporter:
- CertImporter for NPS
- fix-certs and fix-certs-timepro for IIS servers with tricky bindings
- update-octopus-thumbprint and to update the thumbprint variable in Octopus Deploy
- update-ssrs-cert for SQL Server Report Services

Owners: [Kaique Biancatti](https://www.ssw.com.au/people/kaique-biancatti), [Chris Schultz](https://www.ssw.com.au/people/chris-schultz)
