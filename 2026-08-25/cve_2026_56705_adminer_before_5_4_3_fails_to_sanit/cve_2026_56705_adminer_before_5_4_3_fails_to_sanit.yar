import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-56705: Adminer before 5.4.3 fails to sanitize the server field before constructing a PDO DSN stri

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = ""
  condition:
    false  // no file hashes in this brief
}
