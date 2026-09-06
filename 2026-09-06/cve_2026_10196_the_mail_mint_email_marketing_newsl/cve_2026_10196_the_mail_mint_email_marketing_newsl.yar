import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-10196: The Mail Mint – Email Marketing, Newsletter, Email Automation & WooCommerce Emails plugin 

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
