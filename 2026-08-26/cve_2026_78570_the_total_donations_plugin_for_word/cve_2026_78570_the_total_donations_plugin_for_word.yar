import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-78570: The Total Donations plugin for WordPress is vulnerable to Privilege Escalation in all vers

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
