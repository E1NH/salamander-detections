import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-3141: The FormGent plugin for WordPress is vulnerable to unauthorized arbitrary file deletion du

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
