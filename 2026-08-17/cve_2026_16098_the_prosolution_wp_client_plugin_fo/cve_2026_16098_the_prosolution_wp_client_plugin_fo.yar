import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-16098: The ProSolution WP Client plugin for WordPress is vulnerable to Arbitrary File Upload in a

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
