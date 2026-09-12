import "hash"
// Salamander CTI  //  https://salacti.com
// GitLab Community Edition and Enterprise Edition Path Traversal Vulnerability

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
