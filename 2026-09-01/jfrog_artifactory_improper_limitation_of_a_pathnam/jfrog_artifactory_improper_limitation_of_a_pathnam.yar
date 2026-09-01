import "hash"
// Salamander CTI  //  https://salacti.com
// JFrog Artifactory Improper Limitation of a Pathname to a Restricted Directory Vulnerability

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
