import "hash"
// Salamander CTI  //  https://salacti.com
// JFrog Artifactory Incorrect Authorization Vulnerability

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
