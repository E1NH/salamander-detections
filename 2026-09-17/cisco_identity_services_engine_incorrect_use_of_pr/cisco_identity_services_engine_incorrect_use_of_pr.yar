import "hash"
// Salamander CTI  //  https://salacti.com
// Cisco Identity Services Engine Incorrect Use of Privileged APIs Vulnerability

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
