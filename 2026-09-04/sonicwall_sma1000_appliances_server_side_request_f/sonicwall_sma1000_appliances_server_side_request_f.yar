import "hash"
// Salamander CTI  //  https://salacti.com
// SonicWall SMA1000 Appliances Server-Side Request Forgery Vulnerability

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
