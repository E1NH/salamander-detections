import "hash"
// Salamander CTI  //  https://salacti.com
// ConnectWise ScreenConnect Improper Privilege Management and Missing Authorization Vulnerability

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
