import "hash"
// Salamander CTI  //  https://salacti.com
// Inside the FortiBleed Open Directory: A Technical Analysis of What the Attacker Left Behind

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
