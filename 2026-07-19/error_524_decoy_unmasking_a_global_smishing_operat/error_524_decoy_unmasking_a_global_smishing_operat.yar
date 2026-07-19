import "hash"
// Salamander CTI  //  https://salacti.com
// Error 524 Decoy: Unmasking a Global Smishing Operation Hiding Behind Error Pages

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
