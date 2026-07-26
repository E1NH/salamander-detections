import "hash"
// Salamander CTI  //  https://salacti.com
// New customs charges for online orders outside the EU

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
