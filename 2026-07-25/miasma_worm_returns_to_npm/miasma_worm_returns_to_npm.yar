import "hash"
// Salamander CTI  //  https://salacti.com
// Miasma Worm Returns to npm

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Miasma v3"
  condition:
    false  // no file hashes in this brief
}
