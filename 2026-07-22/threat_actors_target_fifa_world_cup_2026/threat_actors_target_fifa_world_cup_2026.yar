import "hash"
// Salamander CTI  //  https://salacti.com
// Threat Actors Target FIFA World Cup 2026

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
