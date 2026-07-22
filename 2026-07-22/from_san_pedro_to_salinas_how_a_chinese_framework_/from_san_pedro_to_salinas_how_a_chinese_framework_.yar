import "hash"
// Salamander CTI  //  https://salacti.com
// From San Pedro to Salinas: How a Chinese Framework “DCloud Uni-App” Powers a Global Scam Economy

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
