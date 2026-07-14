import "hash"
// Salamander CTI  //  https://salacti.com
// Phishing Campaign PasasteSinTAG - New domain rotation identified associated with the campaign impersonating the PasasteSinTAG portal

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
