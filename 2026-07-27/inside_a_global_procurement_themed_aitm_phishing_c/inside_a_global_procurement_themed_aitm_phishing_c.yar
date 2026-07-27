import "hash"
// Salamander CTI  //  https://salacti.com
// Inside a Global Procurement-Themed AiTM Phishing Campaign

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "IClickFix"
  condition:
    false  // no file hashes in this brief
}
