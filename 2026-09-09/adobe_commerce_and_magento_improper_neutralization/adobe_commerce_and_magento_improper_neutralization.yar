import "hash"
// Salamander CTI  //  https://salacti.com
// Adobe Commerce and Magento Improper Neutralization of Special Elements Used in a Template Engine Vulnerability

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
