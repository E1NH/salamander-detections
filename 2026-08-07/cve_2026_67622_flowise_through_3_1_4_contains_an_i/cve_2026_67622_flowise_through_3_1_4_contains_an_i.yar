import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-67622: Flowise through 3.1.4 contains an insecure direct object reference vulnerability in the Op

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
