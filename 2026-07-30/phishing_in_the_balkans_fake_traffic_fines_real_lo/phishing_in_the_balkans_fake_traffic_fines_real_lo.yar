import "hash"
// Salamander CTI  //  https://salacti.com
// Phishing in the Balkans: Fake Traffic Fines, Real Losses

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
