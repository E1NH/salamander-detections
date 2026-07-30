import "hash"
// Salamander CTI  //  https://salacti.com
// The Scam Will Go On: Beware of Fake Offers for Celine Dion Concert Tickets

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
