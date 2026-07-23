import "hash"
// Salamander CTI  //  https://salacti.com
// Branded Gambling Campaigns: How Scammers Are Exploiting Trusted Brand Names to Drive Casino Traffic

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
