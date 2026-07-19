import "hash"
// Salamander CTI  //  https://salacti.com
// "Ghost" Code Phishing Analysis

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "EvilTokens"
  condition:
    hash.md5(0, filesize) == "fcd1b654a0b3e8f85ca7cfdafe494d4b"
}
