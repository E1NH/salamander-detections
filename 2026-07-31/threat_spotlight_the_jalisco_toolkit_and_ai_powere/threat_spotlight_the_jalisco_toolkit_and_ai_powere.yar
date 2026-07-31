import "hash"
// Salamander CTI  //  https://salacti.com
// Threat Spotlight: The Jalisco Toolkit and AI-Powered Phishing Surge

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Jalisco, OmegaLord, EvilTokens, Kali365, Tycoon2fa, Venom, Darcula"
  condition:
    hash.md5(0, filesize) == "9f8a2983fbf5479e8d8c267e0df4e73d"
}
