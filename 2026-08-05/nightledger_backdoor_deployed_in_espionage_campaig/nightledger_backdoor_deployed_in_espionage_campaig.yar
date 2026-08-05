import "hash"
// Salamander CTI  //  https://salacti.com
// NightLedger Backdoor Deployed in Espionage Campaign Targeting the Middle East and Africa

rule Salamander_Mirage_Kitten
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Mirage Kitten"
    malware = "NightLedger, BridgeHead, ArcBridge, TWOSTROKE"
  condition:
    hash.md5(0, filesize) == "a239e655709a2518dd0b7bdbed163679" or
    hash.sha1(0, filesize) == "79f3ef6c6127edb0a5f43ef7a16bfb3418860e19" or
    hash.sha256(0, filesize) == "24771d0a69e442b9493ab1406e0253be1acd31d83f593177fd736f7f6d629ed9"
}
