import "hash"
// Salamander CTI  //  https://salacti.com
// Payouts King Ransomware Initial Access Broker Deploys New Edgecution Malware

rule Salamander_Payouts_King
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Payouts King"
    malware = "Edgecution"
  condition:
    hash.sha256(0, filesize) == "3d1158884fb339b3328bd330fcc27598e1f1c94bcac39e75d1a272afa4deee1a" or
    hash.sha256(0, filesize) == "a08d8e63b0cd3638fb40b8e6da546e26da69439597565827f9cec87915f78568"
}
