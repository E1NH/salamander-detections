import "hash"
// Salamander CTI  //  https://salacti.com
// CitrixBleed 2 (CVE-2025-5777) 7 Steps to Dragonforce Ransomware

rule Salamander_DragonForce
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "DragonForce"
    malware = "DragonForce, Mimikatz, Impacket"
  condition:
    hash.sha256(0, filesize) == "c4fcae3847946173bf0b3cedf5d97a9e3d18090023842f942ba544fa7fda180d" or
    hash.sha256(0, filesize) == "c84739655ce1af0a0269138263d47567418f69e0f75e249f8e23bc21802209e2" or
    hash.sha256(0, filesize) == "eb083365dc70d0294e8c4f55a2e78be0edb0f3497f2a06a70c9f474dafab48d8"
}
