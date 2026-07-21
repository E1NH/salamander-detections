import "hash"
// Salamander CTI  //  https://salacti.com
// JADEPUFFER evolves: The agentic threat actor deploys ransomware built to destroy AI models

rule Salamander_JADEPUFFER
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "JADEPUFFER"
    malware = "ENCFORGE"
  condition:
    hash.sha256(0, filesize) == "8cb0c223b018cecef1d990ec81c67b826eb3c30d54f06193cf69969e9a8baea2" or
    hash.sha256(0, filesize) == "ab9824b61587c77a8d8649545cdbdc63ed2c384e45c9aba534e3f457f96efa7a" or
    hash.sha256(0, filesize) == "ea7822eac6cecef7746c606b862b4d3034856caf754c4cf69533662637905328"
}
