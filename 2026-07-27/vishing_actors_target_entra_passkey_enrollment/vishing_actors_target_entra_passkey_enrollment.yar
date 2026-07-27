import "hash"
// Salamander CTI  //  https://salacti.com
// Vishing actors target Entra passkey enrollment

rule Salamander_O_UNC_066
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "O-UNC-066"
    malware = ""
  condition:
    false  // no file hashes in this brief
}
