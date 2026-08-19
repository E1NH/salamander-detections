import "hash"
// Salamander CTI  //  https://salacti.com
// Fraudulent Employment Operations

rule Salamander_PurpleDelta
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "PurpleDelta"
    malware = ""
  condition:
    false  // no file hashes in this brief
}
