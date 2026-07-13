import "hash"
// Salamander CTI  //  https://salacti.com
// Operation Capsule Vault: RokRAT Attack Chain Analysis Using EMBED_PAYLOAD_v2

rule Salamander_APT37
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "APT37"
    malware = "ROKRAT - S0240"
  condition:
    hash.md5(0, filesize) == "e5c9bb3938f2a24e755ee39073fc3aca"
}
