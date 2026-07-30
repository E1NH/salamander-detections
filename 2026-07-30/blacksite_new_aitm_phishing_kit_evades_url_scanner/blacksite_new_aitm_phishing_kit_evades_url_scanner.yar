import "hash"
// Salamander CTI  //  https://salacti.com
// Blacksite: New AiTM Phishing Kit Evades URL Scanners via Cloaked.gg

rule Salamander_kirapayload
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "kirapayload"
    malware = "Blacksite, Tycoon 2FA"
  condition:
    false  // no file hashes in this brief
}
