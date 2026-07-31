import "hash"
// Salamander CTI  //  https://salacti.com
// Cleaning Out Inboxes: TA488 Comes for Outlook with Another Half-Click Exploit

rule Salamander_TA488
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "TA488"
    malware = "OWAReaper, ZimReaper"
  condition:
    hash.sha256(0, filesize) == "6897b649f29e54d8910459963bbf94ed5c7a4fe66a56bc5962540b226b8e48c4"
}
