import "hash"
// Salamander CTI  //  https://salacti.com
// Observed activity associated with Sidewinder APT. Lure document: No.9374.docx, 64f2681ad0940e6c2c9c76e6834117bf. Observed C2 infrastructure: update[.]ms-office[.]app

rule Salamander_RAZOR_TIGER
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "RAZOR TIGER"
    malware = ""
  condition:
    hash.md5(0, filesize) == "64f2681ad0940e6c2c9c76e6834117bf"
}
