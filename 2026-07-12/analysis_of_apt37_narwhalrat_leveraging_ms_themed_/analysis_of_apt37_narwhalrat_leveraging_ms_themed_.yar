import "hash"
// Salamander CTI  //  https://salacti.com
// Analysis of APT37 NarwhalRAT Leveraging MS-Themed Phishing and Dead-drop C2

rule Salamander_APT37
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "APT37"
    malware = "NarwhalRAT, ROKRAT - S0240"
  condition:
    hash.md5(0, filesize) == "3715092aa00f380cefe8b4d2eddb7d08" or
    hash.md5(0, filesize) == "7cef19f9c4480adac0cd4702ff98f46c" or
    hash.md5(0, filesize) == "7eb9cee1f696727752169f25cf79a338" or
    hash.md5(0, filesize) == "b6b0602310bb2d4360c52685119aac1b"
}
