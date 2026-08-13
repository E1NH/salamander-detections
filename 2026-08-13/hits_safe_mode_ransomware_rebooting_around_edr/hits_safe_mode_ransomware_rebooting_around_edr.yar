import "hash"
// Salamander CTI  //  https://salacti.com
// Hits Safe Mode: Ransomware Rebooting Around EDR

rule Salamander_Storm_1567
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Storm-1567"
    malware = "Akira, AnyDesk"
  condition:
    hash.sha256(0, filesize) == "e2356c742c74cce5c6b6100162d0071a3f71e2fed2ed895c2011061a95b3299a" or
    hash.md5(0, filesize) == "61a1ad1b6a028a1833c85e6544383999" or
    hash.sha1(0, filesize) == "bb6f97878c8cbf762d69717b3480658fe9157ff0" or
    hash.sha256(0, filesize) == "414b9985f46714f44dd1bd63860d2a48dcfababcfe5c712a4b4f575378127a56"
}
