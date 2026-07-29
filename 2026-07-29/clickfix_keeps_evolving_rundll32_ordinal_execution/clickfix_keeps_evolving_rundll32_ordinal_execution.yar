import "hash"
// Salamander CTI  //  https://salacti.com
// ClickFix Keeps Evolving: Rundll32 Ordinal Execution over WebDAV

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "ClearFake"
  condition:
    hash.sha256(0, filesize) == "f11057ab58bef936d98ba189829c64260a6a540cdaa046f93613138e820c98c6" or
    hash.md5(0, filesize) == "5ef7bf4ed52be2a6d5ebbcf3076fba5f" or
    hash.sha1(0, filesize) == "9e03e983e26d4782a3fef0a6ebb47fdcd46974c9"
}
