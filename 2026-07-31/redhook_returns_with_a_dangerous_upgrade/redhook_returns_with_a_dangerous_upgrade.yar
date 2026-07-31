import "hash"
// Salamander CTI  //  https://salacti.com
// RedHook Returns with a Dangerous Upgrade

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "RedHook"
  condition:
    hash.sha256(0, filesize) == "453333bffdd1850ea2e0647f7c805530b578919978a01b1e2be52d6eb2add946"
}
