import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-56793: Dell OpenManage Server Administrator, versions prior to 11.1.0.2, contains an Improper Aut

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = ""
  condition:
    false  // no file hashes in this brief
}
