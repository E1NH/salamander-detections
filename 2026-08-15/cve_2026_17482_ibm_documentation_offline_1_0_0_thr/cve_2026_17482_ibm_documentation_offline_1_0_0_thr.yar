import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-17482: IBM Documentation Offline 1.0.0 through 1.4.1 could allow a remote attacker to execute arb

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
