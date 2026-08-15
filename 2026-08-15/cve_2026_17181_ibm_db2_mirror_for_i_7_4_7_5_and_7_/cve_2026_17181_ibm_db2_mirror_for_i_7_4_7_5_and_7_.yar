import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-17181: IBM Db2 Mirror for i 7.4, 7.5, and 7.6 could allow a remote attacker to write files to arb

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
