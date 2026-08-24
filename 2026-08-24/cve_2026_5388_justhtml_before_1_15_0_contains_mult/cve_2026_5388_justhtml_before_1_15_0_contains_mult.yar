import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-5388: justhtml before 1.15.0 contains multiple security issues in URL sanitization helpers (clea

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
