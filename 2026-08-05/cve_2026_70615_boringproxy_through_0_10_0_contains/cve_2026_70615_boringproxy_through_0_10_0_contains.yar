import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-70615: boringproxy through 0.10.0 contains a newline injection vulnerability that allows authenti

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
