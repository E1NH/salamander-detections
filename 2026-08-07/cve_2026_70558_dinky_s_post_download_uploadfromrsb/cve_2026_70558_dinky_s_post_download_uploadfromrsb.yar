import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-70558: Dinky's POST /download/uploadFromRsByLocal handler passes the caller-supplied path paramet

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
