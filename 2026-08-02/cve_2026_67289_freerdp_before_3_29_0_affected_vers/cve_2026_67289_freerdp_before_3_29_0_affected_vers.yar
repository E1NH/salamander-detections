import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-67289: FreeRDP before 3.29.0 (affected versions <= 3.28.0) does not validate CRLF and control cha

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
