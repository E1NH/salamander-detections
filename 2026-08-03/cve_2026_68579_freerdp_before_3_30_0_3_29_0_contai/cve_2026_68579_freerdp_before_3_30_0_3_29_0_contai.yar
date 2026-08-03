import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-68579: FreeRDP before 3.30.0 (<= 3.29.0) contains a heap-based buffer overflow in the Windows cli

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
