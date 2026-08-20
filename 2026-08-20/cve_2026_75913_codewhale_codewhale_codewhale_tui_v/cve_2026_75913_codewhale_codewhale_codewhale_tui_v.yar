import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-75913: CodeWhale (codewhale / codewhale-tui) versions >= 0.8.41 and < 0.8.64 contain an argument 

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
