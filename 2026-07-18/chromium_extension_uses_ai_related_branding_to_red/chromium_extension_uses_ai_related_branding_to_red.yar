import "hash"
// Salamander CTI  //  https://salacti.com
// Chromium extension uses AI‑related branding to redirect browser search

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
