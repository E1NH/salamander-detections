import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-68771: ComfyUI v0.23.0 contains an unsafe deserialization vulnerability in the LoadTrainingDatase

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
