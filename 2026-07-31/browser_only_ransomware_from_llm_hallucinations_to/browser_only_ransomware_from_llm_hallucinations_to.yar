import "hash"
// Salamander CTI  //  https://salacti.com
// Browser-Only Ransomware: From LLM Hallucinations to a Practical Attack Technique

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "InfernoGrabber, VoidLink"
  condition:
    hash.sha256(0, filesize) == "07c39f79ab92fb21557b82283472dce1c112f577d796111fb752c3c6d84c86b5"
}
