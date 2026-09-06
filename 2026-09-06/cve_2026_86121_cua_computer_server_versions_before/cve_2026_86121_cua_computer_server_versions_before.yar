import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-86121: Cua computer-server versions before 0.3.42 skip authentication when the CONTAINER_NAME env

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
