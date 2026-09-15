import "hash"
// Salamander CTI  //  https://salacti.com
// Thai Broadband Provider Targeted via FortiGate SSL-VPN and MeshCentral Persistence

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
