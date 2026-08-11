import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-34265: SAP NetWeaver Application Server ABAP allows an unauthenticated attacker to exploit logica

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
