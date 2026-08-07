import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-54489: Dell Virtual Storage Integrator for VMware vSphere Client, versions prior to 10.11.1.0, co

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
