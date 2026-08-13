import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-73268: A flaw was found in the cluster-curator-controller component of multicluster engine (MCE)

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
