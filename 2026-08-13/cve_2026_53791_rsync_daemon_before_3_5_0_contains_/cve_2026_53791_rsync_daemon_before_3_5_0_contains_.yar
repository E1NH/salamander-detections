import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-53791: rsync daemon before 3.5.0 contains an IP address spoofing vulnerability that allows unauth

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
