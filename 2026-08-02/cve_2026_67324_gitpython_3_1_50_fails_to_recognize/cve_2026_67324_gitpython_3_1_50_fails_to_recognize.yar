import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-67324: GitPython 3.1.50 fails to recognize joined short-option forms such as -u<value> (the short

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
