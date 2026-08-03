import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-69083: SiYuan versions before v3.7.3 contain SQL injection vulnerabilities in the fullTextSearchA

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
