import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-79675: NLTK before 3.10.3 fails to validate JVM options passed through the per-call options param

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
