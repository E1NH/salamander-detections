import "hash"
// Salamander CTI  //  https://salacti.com
// Tomorrowland 2026, Belgium: People of Tomorrow, Targets of Today

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
