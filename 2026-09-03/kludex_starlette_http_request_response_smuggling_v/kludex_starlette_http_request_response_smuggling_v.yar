import "hash"
// Salamander CTI  //  https://salacti.com
// Kludex Starlette HTTP Request/Response Smuggling Vulnerability

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
