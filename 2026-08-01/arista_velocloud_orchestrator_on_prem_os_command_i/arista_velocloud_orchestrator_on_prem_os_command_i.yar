import "hash"
// Salamander CTI  //  https://salacti.com
// Arista VeloCloud Orchestrator On-Prem OS Command Injection Vulnerability

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
