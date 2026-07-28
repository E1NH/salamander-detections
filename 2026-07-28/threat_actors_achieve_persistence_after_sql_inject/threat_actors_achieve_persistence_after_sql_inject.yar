import "hash"
// Salamander CTI  //  https://salacti.com
// Threat Actors Achieve Persistence After SQL Injection

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "BadIIS, XMRig, CnCrypt Protect"
  condition:
    hash.md5(0, filesize) == "c4c8e8c336c3429d97195076bf3bb6eb"
}
