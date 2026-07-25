import "hash"
// Salamander CTI  //  https://salacti.com
// GitHub Impersonation Deploys Information Stealer

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "BoryptGrab Stealer"
  condition:
    hash.md5(0, filesize) == "b98575f3c0259b480a31b917aa73bc56" or
    hash.md5(0, filesize) == "fd01262bd56510088b9ddfe58ca101ab"
}
