import "hash"
// Salamander CTI  //  https://salacti.com
// NadMesh Botnet Analysis: Product-Level Threat in the AI Services Era

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "NadMesh"
  condition:
    hash.md5(0, filesize) == "ca024acead8f54cfe5b07ac4bdf7fcea" or
    hash.sha1(0, filesize) == "31c69b3e12936abca770d430066f379ec1d997ec" or
    hash.sha256(0, filesize) == "fc4109f5dd1d30b65dd60e57dc639ac1d313bfa5241e36e61fbc4aabc1cda482"
}
