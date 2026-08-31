import "hash"
// Salamander CTI  //  https://salacti.com
// Philippine Nuclear Agency and Naval Contractor Targeted by Suspected Chinese-Speaking Operator Using Known Vulnerabilities

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "IClickFix, Unknown malware"
  condition:
    hash.sha256(0, filesize) == "10df3451915ea35bcb17efe121415f24182680e2d07fc09df07ee695072104c1" or
    hash.sha256(0, filesize) == "7447d0d0c34779d4c519823b39bf6ddc16d2b34a226b82ee69da6f5b4a77ad82"
}
