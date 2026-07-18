import "hash"
// Salamander CTI  //  https://salacti.com
// Behind the Refund: From GST Phishing to Remcos RAT Through a Multi-Stage .NET Infection Chain

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Remcos RAT"
  condition:
    hash.md5(0, filesize) == "07d7d21c2c0920d198efb9ea54900a80" or
    hash.md5(0, filesize) == "20476f3a51dfddf3dc0603fc7858d894" or
    hash.md5(0, filesize) == "2a34bdd25b404737ee5d3b52bf0b3b70" or
    hash.md5(0, filesize) == "3757dccb2adae65ccdf8d5e5c948b927" or
    hash.md5(0, filesize) == "7842d12d9e37c75076133be5b9904cb2" or
    hash.md5(0, filesize) == "cc34d9760394104ad47877a0d57e9c63"
}
