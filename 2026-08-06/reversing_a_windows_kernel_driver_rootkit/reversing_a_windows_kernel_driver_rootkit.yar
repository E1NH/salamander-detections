import "hash"
// Salamander CTI  //  https://salacti.com
// Reversing a Windows Kernel Driver Rootkit

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "CobaltStrike"
  condition:
    hash.sha256(0, filesize) == "4e95aba17c1a423cda5cc9f9f04f7cf8db17e294eb31ed1aa85063601b82fe8d" or
    hash.md5(0, filesize) == "b5f122f3f07f618c0a7678fa40801faa" or
    hash.sha1(0, filesize) == "7440358c5041eba34e8673100989df756a6426da"
}
