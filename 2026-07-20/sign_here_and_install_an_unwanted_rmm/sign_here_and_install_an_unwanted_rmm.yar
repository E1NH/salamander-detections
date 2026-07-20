import "hash"
// Salamander CTI  //  https://salacti.com
// Sign here… and install an unwanted RMM

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Unknown malware"
  condition:
    hash.md5(0, filesize) == "43a151ada3024e8f9a08b040d744ca7c" or
    hash.sha256(0, filesize) == "238df253ffd9f45faf5f503210116abad556fbbfd27c7584e9ad040201acb553"
}
