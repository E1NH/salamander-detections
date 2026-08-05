import "hash"
// Salamander CTI  //  https://salacti.com
// Analysis of a Phishing Email Attack Case

rule Salamander_Larva_24009
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Larva-24009"
    malware = "Quasar RAT"
  condition:
    hash.md5(0, filesize) == "10b40185106eb3760cb71c46117aa0bf" or
    hash.md5(0, filesize) == "1500fefcdda275b70e2051a3e7d9f794" or
    hash.md5(0, filesize) == "2973fda8d0d0fa0200a05889fce85df6" or
    hash.md5(0, filesize) == "444fb3592cd1848660259a913684795b" or
    hash.md5(0, filesize) == "4ad28d0313549e98383144d82982be6e"
}
