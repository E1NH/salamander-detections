import "hash"
// Salamander CTI  //  https://salacti.com
// Supply Chain Compromise via GitHub Actions

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Miasma, M-RED-TEAM"
  condition:
    hash.sha1(0, filesize) == "22bf76fe317ea6769bd38619bd440e42d119bd6b" or
    hash.sha1(0, filesize) == "9890950adcbc2478e7a080234f053214adbad44e" or
    hash.sha1(0, filesize) == "a7e18d96efd3cdb127ef4cdcad9e3ad26c482bf2" or
    hash.sha1(0, filesize) == "c70e105e212ff3c1daa04bb2a62507717f296b0b" or
    hash.sha1(0, filesize) == "c8cb3f6d5b90c46686d2bf531dc1a5786e27edc5"
}
