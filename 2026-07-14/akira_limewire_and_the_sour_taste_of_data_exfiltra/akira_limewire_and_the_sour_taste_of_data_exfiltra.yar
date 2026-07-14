import "hash"
// Salamander CTI  //  https://salacti.com
// Akira, LimeWire, and the Sour Taste of Data Exfiltration

rule Salamander_Storm_1567
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Storm-1567"
    malware = "Akira"
  condition:
    hash.sha256(0, filesize) == "131877a052f62750d815cf55d4c14f606a26025e3094e1b8bb18bd1668e3beaa"
}
