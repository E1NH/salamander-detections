import "hash"
// Salamander CTI  //  https://salacti.com
// Large-Scale GitHub Actions Abuse Powers a Distributed cPanel and WHM Exploitation Campaign

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = ""
  condition:
    hash.md5(0, filesize) == "572745566ec674c6eae10c179b0de2ba" or
    hash.sha1(0, filesize) == "e219da0599dea936ee867792e2dfe6a2c2a7c68b" or
    hash.sha256(0, filesize) == "22f721fd3a81d2e27cbf90a122bb977f630c50b79daa98350f0e57b04dfa81f1"
}
