import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-83627: The Hummingbird – Speed Optimization, Caching, Minify, Compress & CDN plugin for WordPress

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = ""
  condition:
    false  // no file hashes in this brief
}
