import "hash"
// Salamander CTI  //  https://salacti.com
// CVE-2026-4703: The WS Form LITE – Drag & Drop Contact Form Builder plugin for WordPress is vulnerable to 

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
