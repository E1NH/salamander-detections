import "hash"
// Salamander CTI  //  https://salacti.com
// Cisco Secure Firewall Management Center Use of Hard-coded Password Vulnerability

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
