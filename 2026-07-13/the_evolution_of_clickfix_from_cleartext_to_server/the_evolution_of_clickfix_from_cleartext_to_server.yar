import "hash"
// Salamander CTI  //  https://salacti.com
// The Evolution of ClickFix: From Cleartext to Server Side Polymorphism

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "IClickFix, Unknown malware, Vidar"
  condition:
    false  // no file hashes in this brief
}
