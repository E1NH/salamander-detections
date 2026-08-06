import "hash"
// Salamander CTI  //  https://salacti.com
// From open lures to cloaked gates: How a macOS ClickFix campaign learned to hide

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "MacSync, Atomic Stealer, AMOS"
  condition:
    false  // no file hashes in this brief
}
