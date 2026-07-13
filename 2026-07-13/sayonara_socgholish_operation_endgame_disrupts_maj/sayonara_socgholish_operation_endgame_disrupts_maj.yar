import "hash"
// Salamander CTI  //  https://salacti.com
// Sayonara, SocGholish: Operation Endgame Disrupts Major Cybercrime Operation

rule Salamander_GOLD_PRELUDE
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "GOLD PRELUDE"
    malware = "SocGholish, GhoLoader, FrigidStealer, WastedLocker - S0612, LockBit, RansomHub"
  condition:
    false  // no file hashes in this brief
}
