import "hash"
// Salamander CTI  //  https://salacti.com
// Operation Endgame vs. SocGholish Fake Updates

rule Salamander_GOLD_PRELUDE
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "GOLD PRELUDE"
    malware = "FAKEUPDATES"
  condition:
    false  // no file hashes in this brief
}
