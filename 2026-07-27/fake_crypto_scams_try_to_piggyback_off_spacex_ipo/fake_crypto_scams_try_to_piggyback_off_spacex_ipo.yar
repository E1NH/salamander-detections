import "hash"
// Salamander CTI  //  https://salacti.com
// Fake crypto scams try to piggyback off SpaceX IPO

rule Salamander_TA2730
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "TA2730"
    malware = ""
  condition:
    false  // no file hashes in this brief
}
