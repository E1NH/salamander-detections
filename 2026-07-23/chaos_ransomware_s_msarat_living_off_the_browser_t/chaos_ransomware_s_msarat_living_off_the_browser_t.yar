import "hash"
// Salamander CTI  //  https://salacti.com
// Chaos ransomware's msaRAT: Living off the browser to build a covert C2 channel

rule Salamander_Chaos
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Chaos"
    malware = "msaRAT"
  condition:
    false  // no file hashes in this brief
}
