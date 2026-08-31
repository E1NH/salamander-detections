import "hash"
// Salamander CTI  //  https://salacti.com
// Attacks on AI Infrastructure: 90-Day Honeypot Telemetry

rule Salamander_Qilin
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Qilin"
    malware = "XMRig"
  condition:
    false  // no file hashes in this brief
}
