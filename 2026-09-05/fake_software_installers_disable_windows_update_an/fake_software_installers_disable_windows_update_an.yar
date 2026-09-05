import "hash"
// Salamander CTI  //  https://salacti.com
// Fake Software Installers Disable Windows Update and Weaken Microsoft Defender

rule Salamander_Void_Arachne
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Void Arachne"
    malware = "gh0st RAT - S0032, Mydoor, Moudoor, ValleyRAT, Silver Fox trojan"
  condition:
    false  // no file hashes in this brief
}
