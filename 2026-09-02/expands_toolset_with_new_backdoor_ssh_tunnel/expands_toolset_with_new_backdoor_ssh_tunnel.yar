import "hash"
// Salamander CTI  //  https://salacti.com
// Expands Toolset With New Backdoor, SSH Tunnel

rule Salamander_Tortoiseshell
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Tortoiseshell"
    malware = "TWOSTROKE"
  condition:
    false  // no file hashes in this brief
}
