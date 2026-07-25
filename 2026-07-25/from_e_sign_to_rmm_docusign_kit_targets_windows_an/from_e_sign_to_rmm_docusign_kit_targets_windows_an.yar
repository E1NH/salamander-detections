import "hash"
// Salamander CTI  //  https://salacti.com
// From E-Sign to RMM: DocuSign Kit Targets Windows and...

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "MeshAgent, ScreenConnect, SimpleHelp, UEMSAgent"
  condition:
    hash.sha256(0, filesize) == "2a206b085fedf8b20d1db883814c15e0202617da223dbb4e28b7109df98645df" or
    hash.sha256(0, filesize) == "4f1c8de304a855c2a4d1995b41069641dee84f1b51b6fb4a6e24eee59c6a30e4"
}
