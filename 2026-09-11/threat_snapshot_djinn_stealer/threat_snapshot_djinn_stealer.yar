import "hash"
// Salamander CTI  //  https://salacti.com
// Threat Snapshot: Djinn Stealer

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Djinn Stealer, TaskWeaver"
  condition:
    hash.sha256(0, filesize) == "f4a72600a3735c2a4d843875ea61bbb6f935a1af51a81f2fbc992ce11ba94afc"
}
