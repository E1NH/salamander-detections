import "hash"
// Salamander CTI  //  https://salacti.com
// A Djinn in the Machine: TaskWeaver's Node.js Intrusion Chain

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "TaskWeaver, Djinn Stealer"
  condition:
    hash.sha256(0, filesize) == "00cc86d1144020c24c8fbb3a8dc6b908926497ebd23be3bf854360f93d1c8f4c" or
    hash.sha256(0, filesize) == "f4a72600a3735c2a4d843875ea61bbb6f935a1af51a81f2fbc992ce11ba94afc"
}
