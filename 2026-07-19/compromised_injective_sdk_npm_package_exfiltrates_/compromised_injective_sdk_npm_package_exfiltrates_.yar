import "hash"
// Salamander CTI  //  https://salacti.com
// Compromised Injective SDK npm Package Exfiltrates Wallet Keys and Mnemonics

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = ""
  condition:
    hash.sha256(0, filesize) == "103c4e6181151c1bcfedc41506cd1815458c38375d08a8fcd9981dbe0b965ce0" or
    hash.sha256(0, filesize) == "9a59eb454f3ca3fe91214136ee5edd417cc47a80e6f169b52099d6561944baf9"
}
