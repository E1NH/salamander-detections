import "hash"
// Salamander CTI  //  https://salacti.com
// Token Jacking: Cybercriminals Could Be Stealing Your AI Resources

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Shai-Hulud, Miasma"
  condition:
    false  // no file hashes in this brief
}
