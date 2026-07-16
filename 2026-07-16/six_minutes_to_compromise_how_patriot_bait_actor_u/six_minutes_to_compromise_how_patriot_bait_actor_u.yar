import "hash"
// Salamander CTI  //  https://salacti.com
// Six Minutes to Compromise: How 'Patriot Bait' Actor Used AI to Build and Deploy a C&C Botnet

rule Salamander_bandcampro
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "bandcampro"
    malware = ""
  condition:
    false  // no file hashes in this brief
}
