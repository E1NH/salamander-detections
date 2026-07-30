import "hash"
// Salamander CTI  //  https://salacti.com
// Latest goon squad to use fake helpdesk calls to steal creds

rule Salamander_Pink
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Pink"
    malware = ""
  condition:
    false  // no file hashes in this brief
}
