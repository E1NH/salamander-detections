import "hash"
// Salamander CTI  //  https://salacti.com
// PCPJack Hijacked 230 AWS, GCP, and Azure Servers to Run a Hidden SMTP Relay Network

rule Salamander_PCPJack
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "PCPJack"
    malware = "Sliver, Chisel"
  condition:
    false  // no file hashes in this brief
}
