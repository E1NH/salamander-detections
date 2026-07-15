import "hash"
// Salamander CTI  //  https://salacti.com
// How WP-SHELLSTORM Exposed 1.4M WordPress Sites

rule Salamander_WP_SHELLSTORM
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "WP-SHELLSTORM"
    malware = "SNOWLIGHT, VShell, BestShell, Godzilla"
  condition:
    hash.sha256(0, filesize) == "84f7e396a48913851a10cc78c5cc22a25634564abd0694465236d2f365e2bdee"
}
