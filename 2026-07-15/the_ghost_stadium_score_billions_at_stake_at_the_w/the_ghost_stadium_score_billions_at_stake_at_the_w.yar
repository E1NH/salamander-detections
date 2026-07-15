import "hash"
// Salamander CTI  //  https://salacti.com
// The GHOST STADIUM Score: Billions At Stake At The World’s Largest Football Tournament

rule Salamander_GHOST_STADIUM
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "GHOST STADIUM"
    malware = "Vidar, Lumma"
  condition:
    hash.sha1(0, filesize) == "3b8bb7631b39f455d31544b55ba97b49ab1888c1" or
    hash.sha1(0, filesize) == "84ecdca915f1af822ccc8a04479f5179104f353c" or
    hash.sha1(0, filesize) == "9bd164dd3f50d196c7dff4f6c1b0f1345ac96d9a"
}
