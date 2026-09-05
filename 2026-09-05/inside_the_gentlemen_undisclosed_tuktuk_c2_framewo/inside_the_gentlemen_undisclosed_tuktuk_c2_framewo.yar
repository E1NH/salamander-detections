import "hash"
// Salamander CTI  //  https://salacti.com
// Inside The Gentlemen: Undisclosed TukTuk C2 Framework and EDR Neutralization Research

rule Salamander_The_Gentlemen
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "The Gentlemen"
    malware = "TukTuk, GentleKiller, EDRKiller, WarsawKiller, UnknownKiller"
  condition:
    hash.md5(0, filesize) == "4e5136230ec590ce6ef038aac6e72cb2" or
    hash.sha1(0, filesize) == "ba914fe77b177b45799403b16dd14765c510a074" or
    hash.sha256(0, filesize) == "97bd65e98cdc4e93d49edd4ea905d43a61244df0fd3323e6649330de3b1be091" or
    hash.sha1(0, filesize) == "138c41085f5f07adbdeff4df97a6a80252571e28" or
    hash.sha256(0, filesize) == "e2b31ac7ee077b26332444a83a68ab75be641113e7d86979d844a0f3478f01f9" or
    hash.sha256(0, filesize) == "e74088419de2e5b47b1889f2ba1369cb4b436405ce03cf07da452791681f9923" or
    hash.sha256(0, filesize) == "096ec37870eb401793592c9b53b5b52fc7a70b113bc2d9cd3f53231142d6c584" or
    hash.md5(0, filesize) == "07f74b7d16181dec1401c85f8ebe45f3" or
    hash.md5(0, filesize) == "4294c1e975d80fdedfa29919035e5efb" or
    hash.sha1(0, filesize) == "7c17c2bdd8d8efffb26be64245b08a22febb3cf9"
}
