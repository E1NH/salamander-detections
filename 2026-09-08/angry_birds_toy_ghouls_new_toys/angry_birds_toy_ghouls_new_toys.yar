import "hash"
// Salamander CTI  //  https://salacti.com
// Angry Birds: Toy Ghouls’ new toys

rule Salamander_Toy_Ghouls
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Toy Ghouls"
    malware = "mqtt-bird-agent, matrix-bird-agent, GenieLocker, Babuk - S0638, Babyk, Vasa Locker, LockBit"
  condition:
    hash.md5(0, filesize) == "bfadbeee63a4f0bf19ec9deb8fa58f58" or
    hash.md5(0, filesize) == "7916c33688385525078bee504c90f359"
}
