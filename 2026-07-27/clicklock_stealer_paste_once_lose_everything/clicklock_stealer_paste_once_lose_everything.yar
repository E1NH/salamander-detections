import "hash"
// Salamander CTI  //  https://salacti.com
// ClickLock Stealer: Paste Once, Lose Everything

rule Salamander_ClickLock_Dev
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "ClickLock Dev"
    malware = "AMOS"
  condition:
    hash.sha1(0, filesize) == "0a1fb016bd10bac5455175c79aa4511e5ff1a330" or
    hash.sha1(0, filesize) == "2fc970e25570532f9cbe33b7ebfe1f0383a7341a" or
    hash.sha1(0, filesize) == "8dda05168ea8610a2449419a47517bc32823d6ec" or
    hash.sha1(0, filesize) == "b67aa4f598c0ea625a7409ea7884e10a7bc9c3ff" or
    hash.sha1(0, filesize) == "d9617710d4ed8e9b87f6fee0b7014c4101effba0"
}
