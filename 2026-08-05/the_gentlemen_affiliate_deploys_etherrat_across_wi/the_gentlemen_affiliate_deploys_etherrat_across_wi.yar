import "hash"
// Salamander CTI  //  https://salacti.com
// The Gentlemen Affiliate Deploys EtherRAT Across Windows Networks Using Ethereum Smart Contract C2

rule Salamander_The_Gentlemen
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "The Gentlemen"
    malware = "EtherRAT, Sliver"
  condition:
    hash.md5(0, filesize) == "4b690f3ce585df982a042917b82642c8" or
    hash.md5(0, filesize) == "bd1eaea733425cd21a51a652c429951d" or
    hash.sha1(0, filesize) == "60285f6776cc3ff20872feeee7f2fd0b3b04410d" or
    hash.sha1(0, filesize) == "9dd99bc68e60132f32fc33617deb9583c8cebb51" or
    hash.sha256(0, filesize) == "73955566338adffb423c3b7608792963080da780e8b7b2c2cd6b6b0cef6f217f" or
    hash.sha256(0, filesize) == "7567994310a9576b1f98dc672ecfa038f1d65084315f59e3883f9b6f24000073" or
    hash.sha256(0, filesize) == "756c2096f54c5497110c9d854625c3ed592873e566d532077cd7adb4d10d4add" or
    hash.sha256(0, filesize) == "86881b8e9d197ac2f734792de48d5dfaebe7cafb6e35d49c5dd7fe6eb697230e" or
    hash.sha256(0, filesize) == "bd61c2880920bbfb86c12df439dd1ca0258a10e532433698fd029aef2a5b33f2" or
    hash.sha256(0, filesize) == "c7a80576fbd25057435652788591d13998da272edf627fc29d296684cefc50e5" or
    hash.sha256(0, filesize) == "ee6807a8abfabced22ee026e178a28da64d13cc3408e224394ff6e5782fb9e1d" or
    hash.sha256(0, filesize) == "f4c87a1df04274b7497cbf9a4619b946c915cf5210b6e2eaa2fee1629f4ff196" or
    hash.sha256(0, filesize) == "f609621698eaad8c4683750fe8bd0e242349be3eea408da593151ff877ed8ab6" or
    hash.sha256(0, filesize) == "f659681525debda69fe0865b2b27a42f684b1fda66aa7398e80b84cc765c73c7" or
    hash.sha256(0, filesize) == "fb94688ed37dfcb985a8a4d720230e5150956e1788d579b0a54b53a153fd2f2e"
}
