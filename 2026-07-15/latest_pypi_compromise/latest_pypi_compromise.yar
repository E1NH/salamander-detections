import "hash"
// Salamander CTI  //  https://salacti.com
// Latest PyPi Compromise

rule Salamander_TeamPCP
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "TeamPCP"
    malware = "rope.pyz, transformers.pyz, managed.pyz"
  condition:
    hash.sha256(0, filesize) == "069ac1dc7f7649b76bc72a11ac700f373804bfd81dab7e561157b703999f44ce" or
    hash.sha256(0, filesize) == "7d80b3ef74ad7992b93c31966962612e4e2ceb93e7727cdbd1d2a9af47d44ba8" or
    hash.sha256(0, filesize) == "877ff2531a63393c4cb9c3c86908b62d9c4fc3db971bc231c48537faae6cb3ec" or
    hash.sha256(0, filesize) == "aeaf583e20347bf850e2fabdcd6f4982996ba023f8c2cd56bbd299cfd56516f5"
}
