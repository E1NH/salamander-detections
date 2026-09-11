import "hash"
// Salamander CTI  //  https://salacti.com
// Mind the (Patch) Gap: Multiple Chinese Threat Actors Chain 0-day Exploits in Chrome & Windows

rule Salamander_UTA0560__JungleBamboo
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "UTA0560, JungleBamboo"
    malware = "GRIMWEDGE, SUPERSTOMP, LONGTALE"
  condition:
    hash.sha256(0, filesize) == "337b48c1cd6dd6e7b8073327082a60e149517fa084ba17b180e041fffa3b130d" or
    hash.sha256(0, filesize) == "3b71d721c39fad92a44ddd764bbb34afeae44a5db886d0a4827a399a5fbd367f" or
    hash.sha256(0, filesize) == "51462a23ac25e1bd0e49b7cae7f3a71f8d2201e22d45175b587e4740b49863cc" or
    hash.sha256(0, filesize) == "56eda0ac82e06ee609b034306025e67df161c5877399c305c8eaea136e80c951" or
    hash.sha256(0, filesize) == "5995f42a828606705a7339d58a665c229936e81c4e539cdfa115eb46a2eb53d6" or
    hash.sha256(0, filesize) == "59dc108e22cb856c228bbf8a1ab955fb66f0844a07fe10fa0d9fc3823d2cbbcb" or
    hash.sha256(0, filesize) == "5eb5645511b00e4f4d73125654eeb3a3930fcf09c65685dc7f03f725331492e3" or
    hash.sha256(0, filesize) == "69c1603f3f9015beb0097d0a3bb0f17400c314e2eae65a7eceacd3b93ea570dc" or
    hash.sha256(0, filesize) == "7a52ff23949edee8faa61ce0def6dbca8b7e5943c54d23376cc190762ea3985c" or
    hash.sha256(0, filesize) == "b7b0cd6539464ab39c6526e499f86d611faa21c5af945535ebaf187cec543af1" or
    hash.sha256(0, filesize) == "cd0c21f9b32b7feeda1787fccab622dec60ecdf84c0538c08bde3946856b0fa0" or
    hash.sha256(0, filesize) == "d17053557bb90298f7b115432b4820a248fdbe678bca31721529b1f51a82343b" or
    hash.sha256(0, filesize) == "e2a59432ce2b0d83ded936374a11fca3d3defaf4aab90eb37fca58683eae32c0"
}
