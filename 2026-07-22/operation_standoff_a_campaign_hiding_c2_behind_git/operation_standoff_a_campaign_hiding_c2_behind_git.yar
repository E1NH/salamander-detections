import "hash"
// Salamander CTI  //  https://salacti.com
// Operation STANDOFF: A Campaign Hiding C2 Behind GitHub Redirects

rule Salamander_Operation_STANDOFF
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Operation STANDOFF"
    malware = "Amadey, RedLine Stealer"
  condition:
    hash.md5(0, filesize) == "e77221d7a4b47b9107ba1b61a551ca89" or
    hash.sha1(0, filesize) == "95c5ae3fec0d900e4634e11b3ad81971e78e2b31" or
    hash.sha256(0, filesize) == "22ebb950592ccc987fd1dab9ddcd34c4fc519975dc1b82e4a793dc038d2d8e41"
}
