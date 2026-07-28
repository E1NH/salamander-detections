import "hash"
// Salamander CTI  //  https://salacti.com
// SilabRAT, What's Your Power?

rule Salamander_o1oo1
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "o1oo1"
    malware = "SilabRAT, Hijackloader, AsmCrypt"
  condition:
    hash.sha256(0, filesize) == "3a6adbe0081b2488e0f137496e92591e0c29148154b2d99faadab9cc435b879b" or
    hash.sha256(0, filesize) == "79f8da9f9fb4ac7c16d9c210f1f6ef418357a3e7bf602b1dd03a490596fa58c5" or
    hash.sha256(0, filesize) == "fb56e66920c84ef9e51db0ea23144f5755daef97cbff8613b05ab56d0dc9d623" or
    hash.sha256(0, filesize) == "fbce30a0c852972fdc24f1b6a7c270512a50ef1a7c6c88c88b92a2dcbdfdd023"
}
