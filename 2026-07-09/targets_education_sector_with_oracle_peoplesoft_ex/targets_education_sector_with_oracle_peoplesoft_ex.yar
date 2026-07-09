import "hash"
// Salamander CTI  //  https://salacti.com
// Targets Education Sector with Oracle PeopleSoft Exploit

rule Salamander_UNC6240
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "UNC6240"
    malware = "MeshCentral"
  condition:
    hash.sha256(0, filesize) == "c7e9332731b06644fc73e0046a2a89eaa59b09f54250e9bd622467187351711f" or
    hash.md5(0, filesize) == "ebcf977806f68af3147e0b78b55f6aed" or
    hash.sha1(0, filesize) == "cc19e502e4201cc974c753b96429027925224f53" or
    hash.sha256(0, filesize) == "2ab684d93c1553fad87041b4dea97188a97e78589deee2a7bacff905564f3a35" or
    hash.sha256(0, filesize) == "68257a6f9ff196179ec03624e849927f26599eb180a7c82e14ef5bc4e93bc309" or
    hash.sha256(0, filesize) == "d83fdb9e53c5ff03c4cb0451ea1bebd79b53f29eadc1e2fa394c7af13a86ce2f" or
    hash.sha256(0, filesize) == "f02a924c9ff92a8780ce812511341182c6b509d45bc59f3f7b522e37225d24fc"
}
