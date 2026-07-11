import "hash"
// Salamander CTI  //  https://salacti.com
// Iran-Nexus Disseminates MarkiRAT Surveillance Tool

rule Salamander_TAG_182
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "TAG-182"
    malware = "MarkiRAT - S0652, FurBall, DCHSpy, BouldSpy"
  condition:
    hash.sha256(0, filesize) == "400eb6a94810323a1fc5f8ab31c682fe765aaec2cc61b37c31d719c7e45c9a6c" or
    hash.sha256(0, filesize) == "8a7f5c8533df9e51b2da7cc2aeb52d8787418e4915577cc9288be1e46d1945c6" or
    hash.md5(0, filesize) == "07d1db998e4dacc6777f1c854b3ab605" or
    hash.md5(0, filesize) == "b56a18df4daf038785891f33c3e89489" or
    hash.md5(0, filesize) == "d151ad777bcf1b3205273ab732c0fad6" or
    hash.md5(0, filesize) == "d66de5d6dbcb6f460ae6240de8b7aab0" or
    hash.md5(0, filesize) == "db6bc0e947acba379e540349f74fc6ee" or
    hash.sha1(0, filesize) == "1c841649189a46806084b189f50300e36c423163" or
    hash.sha1(0, filesize) == "3fe1fcc2a21e4bab144da57ea6d0f13ddb9819e0" or
    hash.sha1(0, filesize) == "40513398ae248c87f46b13b7f9f303e05d018472" or
    hash.sha1(0, filesize) == "42c83fbfb4299202c91b3391ace6e7732f77a602" or
    hash.sha1(0, filesize) == "8179539efdb90eab355667ac7683358741c8a8ec" or
    hash.sha256(0, filesize) == "13440348516ccee839675f6ac908dd1724ce1d28f92af92fdc7938740d2b7ec5" or
    hash.sha256(0, filesize) == "51a6686b8c5ec7c610637398f3de43589f4e9fcbe8bcc0245343c5454d3b91de" or
    hash.sha256(0, filesize) == "66dcd98c6b310f4429890821e609d48cc6395a6be15ffe5a121ec68b7a8f7402" or
    hash.sha256(0, filesize) == "a4f1b79e96a7d016de1991a64506792018de99eac5df00f7cabe26ef41b2bd81" or
    hash.sha256(0, filesize) == "bb0c7ae4f12e5141480ee26f473636b07e836bb994ff3b2cfec93d4480da171b" or
    hash.sha256(0, filesize) == "cc59bf019af195dcec4394ffd7a8e23c080f4e02b12dcb7c04fb1da6671922a1" or
    hash.sha256(0, filesize) == "ea755862ee81dd0d991b4afca42d8b82bb22a8f1d370bf3d28dbf2e44ab241dd" or
    hash.sha256(0, filesize) == "fa246327bed8fc5864827a8147b8b7aedb6246068259b8c97e82adb957315347"
}
