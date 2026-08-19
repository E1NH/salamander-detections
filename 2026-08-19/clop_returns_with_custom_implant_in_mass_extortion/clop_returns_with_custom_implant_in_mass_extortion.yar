import "hash"
// Salamander CTI  //  https://salacti.com
// Clop Returns with Custom Implant in Mass-Extortion Campaign

rule Salamander_Clop
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Clop"
    malware = "DEWMODE, LEMURLOOT"
  condition:
    hash.sha256(0, filesize) == "321e1fb01eb3462b48ff6ccdef132acc1182e3f7456548439f0d4ead12fd98bf" or
    hash.md5(0, filesize) == "71a7b6b8fa5e21765aeb60d897009aa3" or
    hash.sha1(0, filesize) == "2989c71984b9a464c741e5d93171ca9c153baf5d"
}
