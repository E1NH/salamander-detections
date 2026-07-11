import "hash"
// Salamander CTI  //  https://salacti.com
// KimJongRAT Continues to Evolve by Leveraging LOTS

rule Salamander_Kimsuky
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Kimsuky"
    malware = "Unknown malware"
  condition:
    hash.sha256(0, filesize) == "9758e76b601798a30d903bf05052a53df80451e5c156548ce9da828f608b6470" or
    hash.sha256(0, filesize) == "221a39856b37e3c682f62427f1e6b965b36a2405764689c914672770a01a1fa9" or
    hash.sha256(0, filesize) == "107b5aa3c4ef30b9b832e0a10b1efb1dcf433158bc6af8d890d66c0c9ed50d21" or
    hash.sha256(0, filesize) == "e4ccb2328c06710a7f0254cb6315e1b106396b0ff525f9cf3eada6e85d285c1c"
}
