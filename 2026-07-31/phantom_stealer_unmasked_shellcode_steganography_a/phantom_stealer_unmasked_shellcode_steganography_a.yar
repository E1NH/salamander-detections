import "hash"
// Salamander CTI  //  https://salacti.com
// Phantom Stealer Unmasked: Shellcode, Steganography, and Credential Theft

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "PhantomStealer"
  condition:
    hash.md5(0, filesize) == "031ae066a8188e5fea8d3d7981a2166c" or
    hash.sha1(0, filesize) == "9d79790ceacab47146df25e3704abe580441b2ab" or
    hash.sha256(0, filesize) == "2d5003d9318ae85eb22de99d19705a3cd7bf8e5c3349df979dfb3bdfa080908e" or
    hash.sha256(0, filesize) == "b588caa5365451a6c60fd73fec5b73f13ac41bcc2a3a3bed7244df5917a62f32" or
    hash.sha256(0, filesize) == "be119a21bedc3a79bf4dea8bcf5adf18304997a01ea23e276b9c31be37b789ab" or
    hash.sha256(0, filesize) == "382233c398cbc35dcee845ee17046815f37588a382a8106bfb9b0252ea803961" or
    hash.sha256(0, filesize) == "790945e17a51691483455a11af2efcbe15f2b473b65b151f50287623d1468516" or
    hash.sha256(0, filesize) == "528a46842744366b57edfc6fe2810ca7df43900db75126cd1c78f32957143364" or
    hash.sha256(0, filesize) == "01f1e5369aa0332abb681df7c37818e197ec0a5b5d7b81836b3369a2b1780950" or
    hash.sha256(0, filesize) == "10cfcad907275497dab92af0d687674cec3a0333f80dd16d8d22254794bb2d60" or
    hash.sha256(0, filesize) == "f82a4d30132b5a57cbfd81c7ab0a53d0cf0dda402c2731732a0097aceb4b0b76" or
    hash.sha256(0, filesize) == "e3ceeb24bdca8842d426e87fa61cf185d68fd7783e1a2b97d4106832ca266724" or
    hash.md5(0, filesize) == "390325e2d23bce8d8f63b047f64c3cd5" or
    hash.md5(0, filesize) == "b6ab80e1262197ebc4be80641aa03afa" or
    hash.md5(0, filesize) == "c4fda5f3a27a961149eeeb8bb3666c93" or
    hash.md5(0, filesize) == "c8821ed5d6b2cb2469abfc3cf83210ba" or
    hash.md5(0, filesize) == "d18e6f0dd8a71742fd07125ae6fafcf2" or
    hash.md5(0, filesize) == "e1faeb1fac915fb6c11273d220e7b11f" or
    hash.md5(0, filesize) == "ee4e04111fbe39c13a084ffbece4d284" or
    hash.md5(0, filesize) == "faa9be79966054ec706de4ed983d9644" or
    hash.sha1(0, filesize) == "362a370f117bc54e40a69c1808cfd020ac2fb00d" or
    hash.sha1(0, filesize) == "3fe37d385eae5054cd919c570ebda8086d54686a" or
    hash.sha1(0, filesize) == "5843beb38fe07ba4caee971961dc761218244757" or
    hash.sha1(0, filesize) == "59a5b8188a289d80d29e4943ef471ab19185aa82" or
    hash.sha1(0, filesize) == "5ad3f0d0d8e0276dad0b1cc64aee36774db5543f" or
    hash.sha1(0, filesize) == "64c4707c9df2585ae93425b343df3df60ed585c2" or
    hash.sha1(0, filesize) == "752d07cadfe3f9f13a89f0be50d6bb18a0e16c61" or
    hash.sha1(0, filesize) == "cb6d9d1c6aba200d0a2a45be3d474604b2b11861"
}
