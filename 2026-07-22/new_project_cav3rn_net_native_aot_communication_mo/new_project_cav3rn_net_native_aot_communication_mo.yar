import "hash"
// Salamander CTI  //  https://salacti.com
// New Project CAV3RN .NET Native AOT communication module

rule Salamander_CHRYSENE
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "CHRYSENE"
    malware = "CAV3RN, RDAT - S0495, SC5k, OilCheck, OilBooster, Solar, WhisperGate - S0689, Veaty"
  condition:
    hash.sha256(0, filesize) == "75e51774b8f79e5f256eaae639635f911b3e744d4774fd6068dd980255621509" or
    hash.sha256(0, filesize) == "b3d0f6e4e3be395fd7cf9e8101c89963d77216578cbb117a6ac9bc3564485eff" or
    hash.sha256(0, filesize) == "f3f3006f8304788251b153d53b305322b8acab0c66ec816b8d9f101bcc851da3" or
    hash.md5(0, filesize) == "29b2b8c5d99f05bfcdd0d8d976eb5678" or
    hash.md5(0, filesize) == "c092b02fbc0fdf7ee9608dd016673806" or
    hash.md5(0, filesize) == "caf021dda726b8ba049c2aa395e505a1" or
    hash.sha1(0, filesize) == "66c8a4d782ec9e19d67f426376e0ebb5af868590" or
    hash.sha1(0, filesize) == "83ed3f17a83b083246f90011d33861cdb5734ab3" or
    hash.sha1(0, filesize) == "beb57441b81e56d1d7ba72acd841f2ffe171a325"
}
