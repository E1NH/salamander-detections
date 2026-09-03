import "hash"
// Salamander CTI  //  https://salacti.com
// Counterfeit installers to system compromise: Tracking a deceptive software download campaign

rule Salamander_Void_Arachne
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Void Arachne"
    malware = "ValleyRAT"
  condition:
    hash.md5(0, filesize) == "5251b98614acffe5c856f4039ca03da3" or
    hash.sha1(0, filesize) == "c80ed6716e89d4862f28ebbc130ec5aa362db963" or
    hash.sha256(0, filesize) == "6d6ba2bc9ad414837826f7278bc3e0116f1aeda02d0c2284ed65819f5d9180a8" or
    hash.md5(0, filesize) == "9ec587911e501b73b7cf09f05d0ae17d" or
    hash.sha1(0, filesize) == "5b62403cc9a668c6e5c70ace177fd54fcc4c5936" or
    hash.sha256(0, filesize) == "676a2a7b94ca2f8ec76352ee656e4d075bb342bd7ad6efbc7c19c060001eace7" or
    hash.sha256(0, filesize) == "c4100ad39d8db98f063feb6c3b6c8e9a9f9d9bf25a1e0233f43b058ff8a7dbdf" or
    hash.sha256(0, filesize) == "1bd3662d784840e410d2d3c0a1040277f7f549089447359f01e05c2559cb1f17" or
    hash.sha256(0, filesize) == "c6100166e2d3b40388980f7674712ef39e937ac04925ca5d370415399ed73faf" or
    hash.sha256(0, filesize) == "f33d160d757e4b39019fdef21cf90cafb501b800ca0d4039366bc30856e3d81b" or
    hash.sha256(0, filesize) == "e4fe2dee8f0bb132fa15fc686d1f93df39530a2d3a8d3a1f3a605a057c04e7b3"
}
