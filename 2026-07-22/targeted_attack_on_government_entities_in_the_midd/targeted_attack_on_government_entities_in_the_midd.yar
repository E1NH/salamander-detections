import "hash"
// Salamander CTI  //  https://salacti.com
// Targeted Attack on Government Entities in the Middle East | Part 1

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "TELESHIM, MIXEDKEY, BINDCLOAK"
  condition:
    hash.md5(0, filesize) == "087499849115eb28c4364581d2b28d09" or
    hash.md5(0, filesize) == "28b47bdf16d7af6f8ec21218eac9145a" or
    hash.md5(0, filesize) == "3f60d53a2b5737d77e058d9e33cbe9eb" or
    hash.md5(0, filesize) == "68926e6c958562deaae35de3d9f59de3" or
    hash.md5(0, filesize) == "78a4f8574830bf7fbaf63d7da09be2b8" or
    hash.md5(0, filesize) == "7a14a99d70d42d3f7bf72f843185fc07" or
    hash.md5(0, filesize) == "7cbc51ada1a4aec88660ec32c408114b" or
    hash.md5(0, filesize) == "97124a93766be732e8fef5a56a5346a2" or
    hash.md5(0, filesize) == "b776eb638fbb535708fb92b12fcc1731" or
    hash.md5(0, filesize) == "c99f29ac08454855b3d538960bb2f34f" or
    hash.sha1(0, filesize) == "1099bf51e53bd5fb32401edb4e0be841d8486b19" or
    hash.sha1(0, filesize) == "2377c47cfde148c2140faa7105628174f9c4d56d" or
    hash.sha1(0, filesize) == "577b1cc894636f4ac5ad670b0079b9b7ade137c3" or
    hash.sha1(0, filesize) == "86ee99f293a30720bcc898a4a8e391f93fb9be95" or
    hash.sha1(0, filesize) == "c1f16e31ae71372ee45fa6fd6927c7b887a4e3f2" or
    hash.sha1(0, filesize) == "ccb2002fe8f5cc1f511d52309625b52d1c507421" or
    hash.sha1(0, filesize) == "ee287d6a09295502ab2407aec336f9f0d8477d68" or
    hash.sha1(0, filesize) == "f46c01a5be2e08e36d4ec3302a8650a6ed25ec14" or
    hash.sha1(0, filesize) == "fee6806c96f87bf1e240a2eb6fd7e045101d58d3" or
    hash.sha256(0, filesize) == "0637069c7052118fd5c0f1113541bdd35e5f71cd9689f2516045da152c6fa8d9" or
    hash.sha256(0, filesize) == "32529043d15e9111ba284f1d8a9e4b3f58e071c6b69c8f271d4d02feacd44e66" or
    hash.sha256(0, filesize) == "3b0c658ebaa2bae80af97f390b9b2bb20a2f815eb584b2251255e84da4fa669d" or
    hash.sha256(0, filesize) == "3b3eaea783fd6dab90f0408274bf8a9c49adbdc70c0efd70658d65b0e1684a3f" or
    hash.sha256(0, filesize) == "5c2fe953da53da66fbcbb3be0fd6b63907c10714c337f287b2fc258857bbff6d" or
    hash.sha256(0, filesize) == "789fd11285642861190dc074c1e9a5957073f1a2afebd5160f9cc907f7f320bd" or
    hash.sha256(0, filesize) == "c84542ac30cbe9bb8bd648bad323c37801023bf9451c1c0990452466e084340f" or
    hash.sha256(0, filesize) == "cac1f37beaa814461f7709a073aeec468c74e5d70f7d693a9e367ece4a3a78be" or
    hash.sha256(0, filesize) == "db11ff3f37a8b2aa25c480871504b886a6364167ecb501eacf7345f6bbf9582b"
}
