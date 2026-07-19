import "hash"
// Salamander CTI  //  https://salacti.com
// Millenium: A RAT Rewritten, A Threat Multiplied

rule Salamander_Y2K_Operators
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Y2K Operators"
    malware = "Amadey, Lumma Stealer, MilleniumRAT, MillenuimRAT, Shim RAT, Unknown Stealer"
  condition:
    hash.md5(0, filesize) == "7b6473f036225bc35da89e5049ae55ba" or
    hash.sha1(0, filesize) == "ddbc1037925f7d6c07a9ddbe38286a2fcedc4890" or
    hash.sha256(0, filesize) == "ccca11a6d5835999c40a0a5264084b3740633600c157754fad2ef59559e31736" or
    hash.md5(0, filesize) == "a1c160243efd54a9bf00655966971aae" or
    hash.sha1(0, filesize) == "cc2c9d90ffba060c9521d40776ffaa907ecec2bb" or
    hash.sha256(0, filesize) == "512adab2c69feaf026adfb12cbd7d2eb4fee746120491e44f476eebddcbb19f2" or
    hash.sha256(0, filesize) == "66bf111030a2e22db575c0b7b7b677208745eef8b44265bb4259f41f126f1bf8" or
    hash.sha256(0, filesize) == "7d8b6a64f7b65b281e7b5568929c6f96c62bbae9628162aabe7d8140a86d3de8" or
    hash.md5(0, filesize) == "754ba4fb2e083944f84ba50b90ddda87" or
    hash.sha1(0, filesize) == "f27b08a8347e1ba84a61fbfe58edcb8f84d06642" or
    hash.sha256(0, filesize) == "5a23ca644cb1f310be1abd5f6c6a3b3e15681ced99b0947a7f3465a79aae5089" or
    hash.sha256(0, filesize) == "8f8a71352d2f18162f2f74090dc6f0cae6b37029e3244e6522825ade75163055" or
    hash.sha256(0, filesize) == "a8acc24bb3e6a1a3b66a31ceaefda07d4a0e17415468683458b499f2ba240450" or
    hash.sha256(0, filesize) == "d55ce447e249ef9045750865fa196c8ca8434c8c484f861b7bdecbceeab7c16e" or
    hash.sha256(0, filesize) == "ad0f892b7b99b68491ade4949ef6b575e64d9df5f84a53019b5c1e4eeb4c46a9" or
    hash.sha256(0, filesize) == "1d699a46339626db299548e32ed3a77eec267840c3de39b49caf38b88aeb150d" or
    hash.md5(0, filesize) == "066576554f9eff84eaa415a4bd012b2e" or
    hash.md5(0, filesize) == "07a364ba1b34d0b04bb68872006d9615" or
    hash.md5(0, filesize) == "195d1c56f35d7a8d38e2ab0cdc1fa8cd" or
    hash.md5(0, filesize) == "1ef2f666b543293aaec55d10fbc4bc46" or
    hash.md5(0, filesize) == "35af4c61ce04f0c0796baf5831e2ef24" or
    hash.md5(0, filesize) == "35dfec976f6fd85f76d011d0075b5926" or
    hash.md5(0, filesize) == "3c1032e271dd885e912a79c67f2855e7" or
    hash.md5(0, filesize) == "4f32d85224309688c600c21865294717" or
    hash.md5(0, filesize) == "52deca7016315faf844f0ba0d754027e" or
    hash.md5(0, filesize) == "53e78d1fef04a39353a7dbc19f8ac86d" or
    hash.md5(0, filesize) == "6dc5e2f50900ba1e7a4ee87f950fa409" or
    hash.md5(0, filesize) == "87e06d8cec9cf7c2808d17c836089053" or
    hash.md5(0, filesize) == "89aa2ce1978f3386f9ee433515e457b1" or
    hash.md5(0, filesize) == "a0503abcebf054a006fd4436a73c2dd7" or
    hash.md5(0, filesize) == "b82f0480f6403174120f99cdceab83e0" or
    hash.md5(0, filesize) == "c704ad8e3fe023e03c4ca07973bd6e78" or
    hash.md5(0, filesize) == "d456b165eda38d5d591db9b1bf913463" or
    hash.md5(0, filesize) == "f4281c571efa6e0453cf9878a21bb587" or
    hash.sha1(0, filesize) == "28fbbe5cadb2f4a236acd1977c58bcb7877226e8" or
    hash.sha1(0, filesize) == "34366f3c17d26856028b472dd8d433913eb2c935" or
    hash.sha1(0, filesize) == "5a416890fdb135b3c94a70055273d69d48dc6e7f" or
    hash.sha1(0, filesize) == "73a5a94c1222fd333bf3be1322dd09e896159f1a" or
    hash.sha1(0, filesize) == "76330efb09c3355f7547e78cde1c1a0d1f332cb6" or
    hash.sha1(0, filesize) == "7fad85e9e2c6641498e7c7df4357498b734e3a26" or
    hash.sha1(0, filesize) == "9d858418c57b513908bba61cb081fbf5914d233a" or
    hash.sha1(0, filesize) == "a684f8c4e1759e4b3cd18d7e3a248d79e4616875" or
    hash.sha1(0, filesize) == "b1235ce53ef2a09253f7a212369ae2fef1edde4c" or
    hash.sha1(0, filesize) == "b8370381539c085772d3b7503d39573fc7c24ebc" or
    hash.sha1(0, filesize) == "d826b2a24fa3c9b94efd9a33eac7ab2e71abd2c0" or
    hash.sha1(0, filesize) == "dcff6378b57b6a8ac664254102c656affc62ac49" or
    hash.sha1(0, filesize) == "e3af48f83557fce9f3dbdc557fa126720ea87983" or
    hash.sha1(0, filesize) == "e3c0c8761e15442408fc354262c1e206beb4e11f" or
    hash.sha1(0, filesize) == "eb8d7b899ae946face81d88edbacb3e4d2b4ded4" or
    hash.sha1(0, filesize) == "ee9f060b7446336fc9252d2c639ab6e62f324bfe"
}
