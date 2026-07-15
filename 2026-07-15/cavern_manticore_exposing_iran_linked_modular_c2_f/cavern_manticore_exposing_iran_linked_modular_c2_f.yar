import "hash"
// Salamander CTI  //  https://salacti.com
// Cavern Manticore: Exposing Iran-Linked Modular C2 Framework

rule Salamander_Cavern_Manticore
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Cavern Manticore"
    malware = ""
  condition:
    hash.md5(0, filesize) == "a9336884e006503bc821f3f0d36f141f" or
    hash.md5(0, filesize) == "d0bba7c040ecffd8cc31a62330a144eb" or
    hash.sha1(0, filesize) == "0f57a2bb4c0696170b73e2d35f17c5a6f2f910d7" or
    hash.sha1(0, filesize) == "843d2017c4ded1dbb694dd4bf20bcd9e92af92f6" or
    hash.sha256(0, filesize) == "0a3663648a46771a5a5423ad01e91a4e7ba825595e99fa934cb35cbb4848adc8" or
    hash.sha256(0, filesize) == "2cb1ad3b22db8e3666ea138fee88034a87a87cf43db3d3265a675ebf221379b0" or
    hash.sha256(0, filesize) == "30cb4679c4b8599eeb3d63a551716475c6332bdc4d4b4e3de0964aadb3092a10" or
    hash.sha256(0, filesize) == "37e123bd7998af4eae32718ce254776f36365a80ba56952593dab46f536d4066" or
    hash.sha256(0, filesize) == "5394d3b220de4695f731647e3a70545f951a8912ceb0c6585efab8d6842e8b42" or
    hash.sha256(0, filesize) == "541b1f417b9e42078c3355693a8a492b6a76048850f6549a429e0be99e6819cb" or
    hash.sha256(0, filesize) == "5dc08bda6919a57a85e5f38b857985fa71529ca39c8299868d5a49a987e19b18" or
    hash.sha256(0, filesize) == "7d586fb7f94182a8e2a0e53c7e4deb898066da029da5cd9972a94a59ca6d255a" or
    hash.sha256(0, filesize) == "8e9425c0b46eeb516610ae913d13f2b3f44a023043cb099277031d4ec38a6134" or
    hash.sha256(0, filesize) == "92cae0ad7f98f51a14bcc0ee05e372ebdc29ea96ea7bd161bd3f55198767603b" or
    hash.sha256(0, filesize) == "a4aa217def4c38f4ecacdf47b1cd687f60cc74c18ab75195be3c4357a790bf41" or
    hash.sha256(0, filesize) == "b630c96d3763182533d4fb9b614134382bd644cb02c6c1c3ade848b6ecc31e86" or
    hash.sha256(0, filesize) == "cbc9485db715e1b8cc384fe94b4cceadca4006cda8a5e28adc8848529cfafc93" or
    hash.sha256(0, filesize) == "ccf218189c3aadb1c761da14bfda3bae686769031e1e1b10007648bd72e34748"
}
