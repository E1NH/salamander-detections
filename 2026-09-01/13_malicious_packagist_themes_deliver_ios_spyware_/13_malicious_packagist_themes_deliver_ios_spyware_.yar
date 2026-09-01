import "hash"
// Salamander CTI  //  https://salacti.com
// 13 Malicious Packagist Themes Deliver iOS Spyware That Steals Crypto Wallet Seeds

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = ""
  condition:
    hash.sha256(0, filesize) == "60b6771958cb7e553994ba6752f108575ba70e02d24affb51d8936a17eb0bf5e" or
    hash.sha256(0, filesize) == "d9530e8cd79ac7b3d02b04e05426653afca7075fcf7424eec4d59c6e95745933" or
    hash.sha256(0, filesize) == "92c7d246d2c163c076f783dcc19f87f5b9b9ac301b106b87a7aaea9346ce0052" or
    hash.sha256(0, filesize) == "f2fdfddbc436acc24a654092f5205b2c5bd3208b126b2c2754ac63e7aea22298" or
    hash.sha256(0, filesize) == "9d6b58886189c0e23f706c32d3d8dda97b0b6d927ece6de07270813f070295b5" or
    hash.sha256(0, filesize) == "de539a63cbe27bbd4a7db30fc796cd6dc5309c02ef5e60a3c5cf0835e5601283" or
    hash.md5(0, filesize) == "22c75b2ee026dbbf7001cfdc2bb47855" or
    hash.md5(0, filesize) == "b216e777ad85e77b033d68ad429d869a" or
    hash.sha1(0, filesize) == "ac97f82098288232e8c6e0c8ce5f196b92b3bf59"
}
