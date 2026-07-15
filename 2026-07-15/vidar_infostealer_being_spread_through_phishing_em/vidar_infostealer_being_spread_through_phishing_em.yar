import "hash"
// Salamander CTI  //  https://salacti.com
// Vidar Infostealer Being Spread through Phishing Emails

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Vidar"
  condition:
    hash.md5(0, filesize) == "0b8af4afd26175ba818c0fdb4622bf14" or
    hash.md5(0, filesize) == "1bbf1e83eea55e70d59f0d633789011e" or
    hash.md5(0, filesize) == "2fba9ec34fdf4b1584dd9c69b9ec9393" or
    hash.md5(0, filesize) == "4e885b1a0c1d0636e940b4af20fdc8db" or
    hash.md5(0, filesize) == "536dd0b0f6dff75dc01869df9809df61" or
    hash.md5(0, filesize) == "7dd16d1018865e5e817c418f87e6be00" or
    hash.sha1(0, filesize) == "6eaf8f8cfc9161c6a287d0a1ce8ab436d14cfcad" or
    hash.sha1(0, filesize) == "87cb13512daff0f4e1783a59af449336b6e010e4" or
    hash.sha1(0, filesize) == "bea391c7ef1665bc33712deee1109812fc606cc6" or
    hash.sha256(0, filesize) == "340820f7f4c97e3a2477bc99acf746e13b2c92719ebf5c9947a62eef7ec0dddb" or
    hash.sha256(0, filesize) == "cff8b04f2c8ed63d37fd393ad23652a8b818e80b03851d7c1bd5842963a03348" or
    hash.sha256(0, filesize) == "e8e7faa5e76dc773ffb1a7a6be36a47cc84e3ed45b928859b570332757cdb6cb"
}
