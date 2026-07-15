import "hash"
// Salamander CTI  //  https://salacti.com
// Phishing Campaign Deploys JavaScript-Driven PureLogs Variant to Steal Sensitive Data

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "PureHVNC"
  condition:
    hash.sha256(0, filesize) == "3d510977d60a44322f88100b515f06cb5ed83babc64247068d1a489595faa6c5" or
    hash.sha256(0, filesize) == "07cd03e2082bcb0b890cc59ce4c770d1a095ac6f1ae9cf999f5542555c56f841" or
    hash.md5(0, filesize) == "6af99d08e9295db93ad869af5ec1422e" or
    hash.md5(0, filesize) == "e2470b4bb66131ac43a0e7d30bb30ede" or
    hash.sha1(0, filesize) == "4f2c2a808194d27992ef227c4b9134de01d051fc" or
    hash.sha1(0, filesize) == "cda7136e67b34757ef2688f1e168fc927f025625" or
    hash.sha256(0, filesize) == "670384fafb23140d96f2f8fe04a13fc8cc8e2a6e5e8c973e39b58d103c5fea92" or
    hash.sha256(0, filesize) == "b90988400cced319d260c4937f334ecc364785ed5c593cd2139965e62ca58173" or
    hash.sha256(0, filesize) == "e20b35a8c30e076cdd0e1df05ba1ff2e418dbd39a674f084787cc0af2fda9e95"
}
