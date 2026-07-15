import "hash"
// Salamander CTI  //  https://salacti.com
// LokiBot After a Decade: An Analysis of a Recent LokiBot Campaign

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "Loki, Loki Password Stealer (PWS)"
  condition:
    hash.sha256(0, filesize) == "c099f965144bccd0b590f946659fc3c0747c54aef505b6caaca9078712f455fb" or
    hash.sha256(0, filesize) == "64c7dd0a3a3ae49977ac05913d3878000cce14e5d8c1ee05b782bdfd648bde91" or
    hash.sha256(0, filesize) == "ad10ff9043d6f327045943635fcbd0c5918acb79dc998db92ee4c7dee5224710" or
    hash.sha256(0, filesize) == "4c9f271242f61f1a31b8146305e9a7ed512c521445d4f7a7a901e301307add3d" or
    hash.sha256(0, filesize) == "5864a697bd7b339f56b05405f29a097cd027cafdcc4e63c2aaeccccbf930605f" or
    hash.md5(0, filesize) == "a484efb02ab3c049666af91363bfdf77" or
    hash.sha1(0, filesize) == "c44ec9336ed67352ee021097876a82407c40eea1"
}
