import "hash"
// Salamander CTI  //  https://salacti.com
// The Devil, Eight Million Emails, and a Whole Lot of Milk | Phishing Stager Exposed

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = ""
  condition:
    hash.sha256(0, filesize) == "13ac78f8f2ed76a03c85f0cdef07e5463aa64458303c0949090fcd81868ba8ca" or
    hash.sha256(0, filesize) == "375c2c84e2ca022c565507523b75c9c08a455479861ea41fc9b9ff74b3453445" or
    hash.sha256(0, filesize) == "5d2ad1795b0dfc4a58424b2fa2f002246f653b119d362954ae270b6998e9d575" or
    hash.sha256(0, filesize) == "6c428acbd91be85fedf9cbb334457ddea08ff624d4de88041749578e968d62a8" or
    hash.sha256(0, filesize) == "7fda5f10a2bc212daaa467484c56eb8abf3f3681f6405c5c2fac16d4124e44ca" or
    hash.sha256(0, filesize) == "95fc58dc321b07ecc99d95359bcdee08a5beb519ead8e70e40f33928533a1b14" or
    hash.sha256(0, filesize) == "c5ec55270af084d3c07d2918098d598bc2c5ca42f4189d69cdfcae2c958e5ec7"
}
