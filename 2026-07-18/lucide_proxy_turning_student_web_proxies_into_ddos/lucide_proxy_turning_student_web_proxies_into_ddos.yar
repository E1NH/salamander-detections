import "hash"
// Salamander CTI  //  https://salacti.com
// Lucide Proxy: Turning Student Web Proxies into DDoS Bots

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = ""
  condition:
    hash.md5(0, filesize) == "0a913561831bdf2c26dcf18b852b5cc1" or
    hash.md5(0, filesize) == "c6851a038da578a80eeb201e0588c84c" or
    hash.sha256(0, filesize) == "10ddbbae0070267b8d15888b09a3cdb19fa74d861315b71f21c9ace8b9f85c75" or
    hash.sha256(0, filesize) == "4b188d179e50e8208a6efec85e273e88d8fc390c836f299ba12915e0840408fd" or
    hash.sha256(0, filesize) == "eb4e1394d537d8eba509dd5c57e7aaf4c1df57715c7161330012a11f6202af84"
}
