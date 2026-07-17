import "hash"
// Salamander CTI  //  https://salacti.com
// Crypto Clipper uses Tor and worm-like propagation for persistence and control

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = "CryptoBandits, Contebrew"
  condition:
    hash.md5(0, filesize) == "03b51af0a04467cebfa235199db4c02e" or
    hash.sha1(0, filesize) == "bbe05d2f2487ed09e1062111fd448822364a44a7" or
    hash.sha256(0, filesize) == "0020d23b0f9c5e6851a7f737af73fd143175ee47054931166369edd93338538a" or
    hash.sha256(0, filesize) == "100407796028bf3649752d9d2a67a0e4394d752eb8de86daa42920e814f3fae8" or
    hash.sha256(0, filesize) == "20db98af3037b197c8a846dbf17b87fc6f049c3e0d9a188f9b9a74d3916dd5e1" or
    hash.sha256(0, filesize) == "23c1e673f315dafa14b73034a90dd3d393a984451ff6601b8be8142be6487b43" or
    hash.sha256(0, filesize) == "35a6bc44b176a050fd6824904b7604f0f45b0fdfa26bf9500b9e05973b387cfd" or
    hash.sha256(0, filesize) == "67fc5cf395e28294bbb91ed0e954fdf2e80ebd9119022a115a42c286dc8bacf5" or
    hash.sha256(0, filesize) == "7630debd35cac6b7d58c4427695579b3e3a8b1cc462f523234cd6c698882a68c" or
    hash.sha256(0, filesize) == "7787a9a7d8ae393aa32f257d083903c4dc9b97a1e5b0458c4cd480d4f3cb5b05" or
    hash.sha256(0, filesize) == "9d90f54ae36c6c5435d5b8bed40faf54cc91f6db28574a6310b5ffaeb0362e96" or
    hash.sha256(0, filesize) == "a7abf1d9d6686af1cefcd60b17a312e7eb8cfe267def1ec34aeab6128c811630" or
    hash.sha256(0, filesize) == "b2777b73a4c33ac6a409d475057843be6b5d32262ef28a1f1ff5bb52e3834c5f" or
    hash.sha256(0, filesize) == "c824630154ac4fdfce94ded01f037c305eab51e9bef3f493c60ff3184a640502" or
    hash.sha256(0, filesize) == "cf9fc891ea5ca5ecd8113ef3e69f6f52ff538b6cccbdaa9559106fc72bc6da30" or
    hash.sha256(0, filesize) == "d14b80cbd1a19d4ad0473a0661297f8fdf598e81ff6c4ab24e212dcad2e54b3f" or
    hash.sha256(0, filesize) == "d43bf94f0cb0ab97c88113b7e07d1a4024d1610617b5ad05882b1dbab89e15ba" or
    hash.sha256(0, filesize) == "f3b54984caca95fd496bcfe5d7db1611b08d2f5b7d250b43b430e5d76393f9e0"
}
