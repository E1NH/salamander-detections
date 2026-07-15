import "hash"
// Salamander CTI  //  https://salacti.com
// One Target, Two Flags | Rival Espionage Actors Converge On Pakistani Law Enforcement

rule Salamander_TAG_179
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "TAG-179"
    malware = "Cobalt Strike, PythonStealer, Remcos"
  condition:
    hash.md5(0, filesize) == "fc59fc3d4b2af739014de04428ce2fb5" or
    hash.md5(0, filesize) == "d92fac74e6d7f4d8fc96c9ce6239435f" or
    hash.sha1(0, filesize) == "000fad96a85dd6933c22d3dbec9aed47b7f1f066" or
    hash.sha1(0, filesize) == "c6c197e61079a0a33108c2c87b5e3c7056a138ec" or
    hash.md5(0, filesize) == "96b15bb9ce8ef7c41b708b1620029d99" or
    hash.md5(0, filesize) == "91693c2d5a4b7d090fe06cc7382dfc18" or
    hash.sha1(0, filesize) == "08570471f39bb6725f07b8cddbea99ed48c22686" or
    hash.sha1(0, filesize) == "23f4766c011d193f076dfc735dc460e2a41ead79" or
    hash.sha1(0, filesize) == "23f6781919a50b118d8d4e6a7e9ae63b71ecc885" or
    hash.sha1(0, filesize) == "2bab40c55637398f0497cff9c8cbea564d595c7f" or
    hash.sha1(0, filesize) == "4039454c9189e64285e93fc075a30b93f814b5b5" or
    hash.sha1(0, filesize) == "47f8cb0c2dcf62702f58cfc1603d6325755f6820" or
    hash.sha1(0, filesize) == "539bd79fbb684edea94eb37518134b97e94b9dd8" or
    hash.sha1(0, filesize) == "58cb2d95063b9df807b7aa8dc106b74ce988a491" or
    hash.sha1(0, filesize) == "5d60ff36ff519c2e13e7f66cfa0bb46be79592a7" or
    hash.sha1(0, filesize) == "63b88d00331de88af696dfb7a896935d830e485f" or
    hash.sha1(0, filesize) == "6fe2e74d009abbd56de01fd7404a1245e9b47c79" or
    hash.sha1(0, filesize) == "71757adba833b46f961e840d0f055bcce0b529c4" or
    hash.sha1(0, filesize) == "8c329db96e093fa25268e078405a33c518dbb5c9" or
    hash.sha1(0, filesize) == "d66ab0cd2e44dc8389c111b7ed34c7bcb0b35311" or
    hash.sha256(0, filesize) == "1fd8ba64a687247466fa6e8b7d194154439ef527746fdb8c18b3c3d65b6d2390" or
    hash.sha256(0, filesize) == "71fa6a00314701fef5c6f32c17e1438063d05616198ac9a12004aeab957e11ae" or
    hash.sha256(0, filesize) == "7ea0930a332788c2e88e5822e4908d77cdcaad57e0e97401ed8fe4b117fdfc95"
}
