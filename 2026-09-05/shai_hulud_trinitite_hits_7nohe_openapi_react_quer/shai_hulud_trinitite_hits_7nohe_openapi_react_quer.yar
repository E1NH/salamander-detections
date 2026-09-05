import "hash"
// Salamander CTI  //  https://salacti.com
// Shai-Hulud Trinitite Hits @7nohe/openapi-react-query-codegen

rule Salamander_TeamPCP
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "TeamPCP"
    malware = "Shai-Hulud, Trinitite, Mini Shai-Hulud"
  condition:
    hash.sha1(0, filesize) == "365d4eb738d3146583431948d3ba6e27a32556be" or
    hash.sha1(0, filesize) == "ec7876d6c917dad516ba69bbfafc948b834bf0ab" or
    hash.sha1(0, filesize) == "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
}
