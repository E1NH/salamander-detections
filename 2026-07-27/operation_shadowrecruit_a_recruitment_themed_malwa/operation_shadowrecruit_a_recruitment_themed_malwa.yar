import "hash"
// Salamander CTI  //  https://salacti.com
// Operation ShadowRecruit: A Recruitment-Themed Malware Campaign Leveraging ControlR and Google Sheets to Target Indian Job Seekers

rule Salamander_Operation_C_Major
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Operation C-Major"
    malware = "SheetAgent, PrivateRat"
  condition:
    hash.md5(0, filesize) == "6bcf91af52b9577ba81cbae9368f91f8" or
    hash.md5(0, filesize) == "6f2fd5cb3901d6818316423ac72da5e8" or
    hash.md5(0, filesize) == "90682a7c53132750b1517f80cab2281c" or
    hash.sha1(0, filesize) == "081747ca2a2f4be07b52ab1da0c76b8e508248a7" or
    hash.sha1(0, filesize) == "a154f9bff1999be4a42ffc4cbfc686e64a163997" or
    hash.sha1(0, filesize) == "c1a691fdd339709439774e9402b71a4b4ba50f42" or
    hash.sha256(0, filesize) == "2b33b5185e93e1655eb27dbaa025d7ee088627db3d640fe4709be705646b189c" or
    hash.sha256(0, filesize) == "434243e615b93a1b948c26ad55902bd78f9fa18e42375c15790634375c1ad3f4" or
    hash.sha256(0, filesize) == "70fe7576f20f5dd6a3d872753c922f1394d91487f5eabb417b240b83c22e31b2" or
    hash.sha256(0, filesize) == "b928e523b51187b932e48a65d36ce3d0c39ee9d409d493b90f98cf3d1e0e73b0" or
    hash.sha256(0, filesize) == "c4859db541b2bd0d266bbc44fafb5a767c862a57a3633a949dfaeebdf88ed529" or
    hash.sha256(0, filesize) == "cf3f1bceb83fa3acefbabae4bdc275347cfe03dd7fc770052a33baef204a89f7" or
    hash.sha256(0, filesize) == "ee9dd2a180aea75af5c0eda16b83681c0a5fed451bfad6d5b3af85c3b62fa210" or
    hash.sha256(0, filesize) == "fd2ac3a761f66dc6954014532795f9108f65739f23e4b294d4563673b7996881"
}
