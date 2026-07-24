import "hash"
// Salamander CTI  //  https://salacti.com
// Operation RoundPress Rolls on with More Half-Click Webmail Zero-Days

rule Salamander_TA458
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "TA458"
    malware = "SpyPress"
  condition:
    hash.sha256(0, filesize) == "625e4c166c7a1d5a1becf56b27d4f76a2f95935cbd8d556c30a493263d10dbf8" or
    hash.sha256(0, filesize) == "3a449148a0e3cac604fb93210dd7d91ccf48e06ed9aae064bc53a419a84ce9ba" or
    hash.sha256(0, filesize) == "6b2c02bf82087a3ca5fb7ef8046554ff29ce85d52202bdcfae2b2653aede139a" or
    hash.sha256(0, filesize) == "8b5a4dc237a4c89042176bc89864a4c357dcdd14fa544fe6496ccb6c31cd5b7f" or
    hash.sha256(0, filesize) == "a0c80cab70d6672b01710a70f93311fc1c1db2fbbf9cd6daa543c34b87e3444a" or
    hash.sha256(0, filesize) == "e27d1bf82249002a66395c89dbda6ec5d8df012a84b79d36fffbbf7808d28878" or
    hash.sha256(0, filesize) == "fb8ec4dbed14c0a91361abd82ebe9fb083615c3dbb15348f57317af7cc41dd34"
}
