import "hash"
// Salamander CTI  //  https://salacti.com
// From PostCSS Masquerading to Windows RAT

rule Salamander_Data_Insufficient
{
  meta:
    author = "Salamander CTI"
    reference = "https://salacti.com"
    actor = "Data Insufficient"
    malware = ""
  condition:
    hash.md5(0, filesize) == "208166120775a11cb6680139ea0f3372" or
    hash.md5(0, filesize) == "4c1bdb2b045debf5b25e5be540ef99f0" or
    hash.md5(0, filesize) == "c2875e2f45e5f1dfa04463de53b3fa5a" or
    hash.md5(0, filesize) == "c5207f87b9103634b4db6f120eb6172a" or
    hash.md5(0, filesize) == "f189c338a5f2bc3cce06cee37c0b7522" or
    hash.sha1(0, filesize) == "2890d90edfc08fb4cfafe0d5fa2a9fb6800dedf5" or
    hash.sha1(0, filesize) == "71c6cd37ddc0e5899174c72eefee8b224fd1f4bb" or
    hash.sha1(0, filesize) == "7b1919c35da92cf5fd2583783dc9364fd11b69d2" or
    hash.sha1(0, filesize) == "8e162d4fc8c5c74e16bfb4346f893cc7a71c2476" or
    hash.sha1(0, filesize) == "965e3d19c89f12ef730120b84d9ee38755841447" or
    hash.sha256(0, filesize) == "164e322d6fbc62e254d73583acd7f39444c884d3f5e6a5d27db143fc25bc88b3" or
    hash.sha256(0, filesize) == "17832aa629524ef6e8d8d6e9b6b902a8d324b559e3c36dbd0e221ab1690be871" or
    hash.sha256(0, filesize) == "282b9bc318ad1234cbd1b86424b784299b8be31545802a7c6b751166b814b990" or
    hash.sha256(0, filesize) == "50ffce607867d8fa8eaf6ef5cd25a3c0e7e4415e881b9e55c04a67bcddb74fdf" or
    hash.sha256(0, filesize) == "c8075bbff748096e1c6a1ea0aa67bb6762fdd7551427a12425b35b94c1f1ecf2" or
    hash.sha256(0, filesize) == "f6669bd504ce6b0e303be7ee47f2ebbc062989c88c41f0a3f436044a24869798"
}
