# win-catalog-dotnet

Simple managed library that uses native API calls to extract hashes from the Windows security catalogs. Also provides a function to create file hashes that can be used to validate against the hashes within the security catalogs.

The first implementation used raw ASN1 parsing, with code converted from Matt Graeber's (@mattifestation) Powershell parser, however, C# seems far stricter at type casting, so it made it pretty hard to get to sub-objects. So whilst I got it to work I wasn't happy at not fully understanding the nested ASN1 structures.

https://github.com/mattifestation/CatalogTools

## Code Examples

### Extract all hashes 
```
DirectoryInfo d = new DirectoryInfo(@"C:\Windows\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}");

HashSet<string> hashes = new HashSet<string>();

foreach (var file in d.GetFiles("*.cat"))
{
    int  catVer;
    var temp = CatalogHelper.GetHashesFromCatalog(file.FullName, out catVer);
    foreach (string hash in temp)
    {
        hashes.Add(hash);
    }
}
```

### Hash Files using CryptCATAdminCalcHashFromFileHandle2

```
string sha256 = CatalogHelper.CalculateFileHash(@"C:\Windows\System32\drivers\vmx86.sys", "SHA256");
string sha1 = CatalogHelper.CalculateFileHash(@"C:\Windows\System32\drivers\vmx86.sys", "SHA1");
```