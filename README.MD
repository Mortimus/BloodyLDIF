# BloodyLDIF is a tool to convert BloodyAD output to a format that ldif2bloodhound can understand
```bash
Usage of BloodyLDIF:
  -input string
        Input file path
  -output string
        Output file path
```
# Dump bloodhound data using BloodyAD (which uses LDAP session encryption)
```bash
bloodyAD --host 127.0.0.1 -u lowpriv -p 'password' -d contoso.local get search --filter '(objectClass=*)' --raw >> out.ldif
bloodyAD --host 127.0.0.1 -u lowpriv -p 'password' -d contoso.local get search --base 'CN=Schema,CN=Configuration,DC=contoso,DC=local' --filter '(objectClass=*)' --raw >> out.ldif
```
# Notes
Make sure to delete ldif2bloodhound artifacts inbetween script runs
`/tmp/c0a97d4e8f1f2bc301e54564213140da.cache` is an artifact I've found inbetween runs

# Links
* https://github.com/CravateRouge/bloodyAD
* https://github.com/SySS-Research/ldif2bloodhound