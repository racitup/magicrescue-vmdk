# magicrescue-vmdk
MagicRescue recipe for vmware vmdk files. Requires python3
### Operation
1. Parses the vmdk data looking for the binary header and/or text descriptor
2. If only text, copies the text vmdk
3. Else calculates the file size based on the available information and copies it
Supports magicrescue rename if the vmdk has an embedded descriptor
### Testing
Only tested on hosted sparse vmdks
### Notes
This is not an easy file format to rescue!
For further information, read the source comments
