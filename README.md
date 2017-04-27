# magicrescue-vmdk
MagicRescue recipe for vmware vmdk files. Requires python3
### Operation
1. Parses the vmdk data looking for the binary header and/or text descriptor
2. If only text, copies the text vmdk
3. Else calculates the file size based on the available information and copies it

Supports magicrescue rename if the vmdk has an embedded descriptor
### Support
Supports the following:
* Binary hosted sparse file version 1 with or without embedded text descriptor
* Text vmdk

Does not support:
* Hosted sparse file versions 2 and 3
* Flat/fixed size files (are just data)
* ESXi hosted sparse files (different format)
* Stream optimised files (different format)

### Notes
This is not an easy file format to rescue!

For further information, read the source comments
