string = b"Pay no mind to the distant thunder, Beauty fills his head with wonder, boy"
key = "bca914890bc40728b3cf7d6b5298292d369745a2592ad06ffac1f03f04b671538fdbcff6bd9fe1f086863851d2a31a69743b0452fd87a993f489f3454bbe1cab4510ccb979013277a7bf"
hex_string = string.hex()
print(len(hex_string), len(key))
xoring = int(key, 16).__xor__(int(hex_string, 16))
print(len(hex(xoring).encode()))
