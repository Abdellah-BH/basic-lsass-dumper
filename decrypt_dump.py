key = 0xAA
with open("encrypted_lsass.dmp", "rb") as f:
    data = bytearray(f.read())

decrypted = bytearray([b ^ key for b in data])

with open("lsass_decrypted.dmp", "wb") as f:
    f.write(decrypted)
