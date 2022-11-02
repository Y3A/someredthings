import sys

dwHash = 0x7734773477347734
for i in sys.argv[1]:
    dwHash = (((dwHash << 0x5) + dwHash) + ord(i))&0xffffffffffffffff
print(hex(dwHash))
