import sys
plaintext = open(sys.argv[1], "rb").read()
print('unsigned char payload[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in plaintext) + ' };')