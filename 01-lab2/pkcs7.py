def PKCS7_padding(byte_str, padding):
    len_bytestr = len(byte_str)
    int_to_add = padding - len_bytestr % padding
    for i in range(int_to_add):
        byte_str += int_to_add.to_bytes()

    return byte_str


def PKCS7_unpadding(byte_str):
    len_padding = byte_str[-1]
    print(len_padding)
    return byte_str[:-len_padding]


def main():

    flag = input("str : ")
    flag_b = flag.encode()
    flag_b_padded = PKCS7_padding(flag_b, 16)
    flag_b_unpadded = PKCS7_unpadding(flag_b_padded)

    print("padded : ", PKCS7_padding(flag_b, 16).hex())
    print("unpadded : ", flag_b_unpadded)


main()
