'''
Created on Jan 1, 2019
@author: Shawn
'''


def PatternXorAssert(x, y, z, L):
    command = ""
    # command += "ASSERT(BVXOR({0} & {1} & {2}, BVXOR({0}, BVXOR({1}, {2}))) = 0bin{3});\n".format(
    #         x,
    #         y,
    #         z,
    #         "0" * L
    # )
    command += "ASSERT({0}=BVXOR({1},{2}));\n".format(x, y, z)
    return command


def Return_Sum_String(input_list, vec_len, var_len=1):
    L = len(input_list)
    S = "BVPLUS({}, ".format(vec_len)
    for i in range(L):
        S += "0bin{}@".format("0" * (vec_len - var_len)) + input_list[i] + ", "
    S = S[:-2]
    S += ")"
    return S


def Return_Concate_String(input_list, vec_len):
    L = len(input_list)
    assert L == vec_len
    S = ""
    for i in range(L):
        S += "{}@".format(input_list[i])
    S = S[:-1]
    return S


def Return_Or_String(input_list, vec_len):
    L = len(input_list)
    assert L == vec_len
    S = ""
    for i in range(L):
        S += "{}|".format(input_list[i])
    S = S[:-1]
    return S


def Return_Bin_String(x, x_len):
    y = []
    for i in range(x_len):
        y.append(x >> (x_len - 1 - i) & 0x1)
    return y


def XorTwoAssert(x0, x1):
    return "BVXOR({}, {})".format(x0, x1)


def ListAssert(k_list):
    L = len(k_list)
    assert L >= 2
    if L == 2:
        return "ASSERT({} = {});\n".format(k_list[0], k_list[1])
    xor_before = k_list[L - 1]
    for i in range(L - 2):
        xor_current = XorTwoAssert(k_list[L - 1 - 1 - i], xor_before)
        xor_before = xor_current
    return "ASSERT({} = {});\n".format(k_list[0], xor_current)
