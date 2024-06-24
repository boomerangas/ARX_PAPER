import os

import numpy
import numpy as np


def makedirs(dirs: list):
    for dir in dirs:
        if not os.path.exists(dir):
            os.makedirs(dir)


def sand_t(n, rotation=0) -> list:
    if n % 4 != 0:
        return []
    res = [[], [], [], []]
    for i in range(n):
        remainder = i % 4
        res[remainder].append(i)
    res = np.reshape(res, (len(res), len(res[1])))
    if rotation > 0:
        res = np.roll(res, rotation, 1)
    return np.reshape(res, (1, len(res) * len(res[1]))).tolist()[0]


def sand_rot(n, rotation=0) -> list:
    if n % 4 != 0:
        return []
    res = [i for i in range(n)]
    res = np.reshape(res, (4, n // 4))
    if rotation > 0:
        res = np.roll(res, rotation, 1)
    return np.reshape(res, (1, len(res) * len(res[1]))).tolist()[0]


def sand_rot_nibble(n, rotation=0) -> list:
    if n % 4 != 0:
        return []
    res = [i for i in range(n)]
    res = np.reshape(res, (4, n // 4))
    if rotation > 0:
        res = np.roll(res, rotation, 1)
    return res


def reverse_p_box():
    h = 0x84000000
    bins = bin(h)[2:].zfill(32)
    bins = [int(bins[i]) for i in range(32)]
    bins = numpy.reshape(bins, (4, 8))
    res = numpy.zeros((4, 8), dtype=numpy.int32)

    # perm = [7, 4, 1, 6, 3, 0, 5, 2]
    perm = [0, 7, 6, 5, 4, 3, 2, 1]

    for i in range(len(bins)):
        for j in range(len(perm)):
            res[i][perm[j]] = bins[i][j]

    r = list(res[0]) + list(res[1]) + list(res[2]) + list(res[3])
    r = [str(i) for i in r]
    print(hex(int("".join(r), 2)))

# reverse_p_box()
