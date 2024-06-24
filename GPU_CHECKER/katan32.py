import math
import numpy
from numba import cuda
import numpy as np
import random
import time

WEIGHT = 32
CIPHER_NAME = "KATAN32"

IR = (
    1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1,
    0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0,
    1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0,
    0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1,
    0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1,
    1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1,
    0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0,
    1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1,
    1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1,
    1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1,
    0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1,
    1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0,
    0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1,
    0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1,
    1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0,
)


@cuda.jit
def enc(plaintext, sub_keys, ir, from_round, to_round, temp_list):
    for r in range(from_round, to_round):
        k_a = sub_keys[2 * r]
        k_b = sub_keys[2 * r + 1]

        y1 = plaintext >> 18 & 0x00000001
        y2 = plaintext >> 7 & 0x00000001
        y3 = plaintext >> 12 & 0x00000001
        y4 = plaintext >> 10 & 0x00000001
        y5 = plaintext >> 8 & 0x00000001
        y6 = plaintext >> 3 & 0x00000001

        x1 = plaintext >> (12 + 19) & 0x00000001
        x2 = plaintext >> (7 + 19) & 0x00000001
        x3 = plaintext >> (8 + 19) & 0x00000001
        x4 = plaintext >> (5 + 19) & 0x00000001
        x5 = plaintext >> (3 + 19) & 0x00000001

        f_a = x1 ^ x2 ^ (x3 & x4) ^ (x5 & ir[r]) ^ k_a
        f_b = y1 ^ y2 ^ (y3 & y4) ^ (y5 & y6) ^ k_b

        plaintext <<= 1
        if f_a == 0:
            plaintext &= 0xFFFFFFFE
        else:
            plaintext |= f_a
        if f_b == 0:
            plaintext &= 0xFFF7FFFF
        else:
            plaintext |= (f_b << 19)

    temp_list[0] = plaintext


@cuda.jit
def dec(ciphertext, sub_keys, ir, from_round, to_round, temp_list):
    for rr in range(from_round, to_round):
        r = to_round - 1 - rr
        k_a = sub_keys[2 * r]
        k_b = sub_keys[2 * r + 1]

        y0 = ciphertext & 0x00000001
        y2 = ciphertext >> (7 + 1) & 0x00000001
        y3 = ciphertext >> (12 + 1) & 0x00000001
        y4 = ciphertext >> (10 + 1) & 0x00000001
        y5 = ciphertext >> (8 + 1) & 0x00000001
        y6 = ciphertext >> (3 + 1) & 0x00000001

        x0 = ciphertext >> 19 & 0x00000001
        x2 = ciphertext >> (7 + 19 + 1) & 0x00000001
        x3 = ciphertext >> (8 + 19 + 1) & 0x00000001
        x4 = ciphertext >> (5 + 19 + 1) & 0x00000001
        x5 = ciphertext >> (3 + 19 + 1) & 0x00000001

        f_a = y0 ^ x2 ^ (x3 & x4) ^ (x5 & ir[r]) ^ k_a
        f_b = x0 ^ y2 ^ (y3 & y4) ^ (y5 & y6) ^ k_b

        ciphertext >>= 1
        if f_a == 0:
            ciphertext &= 0x7FFFFFFF
        else:
            ciphertext |= (f_a << 31)
        if f_b == 0:
            ciphertext &= 0xFFFBFFFF
        else:
            ciphertext |= (f_b << 18)

    temp_list[0] = ciphertext


@cuda.jit
def katan_task(keys, input_diff, output_diff, rounds, result_collector, offset, ir, temp_list):
    weight = 14
    thread_index = cuda.threadIdx.x + cuda.blockIdx.x * cuda.blockDim.x
    result_collector[thread_index] = 0
    res = result_collector[thread_index]
    used_list = temp_list[thread_index]

    start = thread_index * (2 ** weight)
    end = thread_index * (2 ** weight) + 2 ** weight

    for i in range(start, end):
        x1 = i
        if x1 > (x1 ^ input_diff):
            continue
        enc(x1, keys, ir, offset, rounds, used_list)
        c1 = used_list[0]

        x2 = x1 ^ input_diff
        enc(x2, keys, ir, offset, rounds, used_list)
        c2 = used_list[0]

        c3 = c1 ^ output_diff
        c4 = c2 ^ output_diff

        dec(c3, keys, ir, offset, rounds, used_list)
        x3 = used_list[0]

        dec(c4, keys, ir, offset, rounds, used_list)
        x4 = used_list[0]
        if x3 ^ x4 == input_diff:
            res += 2
    result_collector[thread_index] = res


def num2bits_cpu(num, bit_length):
    bits = []
    for i in range(bit_length):
        bits.append(num & 1)
        num >>= 1
    return bits


def lfsr(iv):
    state = num2bits_cpu(iv, 80)
    for i in range(254 * 2):
        yield state[0]
        state.append(state[0] ^ state[19] ^ state[30] ^ state[67])
        state.pop(0)


def generate_round_key(key):
    keys = np.zeros(254 * 2, dtype=numpy.int32)
    stream = lfsr(key)
    for i in range(254 * 2):
        keys[i] = (next(stream))
    return keys


def cpu_task():
    # read differential info from files
    result_file_name = 'verify_result_katan32.txt'
    save_file = open(result_file_name, "w")
    data_file = open("check_list_katan32.txt", "r")
    data_list = []
    data = data_file.readline()
    while data != "":
        temps = data.split(",")
        data = []
        for i in temps:
            if i.startswith("0x"):
                data.append(int(i, 16))
            else:
                if "." in i:
                    data.append(float(i))
                else:
                    data.append(int(i))
        data.append(1)
        data_list.append(data)
        data = data_file.readline()

    # GPU task
    threads_in_per_block = 2 ** 8
    blocks_in_per_grid = 2 ** 10
    total_threads = threads_in_per_block * blocks_in_per_grid
    ir = cuda.to_device(IR)

    for dd in data_list:
        start_time = time.time()
        input_diff = dd[0]
        output_diff = dd[3]
        rounds = dd[4]
        boomerang_weight = dd[5]
        rectangle_weight = dd[6]

        #################
        result = numpy.zeros((total_threads,), dtype=numpy.uint32)
        temp_list = numpy.array([[0 for _ in range(32)] for _ in range(total_threads)], dtype=numpy.uint32)
        key = random.randint(0, 2 ** 80)
        sub_keys = generate_round_key(key)

        cuda_sub_keys = cuda.to_device(sub_keys)
        cuda_result = cuda.to_device(result)
        cuda_temp_list = cuda.to_device(temp_list)
        #################

        katan_task[blocks_in_per_grid, threads_in_per_block](cuda_sub_keys, input_diff, output_diff, rounds,
                                                             cuda_result, 0, ir,
                                                             cuda_temp_list)

        res = numpy.zeros((1,), dtype=numpy.uint64)[0]
        for r in cuda_result:
            res += r
        if res == 0:
            tip = "Invalid"
        else:
            tip = math.log2(res / 2 ** 32)

        save_str = "CIPHER:{0}, INPUT_DIFF:{1}, OUTPUT_DIFF:{2}, rounds:{6}\n\tBOOMERANG:{3},RECTANGLE:{4},ACTUAL_WEIGHT:{5}\n\tKey:{7}\n".format(
            CIPHER_NAME, hex(input_diff),
            hex(output_diff), boomerang_weight, rectangle_weight, tip, rounds, hex(key))
        save_file.write(save_str)
        save_file.flush()
        print(save_str)
        print("Task done, time:{}".format(time.time() - start_time))


cpu_task()