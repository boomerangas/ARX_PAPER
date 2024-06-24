import math
import numpy
from numba import cuda
from collections import deque
import random
import time

z0 = 0b01100111000011010100100010111110110011100001101010010001011111
z1 = 0b01011010000110010011111011100010101101000011001001111101110001
z2 = 0b11001101101001111110001000010100011001001011000000111011110101
z3 = 0b11110000101100111001010001001000000111101001100011010111011011
z4 = 0b11110111001001010011000011101000000100011011010110011110001011

VALID_SETUPS = {32: {64: (32, z0)},
                48: {72: (36, z0), 96: (36, z1)},
                64: {96: (42, z2), 128: (44, z3)},
                96: {96: (52, z2), 144: (54, z3)},
                128: {128: (68, z2), 192: (69, z3), 256: (72, z4)}}

WEIGHT = 32
CIPHER_NAME = "SIMON32"

BLOCK_SIZE = 32
KEY_SIZE = 64


@cuda.jit
def enc(key_schedule, plaintext, word_size, mod_mask, temp_list):
    temp_list[0] = 0
    temp_list[1] = 0
    b = (plaintext >> word_size) & mod_mask
    a = plaintext & mod_mask
    encrypt_function(b, a, word_size, mod_mask, key_schedule, temp_list)
    b = temp_list[0]
    a = temp_list[1]
    ciphertext = (b << word_size) + a
    temp_list[0] = ciphertext


@cuda.jit
def dec(key_schedule, ciphertext, word_size, mod_mask, temp_list):
    temp_list[0] = 0
    temp_list[1] = 0
    b = (ciphertext >> word_size) & mod_mask
    a = ciphertext & mod_mask
    decrypt_function(a, b, word_size, mod_mask, key_schedule, temp_list)
    a = temp_list[0]
    b = temp_list[1]
    plaintext = (b << word_size) + a
    temp_list[0] = plaintext


@cuda.jit
def encrypt_function(upper_word, lower_word, word_size, mod_mask, key_schedule, temp_list):
    x = upper_word
    y = lower_word

    for k in key_schedule:
        ls_1_x = ((x >> (word_size - 1)) + (x << 1)) & mod_mask
        ls_8_x = ((x >> (word_size - 8)) + (x << 8)) & mod_mask
        ls_2_x = ((x >> (word_size - 2)) + (x << 2)) & mod_mask
        xor_1 = (ls_1_x & ls_8_x) ^ y
        xor_2 = xor_1 ^ ls_2_x
        y = x
        x = k ^ xor_2

    temp_list[0] = x
    temp_list[1] = y
    return x, y


@cuda.jit
def decrypt_function(upper_word, lower_word, word_size, mod_mask, key_schedule, temp_list):
    x = upper_word
    y = lower_word

    for i in range(len(key_schedule) - 1, -1, -1):
        k = key_schedule[i]
        ls_1_x = ((x >> (word_size - 1)) + (x << 1)) & mod_mask
        ls_8_x = ((x >> (word_size - 8)) + (x << 8)) & mod_mask
        ls_2_x = ((x >> (word_size - 2)) + (x << 2)) & mod_mask
        xor_1 = (ls_1_x & ls_8_x) ^ y
        xor_2 = xor_1 ^ ls_2_x
        y = x
        x = k ^ xor_2

    temp_list[0] = x
    temp_list[1] = y


@cuda.jit
def simon_task(keys, input_diff, output_diff, result_collector, temp_list, block_size):
    weight = 14

    word_size = block_size >> 1
    mod_mask = (2 ** word_size) - 1

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
        enc(keys, x1, word_size, mod_mask, used_list)
        c1 = used_list[0]

        x2 = x1 ^ input_diff
        enc(keys, x2, word_size, mod_mask, used_list)
        c2 = used_list[0]

        c3 = c1 ^ output_diff
        c4 = c2 ^ output_diff

        dec(keys, c3, word_size, mod_mask, used_list)
        x3 = used_list[0]

        dec(keys, c4, word_size, mod_mask, used_list)
        x4 = used_list[0]
        if x3 ^ x4 == input_diff:
            res += 1
    result_collector[thread_index] = res


def generate_round_key(key, key_size, word_size, rounds, zseq):
    mod_mask = (2 ** word_size) - 1
    m = key_size // word_size
    key_schedule = []
    k_init = [((key >> (word_size * ((m - 1) - x))) & mod_mask) for x in range(m)]
    k_reg = deque(k_init)
    round_constant = mod_mask ^ 3
    for x in range(rounds):
        rs_3 = ((k_reg[0] << (word_size - 3)) + (k_reg[0] >> 3)) & mod_mask
        if m == 4:
            rs_3 = rs_3 ^ k_reg[2]
        rs_1 = ((rs_3 << (word_size - 1)) + (rs_3 >> 1)) & mod_mask
        c_z = ((zseq >> (x % 62)) & 1) ^ round_constant
        new_k = c_z ^ rs_1 ^ rs_3 ^ k_reg[m - 1]
        key_schedule.append(k_reg.pop())
        k_reg.appendleft(new_k)
    return key_schedule


def cpu_task():
    # read differential info from files
    result_file_name = 'verify_result_simon32.txt'
    save_file = open(result_file_name, "w")
    data_file = open("check_list_simon32.txt", "r")
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
    block_size = BLOCK_SIZE
    key_size = KEY_SIZE
    word_size = block_size >> 1
    rounds, z_que = VALID_SETUPS[block_size][key_size]

    for dd in data_list:
        start_time = time.time()
        input_diff = dd[0]
        output_diff = dd[3]
        rounds = dd[4]
        boomerang_weight = dd[5]
        rectangle_weight = dd[6]
        switch_len = dd[7]

        key = random.randint(0, 2 ** 32)
        ######################
        result = numpy.zeros((total_threads,), dtype=numpy.uint32)
        temp_list = numpy.array([[0 for _ in range(32)] for _ in range(total_threads)], dtype=numpy.uint32)
        sub_keys = generate_round_key(key, key_size, word_size, rounds, z_que)

        cuda_sub_keys = cuda.to_device(sub_keys)
        cuda_result = cuda.to_device(result)
        cuda_temp_list = cuda.to_device(temp_list)
        #############################
        simon_task[blocks_in_per_grid, threads_in_per_block](cuda_sub_keys, input_diff, output_diff, cuda_result,
                                                             cuda_temp_list,
                                                             block_size)
        res = numpy.zeros((1,), dtype=numpy.uint64)[0]
        for r in cuda_result:
            res += r
        if res == 0:
            tip = "Invalid"
        else:
            tip = math.log2(res / 2 ** 31)

        save_str = "CIPHER:{0}, INPUT_DIFF:{1}, OUTPUT_DIFF:{2}, rounds:{6}, sw_len:{8}\n\tBOOMERANG:{3},RECTANGLE:{4},ACTUAL_WEIGHT:{5}\n\tKey:{7}\n".format(
            CIPHER_NAME, hex(input_diff),
            hex(output_diff), boomerang_weight, rectangle_weight, tip, rounds, hex(key), switch_len)
        save_file.write(save_str)
        save_file.flush()
        print(save_str)
        print("Task done, time:{}".format(time.time() - start_time))


cpu_task()
