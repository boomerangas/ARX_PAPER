'''
Created on May 14, 2022

@author: jesenteh
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher


class katan64(AbstractCipher):
    """
    Represents the differential behaviour of Katan64 and can be used
    to find differential characteristics for the given parameters.
    It uses an alternative representation of Katan64 in ARX form.
    """

    name = "katan64"

    def ax_box(self, x):
        x0 = x >> 3 & 0x1
        x1 = x >> 2 & 0x1
        x2 = x >> 1 & 0x1
        x3 = x & 0x1
        return (x0 & x1) ^ (x2 & x3)

    def ax_box_2(self, x):
        x0 = x >> 1 & 0x1
        x1 = x & 0x1
        return x0 & x1

    def small_vari(self, x_in, x_out):
        variables = ["{0}[{1}:{1}]".format(x_in, 39 + 11),
                     "{0}[{1}:{1}]".format(x_in, 39 + 20),
                     "{0}[{1}:{1}]".format(x_out, 39 + 11 + 1),
                     "{0}[{1}:{1}]".format(x_out, 39 + 20 + 1)]
        return variables

    def big_vari(self, x_in, x_out):

        variables = ["{0}[{1}:{1}]".format(x_in, 9),
                     "{0}[{1}:{1}]".format(x_in, 14),
                     "{0}[{1}:{1}]".format(x_in, 21),
                     "{0}[{1}:{1}]".format(x_in, 33),
                     "{0}[{1}:{1}]".format(x_out, 9 + 1),
                     "{0}[{1}:{1}]".format(x_out, 14 + 1),
                     "{0}[{1}:{1}]".format(x_out, 21 + 1),
                     "{0}[{1}:{1}]".format(x_out, 33 + 1)]

        return variables

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['Xa', 'Xb', 'Xc', 'Ya', 'Yb', 'Yc', 'A', 'F', 'w']

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for KATAN64 with
        the given parameters.
        Must use wordsize = 64
        """

        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]
        offset = parameters["offset"]

        switch_start_round = parameters["switchStartRound"]
        switch_rounds = parameters["switchRounds"]

        e0_start_search_num = 0
        e0_end_search_num = rounds if switch_start_round == -1 else switch_start_round + switch_rounds
        em_start_search_num = rounds if switch_start_round == -1 else switch_start_round
        em_end_search_num = rounds if switch_start_round == -1 else e0_end_search_num
        e1_start_search_num = rounds if switch_start_round == -1 else switch_start_round + 1
        e1_end_search_num = rounds

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP\n% KATAN64 w={}"
                      "rounds={} with IR offset={}\n\n\n".format(wordsize, rounds, offset))
            stp_file.write(header)

            # Setup variables
            # xa = input (64) after first sub-round 
            # xb = input (64) after second subround 
            # xc = input (64) after third subround 
            # f = outputs of AND operation (Only 9 bits required, use 9 bits to store)
            # a = active or inactive AND operation (Only 9 bits required, use 9 bits to store)
            xa = ["Xa{}".format(i) for i in range(rounds + 1)]  # Additional one for output difference
            xb = ["Xb{}".format(i) for i in range(rounds)]  # Intermediate x values, no need output difference
            xc = ["Xc{}".format(i) for i in range(rounds)]  # Intermediate x values, no need output difference
            ya = ["Ya{}".format(i) for i in range(rounds + 1)]  # Additional one for output difference
            yb = ["Yb{}".format(i) for i in range(rounds)]  # Intermediate x values, no need output difference
            yc = ["Yc{}".format(i) for i in range(rounds)]  # Intermediate x values, no need output difference
            f = ["F{}".format(i) for i in range(rounds)]
            a = ["A{}".format(i) for i in range(rounds)]

            # w = weight
            w = ["w{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, xa, wordsize)
            stpcommands.setupVariables(stp_file, xb, wordsize)
            stpcommands.setupVariables(stp_file, xc, wordsize)
            stpcommands.setupVariables(stp_file, ya, wordsize)
            stpcommands.setupVariables(stp_file, yb, wordsize)
            stpcommands.setupVariables(stp_file, yc, wordsize)
            stpcommands.setupVariables(stp_file, f, wordsize)
            stpcommands.setupVariables(stp_file, a, wordsize)
            stpcommands.setupVariables(stp_file, w, wordsize)

            stpcommands.setupWeightComputation(stp_file, weight, w, wordsize)

            # E0
            for i in range(e0_start_search_num, e0_end_search_num):
                self.setupKatanRound(stp_file, xa[i], xb[i], xc[i], f[i], a[i], xa[i + 1],
                                     w[i], wordsize, i, offset)
            # Em
            for i in range(em_start_search_num, em_end_search_num):
                command = stpcommands.and_bct(self.small_vari(xa[i], xb[i + 1]), self.ax_box_2, 2)
                command += stpcommands.and_bct(self.small_vari(xb[i], xc[i + 1]), self.ax_box_2, 2)
                command += stpcommands.and_bct(self.small_vari(xc[i], ya[i + 1]), self.ax_box_2, 2)
                command += stpcommands.and_bct(self.big_vari(xa[i], xb[i + 1]), self.ax_box, 4)
                command += stpcommands.and_bct(self.big_vari(xb[i], xc[i + 1]), self.ax_box, 4)
                command += stpcommands.and_bct(self.big_vari(xc[i], ya[i + 1]), self.ax_box, 4)
                stp_file.write(command)
            # E1
            for i in range(e1_start_search_num, e1_end_search_num):
                self.setupKatanRound(stp_file, ya[i], yb[i], yc[i], f[i], a[i], ya[i + 1],
                                     w[i], wordsize, i, offset)

            # No all zero characteristic
            if switch_start_round == -1:
                stpcommands.assertNonZero(stp_file, xa, wordsize)
            else:
                # use BCT
                stpcommands.assertNonZero(stp_file, xa[e0_start_search_num:e0_end_search_num], wordsize)
                stpcommands.assertNonZero(stp_file, ya[e1_start_search_num:e1_end_search_num], wordsize)

            # Iterative characteristics only
            # Input difference = Output difference
            if parameters["iterative"]:
                stpcommands.assertVariableValue(stp_file, xa[0], xa[rounds])

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, wordsize)

            stpcommands.setupQuery(stp_file)

        return

    def setupKatanRound(self, stp_file, xa_in, xb, xc, f, a, xa_out, w, wordsize, r, offset):
        """
        Model for differential behaviour of one round KATAN48
        """
        command = ""
        IR = [1, 1, 1, 1, 1, 1, 1, 0, 0, 0,
              1, 1, 0, 1, 0, 1, 0, 1, 0, 1,
              1, 1, 1, 0, 1, 1, 0, 0, 1, 1,
              0, 0, 1, 0, 1, 0, 0, 1, 0, 0,
              0, 1, 0, 0, 0, 1, 1, 0, 0, 0,
              1, 1, 1, 1, 0, 0, 0, 0, 1, 0,
              0, 0, 0, 1, 0, 1, 0, 0, 0, 0,
              0, 1, 1, 1, 1, 1, 0, 0, 1, 1,
              1, 1, 1, 1, 0, 1, 0, 1, 0, 0,
              0, 1, 0, 1, 0, 1, 0, 0, 1, 1,
              0, 0, 0, 0, 1, 1, 0, 0, 1, 1,
              1, 0, 1, 1, 1, 1, 1, 0, 1, 1,
              1, 0, 1, 0, 0, 1, 0, 1, 0, 1,
              1, 0, 1, 0, 0, 1, 1, 1, 0, 0,
              1, 1, 0, 1, 1, 0, 0, 0, 1, 0,
              1, 1, 1, 0, 1, 1, 0, 1, 1, 1,
              1, 0, 0, 1, 0, 1, 1, 0, 1, 1,
              0, 1, 0, 1, 1, 1, 0, 0, 1, 0,
              0, 1, 0, 0, 1, 1, 0, 1, 0, 0,
              0, 1, 1, 1, 0, 0, 0, 1, 0, 0,
              1, 1, 1, 1, 0, 1, 0, 0, 0, 0,
              1, 1, 1, 0, 1, 0, 1, 1, 0, 0,
              0, 0, 0, 1, 0, 1, 1, 0, 0, 1,
              0, 0, 0, 0, 0, 0, 1, 1, 0, 1,
              1, 1, 0, 0, 0, 0, 0, 0, 0, 1,
              0, 0, 1, 0]

        # ***************************************
        # First iteration of nonlinear functions
        # ***************************************

        # Check if AND is active
        # a[0] = x[9] | x[14]
        command += "ASSERT({0}[0:0] = {1}[9:9]|{2}[14:14]);\n".format(a, xa_in, xa_in)
        # a[1] = x[21]| x[33]
        command += "ASSERT({0}[1:1] = {1}[21:21]|{2}[33:33]);\n".format(a, xa_in, xa_in)
        # Locations for L1 = 11 and 20. In full 64-bit register, 11+39 = 50, 20+39 = 59
        # a[2] = x[50] | x[59]
        command += "ASSERT({0}[2:2] = {1}[50:50]|{2}[59:59]);\n".format(a, xa_in, xa_in)

        # Calculate weights and output of AND operations
        # If a=1, w = 1, otherwise, w = 0
        # If a = 1, f = 0/1, otherwise, f = 0
        for i in range(3):
            # command += "ASSERT({0}[{2}:{2}] = {1}[{2}:{2}]);\n".format(w,a,i)
            command += "ASSERT(BVLE({0}[{2}:{2}],{1}[{2}:{2}]));\n".format(f, a, i)

        # w[1]=a[2]
        command += "ASSERT({0}[1:1] = {1}[2:2]);\n".format(w, a)  # AND in the L1 register
        # As long as either 1 AND operation in L2 register is active, prob is 1
        # w[0]=a[0]|a[1]
        command += "ASSERT({0}[0:0] = {1}[0:0] | {1}[1:1]);\n".format(w, a)

        # Shift and store into xb
        # Permutation layer (shift left L2 by 1 except for position 38)
        for i in range(0, 38):
            command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(xb, i + 1, xa_in, i)
        # Permutation layer (shift left L1 by 1 except for position 63 (L1_24))
        for i in range(39, 63):
            command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(xb, i + 1, xa_in, i)

        # Perform XOR operation for to get bits for position L2_0 and 39 (L1_0)
        # x_out[0] = x[63]^x[54]^a[2]^(x[48]&IR[r])
        command += "ASSERT({0}[0:0] = BVXOR({1}[63:63],BVXOR({1}[54:54],BVXOR({2}[2:2],({1}[48:48]&0b{3})))));\n".format(
            xb, xa_in, f, IR[r + offset])
        # x_out[39] = x[38]^a[1]^x[25]^a[0]
        command += "ASSERT({0}[39:39] = BVXOR({1}[38:38],BVXOR({2}[1:1],BVXOR({1}[25:25],{2}[0:0]))));\n".format(xb,
                                                                                                                 xa_in,
                                                                                                                 f)

        # ***************************************
        # Second iteration of nonlinear functions
        # ***************************************
        # Bits 3-5 are used for a,f,w

        # Check if AND is active
        # a[3] = x[9] | x[14]
        command += "ASSERT({0}[3:3] = {1}[9:9]|{2}[14:14]);\n".format(a, xb, xb)
        # a[4] = x[21]| x[33]
        command += "ASSERT({0}[4:4] = {1}[21:21]|{2}[33:33]);\n".format(a, xb, xb)
        # Locations for L1 = 11 and 20. In full 64-bit register, 11+39 = 50, 20+39 = 59
        # a[5] = x[50] | x[59]
        command += "ASSERT({0}[5:5] = {1}[50:50]|{2}[59:59]);\n".format(a, xb, xb)

        # Calculate weights and output of AND operations
        # If a=1, w = 1, otherwise, w = 0
        # If a = 1, f = 0/1, otherwise, f = 0
        for i in range(3, 6):
            # command += "ASSERT({0}[{2}:{2}] = {1}[{2}:{2}]);\n".format(w,a,i)
            command += "ASSERT(BVLE({0}[{2}:{2}],{1}[{2}:{2}]));\n".format(f, a, i)

        # w[3]=a[5]
        command += "ASSERT({0}[3:3] = {1}[5:5]);\n".format(w, a)  # AND in the L1 register
        # As long as either 1 AND operation in L2 register is active, prob is 1
        # w[2]=a[3]|a[4]
        command += "ASSERT({0}[2:2] = {1}[3:3] | {1}[4:4]);\n".format(w, a)

        # Shift and store into xc
        # Permutation layer (shift left L2 by 1 except for position 38)
        for i in range(0, 38):
            command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(xc, i + 1, xb, i)
        # Permutation layer (shift left L1 by 1 except for position 63 (L1_24))
        for i in range(39, 63):
            command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(xc, i + 1, xb, i)

        # Perform XOR operation for to get bits for position L2_0 and 29 (L1_0)
        # x_out[0] = x[63]^x[54]^a[2]^(x[48]&IR[r])
        command += "ASSERT({0}[0:0] = BVXOR({1}[63:63],BVXOR({1}[54:54],BVXOR({2}[5:5],({1}[48:48]&0b{3})))));\n".format(
            xc, xb, f, IR[r + offset])
        # x_out[39] = x[38]^a[1]^x[25]^a[0]
        command += "ASSERT({0}[39:39] = BVXOR({1}[38:38],BVXOR({2}[4:4],BVXOR({1}[25:25],{2}[3:3]))));\n".format(xc, xb,
                                                                                                                 f)

        # ***************************************
        # Third iteration of nonlinear functions
        # ***************************************
        # Bits 6,7,8 are used for a,f,w

        # Check if AND is active
        # a[6] = x[9] | x[14]
        command += "ASSERT({0}[6:6] = {1}[9:9]|{2}[14:14]);\n".format(a, xc, xc)
        # a[7] = x[21]| x[33]
        command += "ASSERT({0}[7:7] = {1}[21:21]|{2}[33:33]);\n".format(a, xc, xc)
        # Locations for L1 = 11 and 20. In full 64-bit register, 11+39 = 50, 20+39 = 59
        # a[8] = x[50] | x[59]
        command += "ASSERT({0}[8:8] = {1}[50:50]|{2}[59:59]);\n".format(a, xc, xc)

        # Calculate weights and output of AND operations
        # If a=1, w = 1, otherwise, w = 0
        # If a = 1, f = 0/1, otherwise, f = 0
        for i in range(6, 9):
            # command += "ASSERT({0}[{2}:{2}] = {1}[{2}:{2}]);\n".format(w,a,i)
            command += "ASSERT(BVLE({0}[{2}:{2}],{1}[{2}:{2}]));\n".format(f, a, i)

        # w[5]=a[8]
        command += "ASSERT({0}[5:5] = {1}[8:8]);\n".format(w, a)  # AND in the L1 register
        # As long as either 1 AND operation in L2 register is active, prob is 1
        # w[4]=a[6]|a[7]
        command += "ASSERT({0}[4:4] = {1}[6:6] | {1}[7:7]);\n".format(w, a)

        # Shift and store into xa_out
        # Permutation layer (shift left L2 by 1 except for position 38)
        for i in range(0, 38):
            command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(xa_out, i + 1, xc, i)
        # Permutation layer (shift left L1 by 1 except for position 63 (L1_24))
        for i in range(39, 63):
            command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(xa_out, i + 1, xc, i)

        # Perform XOR operation for to get bits for position L2_0 and 29 (L1_0)
        # x_out[0] = x[63]^x[54]^a[2]^(x[48]&IR[r])
        command += "ASSERT({0}[0:0] = BVXOR({1}[63:63],BVXOR({1}[54:54],BVXOR({2}[8:8],({1}[48:48]&0b{3})))));\n".format(
            xa_out, xc, f, IR[r + offset])
        # x_out[39] = x[38]^a[1]^x[25]^a[0]
        command += "ASSERT({0}[39:39] = BVXOR({1}[38:38],BVXOR({2}[7:7],BVXOR({1}[25:25],{2}[6:6]))));\n".format(xa_out,
                                                                                                                 xc, f)

        # Use 9 bits to store weight (for each of the ANDs in the 2 iteraions). The rest must be 0.
        command += "ASSERT(0b0000000000000000000000000000000000000000000000000000000000 = {0}[63:6]);\n".format(w)
        command += "ASSERT(0b0000000000000000000000000000000000000000000000000000000 = {0}[63:9]);\n".format(f)
        command += "ASSERT(0b0000000000000000000000000000000000000000000000000000000 = {0}[63:9]);\n".format(a)

        stp_file.write(command)
        return
