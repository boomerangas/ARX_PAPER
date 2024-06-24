'''
Created on May 13, 2022

@author: jesenteh
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher


class katan48(AbstractCipher):
    """
    Represents the differential behaviour of Katan48 and can be used
    to find differential characteristics for the given parameters.
    It uses an alternative representation of Katan48 in ARX form.
    """

    name = "katan48BCT"

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

    def small_vari(self, x_in, x_out, offset=0):
        variables = ["{0}[{1}:{1}]".format(x_in, 29 + 7 + offset),
                     "{0}[{1}:{1}]".format(x_out, 29 + 7 + 1 + offset),
                     "{0}[{1}:{1}]".format(x_in, 29 + 15 + offset),
                     "{0}[{1}:{1}]".format(x_out, 29 + 15 + 1 + offset)]
        return variables

    def big_vari(self, x_in, x_out, offset=0):
        variables = ["{0}[{1}:{1}]".format(x_in, 6 + offset),
                     "{0}[{1}:{1}]".format(x_out, 6 + 1 + offset),
                     "{0}[{1}:{1}]".format(x_in, 15 + offset),
                     "{0}[{1}:{1}]".format(x_out, 15 + 1 + offset),

                     "{0}[{1}:{1}]".format(x_in, 13 + offset),
                     "{0}[{1}:{1}]".format(x_out, 13 + 1 + offset),
                     "{0}[{1}:{1}]".format(x_in, 21 + offset),
                     "{0}[{1}:{1}]".format(x_out, 21 + 1 + offset)]

        return variables

    def getFormatString(self):
        """
        Returns the print format.
        """
        # return ['Xa', 'Xb', 'Ya', 'Yb', 'XO', 'XG', 'YO', 'YG', 'w']
        return ['Xa', 'Ya', 'w']

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for KATAN48 with
        the given parameters.
        Must use wordsize = 64
        """

        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]
        offset = parameters["offset"]
        switch_start_round = parameters["switchStartRound"]
        switch_rounds = parameters["switchRounds"]

        command = ""

        e0_start_search_num = 0
        e0_end_search_num = rounds if switch_start_round == -1 else switch_start_round
        em_start_search_num = rounds if switch_start_round == -1 else switch_start_round
        em_end_search_num = (
            rounds if switch_start_round == -1 else em_start_search_num + switch_rounds
        )
        e1_start_search_num = (
            rounds if switch_start_round == -1 else switch_start_round + switch_rounds
        )
        e1_end_search_num = rounds

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP\n% KATAN48 w={}"
                      "rounds={} with IR offset={}\n\n\n".format(wordsize, rounds, offset))
            stp_file.write(header)

            # Setup variables
            # xa = input (64) after first sub-round (only 48 bits used)
            # xb = input (64) after first subround (only 48 bits used)
            # f = outputs of AND operation (Only 6 bits required, use 6 bits to store)
            # a = active or inactive AND operation (Only 6 bits required, use 6 bits to store)
            # Additional one for output difference
            xa = ["Xa{}".format(i) for i in range(rounds + 1)]
            # Intermediate x values, no need output difference
            xb = ["Xb{}".format(i) for i in range(rounds)]
            ya = ["Ya{}".format(i) for i in range(rounds + 1)]
            yb = ["Yb{}".format(i) for i in range(rounds + 1)]
            x_f_out = ["XO{}".format(i) for i in range(rounds)]
            x_a_out = ["XG{}".format(i) for i in range(rounds)]
            y_f_out = ["YO{}".format(i) for i in range(rounds)]
            y_a_out = ["YG{}".format(i) for i in range(rounds)]

            # w = weight
            w = ["w{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, xa, wordsize)
            stpcommands.setupVariables(stp_file, xb, wordsize)
            stpcommands.setupVariables(stp_file, ya, wordsize)
            stpcommands.setupVariables(stp_file, yb, wordsize)
            stpcommands.setupVariables(stp_file, x_a_out, wordsize)
            stpcommands.setupVariables(stp_file, x_f_out, wordsize)
            stpcommands.setupVariables(stp_file, y_a_out, wordsize)
            stpcommands.setupVariables(stp_file, y_f_out, wordsize)
            stpcommands.setupVariables(stp_file, w, wordsize)

            stpcommands.setupWeightComputation(stp_file, weight, w, wordsize)

            # E0
            for i in range(e0_start_search_num, e0_end_search_num):
                self.setupKatanRound(stp_file, xa[i], xb[i], x_f_out[i], x_a_out[i], xa[i + 1],
                                     w[i], wordsize, i, offset)
            # Em

            for i in range(em_start_search_num, em_end_search_num):
                self.setupKatanRound(
                    stp_file, xa[i], xb[i], x_f_out[i], x_a_out[i], xa[i + 1], w[i], wordsize, i, offset, True
                )
                self.setupKatanRound(
                    stp_file, ya[i + 1], yb[i + 1], y_f_out[i], y_a_out[i], ya[i + 2], w[i], wordsize, i, offset, True
                )
                command += self.and_bct(
                    self.small_vari(xa[i], ya[i + 1], -0))
                command += self.and_bct(
                    self.big_vari(xa[i], ya[i + 1], -0))

            # E1
            for i in range(e1_start_search_num, e1_end_search_num):
                self.setupKatanRound(stp_file, ya[i], yb[i], y_f_out[i], y_a_out[i], ya[i + 1],
                                     w[i], wordsize, i, offset)

            # Modify start_round to start from different positions

            # No all zero characteristic
            if switch_start_round == -1:
                stpcommands.assertNonZero(stp_file, xa, wordsize)
            else:
                # use BCT
                stpcommands.assertNonZero(
                    stp_file, [xa[0]], wordsize)
                stpcommands.assertNonZero(
                    stp_file, [ya[rounds]], wordsize)

            # Iterative characteristics only
            # Input difference = Output difference
            if parameters["iterative"]:
                stpcommands.assertVariableValue(stp_file, xa[0], xa[rounds])

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, wordsize)

            command += self.pre_handle(parameters)

            stp_file.write(command)
            stpcommands.setupQuery(stp_file)

        return

    def setupKatanRound(self, stp_file, xa_in, xb, f, a, xa_out, w, wordsize, r, offset, switch=False):
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
        # a[0] = x[6] | x[15]
        command += "ASSERT({0}[0:0] = {1}[6:6]|{2}[15:15]);\n".format(a,
                                                                      xa_in, xa_in)
        # a[1] = x[13]| x[21]
        command += "ASSERT({0}[1:1] = {1}[13:13]|{2}[21:21]);\n".format(a,
                                                                        xa_in, xa_in)
        # Locations for L1 = 7 and 15. In full 48-bit register, 7+29 = 36, 15+29 = 44
        # a[2] = x[36] | x[44]
        command += "ASSERT({0}[2:2] = {1}[36:36]|{2}[44:44]);\n".format(a,
                                                                        xa_in, xa_in)

        # Calculate weights and output of AND operations
        # If a=1, w = 1, otherwise, w = 0
        # If a = 1, f = 0/1, otherwise, f = 0
        for i in range(3):
            # command += "ASSERT({0}[{2}:{2}] = {1}[{2}:{2}]);\n".format(w,a,i)
            command += "ASSERT(BVLE({0}[{2}:{2}],{1}[{2}:{2}]));\n".format(f, a, i)
        if not switch:
            # w[1]=a[2]
            # AND in the L1 register
            command += "ASSERT({0}[1:1] = {1}[2:2]);\n".format(w, a)
            # As long as either 1 AND operation in L2 register is active, prob is 1
            # w[0]=a[0]|a[1]
            command += "ASSERT({0}[0:0] = {1}[0:0] | {1}[1:1]);\n".format(w, a)

        # Shift and store into xb
        # Permutation layer (shift left L2 by 1 except for position 28)
        for i in range(0, 28):
            command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(xb,
                                                                       i + 1, xa_in, i)
        # Permutation layer (shift left L1 by 1 except for position 47 (L1_12))
        for i in range(29, 47):
            command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(xb,
                                                                       i + 1, xa_in, i)

        # Perform XOR operation for to get bits for position L2_0 and 29 (L1_0)
        # x_out[0] = x[47]^x[41]^a[2]^(x[35]&IR[r])
        command += "ASSERT({0}[0:0] = BVXOR({1}[47:47],BVXOR({1}[41:41],BVXOR({2}[2:2],({1}[35:35]&0b{3})))));\n".format(
            xb, xa_in, f, IR[r + offset])
        # x_out[29] = x[28]^a[1]^x[19]^a[0]
        command += "ASSERT({0}[29:29] = BVXOR({1}[28:28],BVXOR({2}[1:1],BVXOR({1}[19:19],{2}[0:0]))));\n".format(xb,
                                                                                                                 xa_in,
                                                                                                                 f)

        # ***************************************
        # Second iteration of nonlinear functions
        # ***************************************
        # Bits 3-5 are used for a,f,w

        # Check if AND is active
        # a[3] = x[6] | x[15]
        command += "ASSERT({0}[3:3] = {1}[6:6]|{2}[15:15]);\n".format(a, xb, xb)
        # a[4] = x[13]| x[21]
        command += "ASSERT({0}[4:4] = {1}[13:13]|{2}[21:21]);\n".format(a, xb, xb)
        # Locations for L1 = 7 and 15. In full 48-bit register, 7+29 = 36, 15+29 = 44
        # a[5] = x[36] | x[44]
        command += "ASSERT({0}[5:5] = {1}[36:36]|{2}[44:44]);\n".format(a, xb, xb)

        # Calculate weights and output of AND operations
        # If a=1, w = 1, otherwise, w = 0
        # If a = 1, f = 0/1, otherwise, f = 0
        for i in range(3, 6):
            # command += "ASSERT({0}[{2}:{2}] = {1}[{2}:{2}]);\n".format(w,a,i)
            command += "ASSERT(BVLE({0}[{2}:{2}],{1}[{2}:{2}]));\n".format(f, a, i)
        if not switch:
            # w[3]=a[5]
            # AND in the L1 register
            command += "ASSERT({0}[3:3] = {1}[5:5]);\n".format(w, a)
            # As long as either 1 AND operation in L2 register is active, prob is 1
            # w[2]=a[3]|a[4]
            command += "ASSERT({0}[2:2] = {1}[3:3] | {1}[4:4]);\n".format(w, a)

        # Shift and store into xa_out
        # Permutation layer (shift left L2 by 1 except for position 28)
        for i in range(0, 28):
            command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(
                xa_out, i + 1, xb, i)
        # Permutation layer (shift left L1 by 1 except for position 47 (L1_12))
        for i in range(29, 47):
            command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(
                xa_out, i + 1, xb, i)

        # Perform XOR operation for to get bits for position L2_0 and 29 (L1_0)
        # x_out[0] = x[47]^x[41]^a[5]^(x[35]&IR[r])
        command += "ASSERT({0}[0:0] = BVXOR({1}[47:47],BVXOR({1}[41:41],BVXOR({2}[5:5],({1}[35:35]&0b{3})))));\n".format(
            xa_out, xb, f, IR[r + offset])
        # x_out[29] = x[28]^a[4]^x[19]^a[3]
        command += "ASSERT({0}[29:29] = BVXOR({1}[28:28],BVXOR({2}[4:4],BVXOR({1}[19:19],{2}[3:3]))));\n".format(xa_out,
                                                                                                                 xb, f)

        # Use 6 bits to store weight (for each of the ANDs in the 2 iteraions). The rest must be 0.
        # command += "ASSERT(0b000000000000000000000000000000000000000000000000000000000000 = {0}[63:4]);\n".format(w)
        # command += "ASSERT(0b0000000000000000000000000000000000000000000000000000000000 = {0}[63:6]);\n".format(f)
        # command += "ASSERT(0b0000000000000000000000000000000000000000000000000000000000 = {0}[63:6]);\n".format(a)

        command += "ASSERT(0b00000000000000000000000000000000000000000000 = {0}[47:4]);\n".format(
            w)
        command += "ASSERT(0b000000000000000000000000000000000000000000 = {0}[47:6]);\n".format(
            f)
        command += "ASSERT(0b000000000000000000000000000000000000000000 = {0}[47:6]);\n".format(
            a)

        # TODO: Fix the 16 MSBs to zero for all X
        # command += "ASSERT(0b0000000000000000 = {0}[63:48]);\n".format(xa_in)
        # command += "ASSERT(0b0000000000000000 = {0}[63:48]);\n".format(xa_out)
        # command += "ASSERT(0b0000000000000000 = {0}[63:48]);\n".format(xb)

        stp_file.write(command)
        return

    def pre_handle(self, param):
        if 'countered_trails' not in param:
            return ""
        characters = param["countered_trails"]
        if len(characters) == 0:
            return ""
        r = param["rounds"]
        command = "ASSERT(NOT("
        for characteristic in characters:
            trails_data = characteristic.getData()
            # input diff
            input_diff = trails_data[0][0]

            # output diff
            output_diff = trails_data[r][1]

            str1 = "(BVXOR(Xa0,{0}) | BVXOR(Ya{1}, {2}))".format(
                input_diff, r, output_diff
            )
            command += str1
            command += "&"
        command = command[:-1]
        command += "=0x000000000000));\n"
        return command

    def and_bct(self, variables):
        if len(variables) == 4:
            return "ASSERT(BVXOR({0}&{1}, {2}&{3})=0bin0);\n".format(
                variables[0], variables[1], variables[2], variables[3]
            )
        else:
            str1 = "BVXOR({0}&{1}, {2}&{3})".format(
                variables[0], variables[1], variables[2], variables[3]
            )
            str2 = "BVXOR({0}&{1}, {2}&{3})".format(
                variables[4], variables[5], variables[6], variables[7]
            )
            return "ASSERT(BVXOR({0}, {1})=0bin0);\n".format(str1, str2)

    def create_cluster_parameters(self, parameters, characteristics):
        r = parameters['rounds']
        trails_data = characteristics.getData()
        input_diff = trails_data[0][0]
        output_diff = trails_data[r][1]
        parameters["fixedVariables"]["Xa0"] = input_diff
        parameters["fixedVariables"]["Ya{}".format(r)] = output_diff

    def get_diff_hex(self, parameters, characteristics):
        switch_start_round = parameters['switchStartRound']
        switch_rounds = parameters['switchRounds']
        r = parameters['rounds']
        trails_data = characteristics.getData()
        # input diff
        input_diff = trails_data[0][0]

        # output diff
        output_diff = trails_data[r][1]

        # switch diff
        switch_input_diff = trails_data[switch_start_round][0]
        switch_output_diff = trails_data[switch_start_round + switch_rounds][1]
        return input_diff, switch_input_diff, switch_output_diff, output_diff

    def get_cluster_params(self, new_parameter, new_p, prob):
        print()
