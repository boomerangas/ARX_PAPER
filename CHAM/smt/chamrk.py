'''
Created on Aug 25, 2022

@author: Je Sen

Note that a new parameter "sround" needs to be included into CryptoSMT
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher

from parser.stpcommands import getStringRightRotate as rotr
from parser.stpcommands import getStringLeftRotate as rotl


class CHAMRKCipher(AbstractCipher):
    """
    Represents the related-key differential behaviour of CHAM and can be used
    to find differential characteristics for the given parameters.
    """

    name = "chamrk"

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['X0', 'X1', 'X2', 'X3', 'RK', 'K', 'w']

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for CHAM with
        the given parameters.
        """
        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]
        sround = parameters["sround"]
        print("Starting from round {}".format(sround))
        with open(stp_filename, 'w') as stp_file:
            stp_file.write("% Input File for STP\n% Related-key CHAM w={} "
                           "rounds={} start round={}\n\n\n".format(wordsize, rounds,sround))

            # Setup variable
            # w = weight
            x0 = ["X0{}".format(i) for i in range(0, rounds + 1)]
            x1 = ["X1{}".format(i) for i in range(0, rounds + 1)]
            x2 = ["X2{}".format(i) for i in range(0, rounds + 1)]
            x3 = ["X3{}".format(i) for i in range(0, rounds + 1)]
            x0x1 = ["X0X1{}".format(i) for i in range(0, rounds + 1)]
            w = ["w{}".format(i) for i in range(0, rounds)]
            rk = ["RK{}".format(i) for i in range(0, 16)] #Only 16 key words derived from master key
            MK = ["K{}".format(i) for i in range(0, 8)] #Only 16 key words derived from master key

            stpcommands.setupVariables(stp_file, x0, wordsize)
            stpcommands.setupVariables(stp_file, x1, wordsize)
            stpcommands.setupVariables(stp_file, x2, wordsize)
            stpcommands.setupVariables(stp_file, x3, wordsize)
            stpcommands.setupVariables(stp_file, x0x1, wordsize)
            stpcommands.setupVariables(stp_file, w, wordsize)
            stpcommands.setupVariables(stp_file, rk, wordsize)
            stpcommands.setupVariables(stp_file, MK, wordsize)

            self.setupRK(stp_file, MK, rk, wordsize)    
            
            # Ignore MSB
            stpcommands.setupWeightComputation(stp_file, weight, w, wordsize, 1)
            rot_x0 = 0
            rot_x1 = 0
            for i in range(0,rounds):
                if ((i+sround+1) % 2) == 0:    #even rounds
                    rot_x1 = 8
                    rot_x0 = 1
                else:                   #odd rounds
                    rot_x1 = 1
                    rot_x0 = 8
                   
                index = (i+sround)%16
                self.setupCHAMRound(stp_file, x0[i], x1[i], x2[i], x3[i],
                                    x0[i+1], x1[i+1], x2[i+1], x3[i+1], x0x1[i],
                                    rot_x0, rot_x1, w[i], rk[index], wordsize)

            # No all zero characteristic
            temp = [x0[0], x1[0], x2[0], x3[0]]
            stpcommands.assertNonZero(stp_file, temp,wordsize)
            stpcommands.assertNonZero(stp_file, x0 + x1 + x2 + x3, wordsize)

            # Iterative characteristics only
            # Input difference = Output difference
            if parameters["iterative"]:
                stpcommands.assertVariableValue(stp_file, x0[0], x0[rounds])
                stpcommands.assertVariableValue(stp_file, x1[0], x1[rounds])
                stpcommands.assertVariableValue(stp_file, x2[0], x2[rounds])
                stpcommands.assertVariableValue(stp_file, x3[0], x3[rounds])

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, wordsize)

            stpcommands.setupQuery(stp_file)

        return

    def setupRK(self, stp_file, MK, rk, wordsize):
        """
        Set up related key schedule
        """
        command = ""
        for i in range(0, 8):
            index = (i+8)^1
            command += "ASSERT({0} = BVXOR(BVXOR({1},{1}[14:0]@{1}[15:15]),{1}[7:0]@{1}[15:8]));\n".format(rk[i], MK[i])
            command += "ASSERT({0} = BVXOR(BVXOR({1},{1}[14:0]@{1}[15:15]),{1}[4:0]@{1}[15:5]));\n".format(rk[index], MK[i])
        
        stp_file.write(command)
        
        return
    
    def setupCHAMRound(self, stp_file, x0_in, x1_in, x2_in, x3_in,
                       x0_out, x1_out, x2_out, x3_out, x0x1,
                       rot_x0, rot_x1, w, rk, wordsize):
        """
        Model for differential behaviour of one round CHAM
        """
        command = ""

        # even rounds:
        # X_{i+1}[3] = (X_{i}[0] + (X_{i}[1] << 1)) << 8
        # odd rounds:
        # X_{i+1}[3] = (X_{i}[0] + (X_{i}[1] << 8)) << 1
        
        val = "BVXOR({0},{1})".format(rk,rotl(x1_in,rot_x1,wordsize))

        command += "ASSERT("
        # command += stpcommands.getStringAdd(
                                            # rotl(x1_in,
                                                 # rot_x1,
                                                 # wordsize),
                                            # x0_in,
                                            # x0x1,
                                            # wordsize)
        command += stpcommands.getStringAdd(val,
                                            x0_in,
                                            x0x1,
                                            wordsize)
                                            
        command += ");\n"

        command += "ASSERT({0} = {1});\n".format(x3_out, rotl(x0x1, rot_x0, wordsize))

        # X_{i+1}[2] = X_{i+1}[3]
        # X_{i+1}[1] = X_{i+1}[2]
        # X_{i+1}[0] = X_{i+1}[1]
        command += "ASSERT({0} = {1});\n".format(x2_out, x3_in)
        command += "ASSERT({0} = {1});\n".format(x1_out, x2_in)
        command += "ASSERT({0} = {1});\n".format(x0_out, x1_in)

        #For weight computation
        command += "ASSERT({0} = ~".format(w)
        command += stpcommands.getStringEq(x0_in,
                                           val,
                                           x0x1)
        command += ");\n"

        stp_file.write(command)
        return
