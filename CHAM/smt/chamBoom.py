'''
Created on Jul 21, 2022

@author: je sen
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher

from parser.stpcommands import getStringRightRotate as rotr
from parser.stpcommands import getStringLeftRotate as rotl


class ChamBoom(AbstractCipher):
    """
    Finds a deterministic sandwich distinguisher based on ladder switch for CHAM in truncated form
    """

    name = "chamboom"

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['X0', 'X1', 'X2', 'X3', 'Y0', 'Y1', 'Y2', 'Y3']
        #X represents upper trail, Y represents lower trail

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a deterministic sandwich distinguisher
        Performs a search for two trails, where the two trails must never overlap in the active addition operation
        """
        wordsize = 1 # Use 1 bit to represent an active or inactive 16-bit word
        rounds = parameters["rounds"]
        weight = parameters["sweight"] #Weight represents number of overlaps
        sround = parameters["sround"]

        with open(stp_filename, 'w') as stp_file:
            stp_file.write("% Input File for boomerang STP\n% CHAM w={} "
                           "rounds={} start round={}\n\n\n".format(wordsize, rounds,sround))

            # Setup variable
            # w = weight
            x0 = ["X0{}".format(i) for i in range(sround, sround+rounds + 1)]
            x1 = ["X1{}".format(i) for i in range(sround, sround+rounds + 1)]
            x2 = ["X2{}".format(i) for i in range(sround, sround+rounds + 1)]
            x3 = ["X3{}".format(i) for i in range(sround, sround+rounds + 1)]
            y0 = ["Y0{}".format(i) for i in range(sround, sround+rounds + 1)]
            y1 = ["Y1{}".format(i) for i in range(sround, sround+rounds + 1)]
            y2 = ["Y2{}".format(i) for i in range(sround, sround+rounds + 1)]
            y3 = ["Y3{}".format(i) for i in range(sround, sround+rounds + 1)]
            # x0x1 = ["X0X1{}".format(i) for i in range(sround, sround+rounds + 1)]
            # y0y1 = ["Y0Y1{}".format(i) for i in range(sround, sround+rounds + 1)]
            w = ["w{}".format(i) for i in range(sround, sround+rounds)]

            stpcommands.setupVariables(stp_file, x0, 1)
            stpcommands.setupVariables(stp_file, x1, 1)
            stpcommands.setupVariables(stp_file, x2, 1)
            stpcommands.setupVariables(stp_file, x3, 1)
            
            stpcommands.setupVariables(stp_file, y0, 1)
            stpcommands.setupVariables(stp_file, y1, 1)
            stpcommands.setupVariables(stp_file, y2, 1)
            stpcommands.setupVariables(stp_file, y3, 1)
            
            # stpcommands.setupVariables(stp_file, x0x1, 1)
            stpcommands.setupVariables(stp_file, w, wordsize)

            # AA = Active AND
            stpcommands.setupAAComputation(stp_file, weight, w, wordsize)
            # rot_x0 = 0
            # rot_x1 = 0
            for i in range(rounds):
                # if ((i+1) % 2) == 0:    #even rounds
                    # rot_x1 = 8
                    # rot_x0 = 1
                # else:                   #odd rounds
                    # rot_x1 = 1
                    # rot_x0 = 8

                self.setupCHAMRound(stp_file, x0[i], x1[i], x2[i], x3[i],
                                    x0[i+1], x1[i+1], x2[i+1], x3[i+1], 
                                    y0[i], y1[i], y2[i], y3[i],
                                    y0[i+1], y1[i+1], y2[i+1], y3[i+1],
                                    w[i], wordsize)

            # No all zero characteristic
            stpcommands.assertNonZero(stp_file, x0 + x1 + x2 + x3, wordsize)
            stpcommands.assertNonZero(stp_file, y0 + y1 + y2 + y3, wordsize)

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, wordsize)

            stpcommands.setupQuery(stp_file)

        return
    
    #The following is a truncated search in "standard model" where cancellations may occur
    def setupCHAME0Round(self, stp_file, x0_in, x1_in, x2_in, x3_in,
                       x0_out, x1_out, x2_out, x3_out,
                       y0_in, y1_in, y2_in, y3_in,
                       y0_out, y1_out, y2_out, y3_out,
                       w, wordsize):
        """
        Model for differential behaviour of one round CHAM (E0)
        """
        command = ""
        
        #Rotate Words
        command += "ASSERT({0} = {1});\n".format(x0_out, x1_in)
        command += "ASSERT({0} = {1});\n".format(x1_out, x2_in)
        command += "ASSERT({0} = {1});\n".format(x2_out, x3_in)
        
        #E0 does not need y
        # command += "ASSERT({0} = {1});\n".format(y0_out, y1_in)
        # command += "ASSERT({0} = {1});\n".format(y1_out, y2_in)
        # command += "ASSERT({0} = {1});\n".format(y2_out, y3_in)
        
        command += "ASSERT((~{0}&~{1}&~{2})|({0}&~{1}&{2})|({0}&{1}&~{2})|({0}&{1}&{2})|(~{0}&{1}&{2}) = 0b1);\n".format(x3_out, x0_in, x1_in)
        
        #command += "ASSERT({0} = {1}|{2});\n".format(y0_in, y3_out , y1_in)
        
        #Calculate number of active ANDs
        command += "ASSERT({0}|{1} = {2});\n".format(x0_in, x1_in, w)

        stp_file.write(command)
    
    #The following aims to minimize the number of overlapping AND/SUB
    def setupCHAMRound(self, stp_file, x0_in, x1_in, x2_in, x3_in,
                       x0_out, x1_out, x2_out, x3_out,
                       y0_in, y1_in, y2_in, y3_in,
                       y0_out, y1_out, y2_out, y3_out,
                       w, wordsize):
        """
        Model for differential behaviour of one round CHAM
        """
        command = ""
        
        #Rotate Words
        command += "ASSERT({0} = {1});\n".format(x0_out, x1_in)
        command += "ASSERT({0} = {1});\n".format(x1_out, x2_in)
        command += "ASSERT({0} = {1});\n".format(x2_out, x3_in)
        
        command += "ASSERT({0} = {1});\n".format(y0_out, y1_in)
        command += "ASSERT({0} = {1});\n".format(y1_out, y2_in)
        command += "ASSERT({0} = {1});\n".format(y2_out, y3_in)
        
        #Addition operation (If any word is active, output is 1)
        command += "ASSERT({0} = {1}|{2});\n".format(x3_out, x0_in, x1_in)
        command += "ASSERT({0} = {1}|{2});\n".format(y0_in, y3_out , y1_in)
        
        #Compute number of overlaps (stored in w)
        command += "ASSERT({0}&{1} = {2});\n".format(x3_out, y0_in, w)

        stp_file.write(command)
        
    
