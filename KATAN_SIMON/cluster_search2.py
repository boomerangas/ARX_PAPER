from argparse import ArgumentParser, RawTextHelpFormatter
import yaml
from ciphers import katan32bct, simonbct, katan48bct, katan64bct
import time
import util
import random
from cryptanalysis import search
import copy
import math
import uuid
import os
from config import (USE_SHARP)
import re

START_WEIGHT = {"simon32": {10: 13, 13: 24}}

CIPHER_MAPPING = {"katan32BCT": katan32bct.katan32(),
                  "simon": simonbct.SimonCipher(),
                  "katan48BCT": katan48bct.katan48(),
                  "katan64BCT": katan64bct.katan64()}

RESULT_DIC = {'simon': "simon_result/", "katan32BCT": "katan32_result/", "katan48BCT": "katan48_result/",
              "katan64BCT": "katan64_result/"}
TEMP_DIC = "tmp/"


def check_solutions(new_parameter, cipher, threshold, cluster_count):
    if 'countered_trails' in new_parameter:
        new_parameter['countered_trails'].clear()
    prob = 0
    start_time = str(uuid.uuid4())
    stp_file = TEMP_DIC + "{}{}-{}.stp".format(cipher.name, "clutesr", start_time)
    last_weight = 0
    count = 1
    cluster_counter = 0
    new_parameter['cluster'] = 1
    ori_w = new_parameter['sweight']
    while count < threshold and cluster_counter < cluster_count:
        cluster_counter += 1
        new_weight = last_weight
        cipher.createSTP(stp_file, new_parameter)

        # Start solver
        sat_process = search.startSATsolver(stp_file)

        # Find the number of solutions with the SAT solver
        print("Finding all trails of weight {}".format(new_parameter["sweight"]))

        # Watch the process and count solutions
        solutions = 0
        while sat_process.poll() is None:
            lines = sat_process.stdout.readlines()
            if USE_SHARP == 1:
                done = False
                for line in lines:
                    if "exact arb" in line.decode("utf-8"):
                        done = True
                if not done:
                    continue
                line = lines[len(lines) - 1].decode("utf-8")
                pattern = re.compile('\d+')
                solutions += int(pattern.search(line).group())
            else:
                for line in lines:
                    if "s SATISFIABLE" in line.decode("utf-8"):
                        solutions += 1
        if solutions > 0:
            solutions /= 2
            print("\n\tSolutions: {}".format(solutions))
            new_p = math.pow(2, -new_parameter["sweight"] * 2) * solutions
            prob += new_p
            new_weight = int(math.log2(prob))
            # if new_weight < -37:
            #     break
            report_str = "boomerang weight: {0}, rectangle weight:{1}".format(-ori_w * 2,
                                                                              math.log2(prob))
            print(report_str)
            cipher.get_cluster_params(new_parameter, new_p, prob)
        if prob > 1:
            prob = 1
            break
        new_parameter['sweight'] += 1
        # print("Cluster Searching Stage|Current Weight:{0}".format(new_weight))
        if new_weight == last_weight:
            count += 1
        else:
            last_weight = new_weight
            count = 1
    return prob


SWITCH_R = 0
WEIGHT = 0


def find_single_trail(cipher, r, lunch_arg):
    global WEIGHT, SWITCH_R
    result_dic = RESULT_DIC[cipher.name]
    task_start_time = time.time()
    valid_count = 0
    save_file = result_dic + "{0}-{1}.txt".format(cipher.name, r)
    save_list_file = result_dic + "{0}-{1}-LIST.txt".format(cipher.name, r)
    result_file = open(save_file, "w")
    result_list_file = open(save_list_file, 'w')
    params = copy.deepcopy(lunch_arg)
    each_round_max_valid = int(lunch_arg['eachRoundMaxValid'])
    each_round_max_time = int(lunch_arg['eachRoundMaxTime']) * 3600
    rnd_string_tmp = "%030x" % random.randrange(16 ** 30)
    stp_file = TEMP_DIC + "{0}-{1}-{2}.stp".format(cipher.name, rnd_string_tmp, r)
    detail_list = []
    check_list = []
    switch_round1 = 2
    while valid_count < each_round_max_valid and time.time() - task_start_time < each_round_max_time:
        if switch_round1 > r - 2:
            break
        params["switchStartRound"] = switch_round1
        if params['sweight'] >= lunch_arg['endweight']:
            break
        cipher.createSTP(stp_file, params)
        if params["boolector"]:
            result = search.solveBoolector(stp_file)
        else:
            result = search.solveSTP(stp_file)
        if not search.foundSolution(result):
            # print(
            #     "Rounds:{1}, No trails, weight:{0}\n".format(
            #         params["sweight"], params["rounds"]
            #     )
            # )
            params["sweight"] += 1
            continue

        characteristic = search.parsesolveroutput.getCharSTPOutput(result, cipher, params["rounds"])
        print("Rounds:{0}, switch start r:{1}, weight:{2}".format(r, params["switchStartRound"], params['sweight']))
        params["sweight"] = 0
        if WEIGHT == 0:
            WEIGHT = params['sweight']
            SWITCH_R = switch_round1
        elif WEIGHT > params['sweight']:
            WEIGHT = params['sweight']
            SWITCH_R = switch_round1
        switch_round1 += 1
        # params["countered_trails"].append(characteristic)
    print(SWITCH_R)
    print(WEIGHT)


def start_search(lunch_arg):
    cipher_name = lunch_arg['cipher']
    cipher = CIPHER_MAPPING[cipher_name]
    util.makedirs([RESULT_DIC[cipher_name], TEMP_DIC])
    start_round = lunch_arg['startRound']
    end_round = lunch_arg['endRound']
    end_round = start_round + 1 if end_round == -1 else end_round
    switch_rounds = lunch_arg['switchRounds']
    params = copy.deepcopy(lunch_arg)
    for r in range(start_round, end_round):
        start_weight = 0
        for i in range(r, -1, -1):
            if i in START_WEIGHT:
                start_weight = START_WEIGHT[i]
                break
        params['rounds'] = r
        find_single_trail(cipher, r, params)


def loadparameters(args):
    """
    Get parameters from the argument list and inputfile.
    """
    # Load default values
    params = {"cipher": "simon",
              "startRound": 5,
              "endRound": -1,
              "switchRounds": 4,
              "threshold": 6,
              "eachRoundMaxTime": 60 * 60 * 5,
              "eachRoundMaxValid": 2,
              "wordsize": 16,
              "blocksize": 64,
              "sweight": 0,
              "endweight": 1000,
              "iterative": False,
              "boolector": False,
              "dot": None,
              "latex": None,
              "nummessages": 1,
              "timelimit": -1,
              "fixedVariables": {},
              "blockedCharacteristics": []}

    # Check if there is an input file specified
    if args.inputfile:
        with open(args.inputfile[0], 'r') as input_file:
            doc = yaml.load(input_file, Loader=yaml.Loader)
            params.update(doc)
            if "fixedVariables" in doc:
                fixed_vars = {}
                for variable in doc["fixedVariables"]:
                    fixed_vars = dict(list(fixed_vars.items()) +
                                      list(variable.items()))
                params["fixedVariables"] = fixed_vars

    return params


def main():
    parser = ArgumentParser(description="This tool finds the best differential"
                                        "trail in a cryptopgrahic primitive"
                                        "using STP and CryptoMiniSat.",
                            formatter_class=RawTextHelpFormatter)

    parser.add_argument('--inputfile', nargs=1, help="Use an yaml input file to"
                                                     "read the parameters.")

    args = parser.parse_args()
    params = loadparameters(args)
    start_search(params)


if __name__ == '__main__':
    main()
