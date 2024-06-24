# arx-bct
Revisiting Boomerang Connectivity for ARX Ciphers

Run ``make all`` to compile all files.

toy-exp.cpp - Experimentally derive boomerang probability for various scenarios (verification of correctness)

toy-eval.cpp - Derive boomerang probability for the 2-round switch using ABCT (verification of correctness)

test.sh - Compute boomerang probability for all 2-round switches to be compared with toy-exp (verification of correctness)

arx-bdti.cpp - Generate ABDT

arx-bct-2.cpp - Generate ABCT

arx-bct.cpp - Generate original ABCT (with fixed addends)
