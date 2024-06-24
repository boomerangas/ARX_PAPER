The part of this repository is about the boomerang attacks on AND-based ciphers.

### Experimental Environments Setup:

1. Install [STP](https://github.com/stp/stp).
2. Install [Cryptominisat](https://github.com/msoos/cryptominisat/).
3. Setting paths of STP and Cryptominisat on the  file ```config.py```.
4. ```pip3 install pyyaml```

### How to run the code:

1. KATAN32: ```python3 cluster_search.py --inputfile katan32.yml```
2. SIMON32/64: ```python3 cluster_search.py --inputfile simon32.yml```
3. The results are in ```/xxxx_results``` folders.


Oringal repository: https://github.com/kste/cryptosmt