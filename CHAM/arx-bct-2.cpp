#include <iostream>
#include <stdio.h>
using namespace std;

typedef uint8_t word_t;
#define size 8
int main(int argc, char * argv[]) {

    /*
        d0, dp, n0, np (delta_0, delta_0_p, nabla_0, nabla_0_p)
    */

    if (argc != 5) {
        printf("Please enter all target differences. E.g. ./ABCT.elf 1 1 1 1\n");
        exit(0);
    }
    word_t d_i = atoi(argv[1]);
    word_t d_ip = atoi(argv[2]);
    word_t d_o = atoi(argv[3]);
    word_t d_op = atoi(argv[4]);

    uint64_t BCT[size][size][size][size]={{0},{0},{0},{0}};

    word_t x, xp, diff;
    for(word_t d0=0; d0<size; d0++)
        for(word_t dp=0; dp<size; dp++)
            for(word_t n0=0; n0<size; n0++)
                for (word_t np=0; np<size; np++)
                    for (word_t x=0; x<size; x++)
                        for (word_t xp=0; xp<size; xp++)
                        {   //x3=((x+xp)^n0)-(xp^np)
                            word_t x3 = ((((x+xp)%size) ^ n0) - (xp^np));
                            x3 = x3%size; //Modular sub
                            //x4=(((x^d0)+(xp^dp))^n0)-(xp^dp^np)
                            word_t x4 = ((((x^d0)+(xp^dp))%size)^n0) - (xp^dp^np);
                            x4 = x4%size; //Modular sub
                            diff = x3^x4;
                            if (diff == d0)
                                BCT[d0][dp][n0][np]++;
                        }

    printf("ABCT[%x][%x][%x][%x]=%ld\n", d_i, d_ip, d_o, d_op, BCT[d_i][d_ip][d_o][d_op]);

}