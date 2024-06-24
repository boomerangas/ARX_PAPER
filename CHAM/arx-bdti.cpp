#include <iostream>
#include <stdio.h>
#include <math.h>
using namespace std;

typedef uint8_t word_t;
#define size 8

#define ROTL3_1(x) (((x)<<(1)) | (x>>(3-(1)))) & 0x7
#define ROTR3_1(x) (((x)>>(1)) | ((x)<<(3-(1)))) & 0x7
#define ROTL3_2(x) (((x)<<(2)) | (x>>(3-(2)))) & 0x7
#define ROTR3_2(x) (((x)>>(2)) | ((x)<<(3-(2)))) & 0x7

#define ROL1 ROTL3_1
#define ROL2 ROTL3_2
#define ROR1 ROTR3_1
#define ROR2 ROTR3_2

int main(int argc, char * argv[]) {

    /*
        d0, dp, n0, np (delta_0, delta_0_p, nabla_0, nabla_0_p)
    */

    if (argc != 6) {
        printf("Please enter all target differences. E.g. ./ABDTi.elf 1 1 1 1 1\n");
        exit(0);
    }
    word_t d_i = atoi(argv[1]);
    word_t d_ip = atoi(argv[2]);
    word_t d_o = atoi(argv[3]);
    word_t d_op = atoi(argv[4]);
    word_t d_oo = atoi(argv[5]);

    uint64_t BDT[size][size][size][size][size]={{0},{0},{0},{0},{0},{0}};

    word_t x, xp, diff;
    for(word_t d0=0; d0<size; d0++)
        for(word_t dp=0; dp<size; dp++)
            for(word_t n0=0; n0<size; n0++)
                for (word_t np=0; np<size; np++)
                    for (word_t x=0; x<size; x++)
                        for (word_t xp=0; xp<size; xp++)
                        {   //x3=((x+xp)^n0)-(xp^np)
                            word_t y1 = (x+xp)%size;
                            word_t y3 = y1 ^ n0;
                            word_t x3 = (y3 - (xp^np));
                            x3 = x3%size; //Modular sub

                            //x4=(((x^d0)+(xp^dp))^n0)-(xp^dp^np)
                            word_t x2 = x^d0;
                            word_t x2p = xp^dp;
                            word_t y2 = (x2+x2p)%size;
                            word_t x4 = (y2^n0) - (xp^dp^np);
                            x4 = x4%size; //Modular sub
                            diff = x3^x4;
                            if (diff == d0)
                                for (word_t n1=0; n1<size; n1++) {
                                    // if ( ((x^x3)==n1) && ((x2^x4)==n1) )
                                    if ((x^x3)==n1)
                                        BDT[d0][dp][n0][np][n1]++;
                                }
                        }
    double sum = 0;

    printf("BDTi[%x][%x][%x][%x][%x]=%ld\n", d_i, d_ip, d_o, d_op, d_oo, BDT[d_i][d_ip][d_o][d_op][d_oo]);


}