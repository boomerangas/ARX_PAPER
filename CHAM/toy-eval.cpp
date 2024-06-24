/*
Uses ABDTi to evaluate the 2-round (non-deterministic) boomerang switch
Just enter the values for a and b.
*/

#include <iostream>
#include <math.h>
#include <stdio.h>
using namespace std;

#define ROTL3_1(x) (((x)<<(1)) | (x>>(3-(1)))) & 0x7
#define ROTR3_1(x) (((x)>>(1)) | ((x)<<(3-(1)))) & 0x7
#define ROTL3_2(x) (((x)<<(2)) | (x>>(3-(2)))) & 0x7
#define ROTR3_2(x) (((x)>>(2)) | ((x)<<(3-(2)))) & 0x7

#define ROL1 ROTL3_1
#define ROL2 ROTL3_2
#define ROR1 ROTR3_1
#define ROR2 ROTR3_2

typedef uint8_t word_t;
#define size 8
int main(int argc, char * argv[]) {

    /*
        d0, dp, n0, np (delta_0, delta_0_p, nabla_0, nabla_0_p)
    */
    if (argc != 3) {
        printf("Please enter the values for differences a and b. E.g. ./eval.elf 4 4\n");
        exit(0);
    }
    word_t alpha = atoi(argv[1]);
    word_t beta = atoi(argv[2]);

    double prob = 0;
    uint64_t ABDTi[size][size][size][size][size]={{0},{0},{0},{0},{0}};
    uint64_t ABCT[size][size][size][size]={{0},{0},{0},{0}};
    word_t x, xp, diff;

    //ABDTi
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
                                        ABDTi[d0][dp][n0][np][n1]++;
                                }
                        }
    //ABCT                  
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
                                ABCT[d0][dp][n0][np]++;
                        }
    word_t betar2 = ROR2(beta); //Rotate beta right by 2
    uint32_t valid[8] = {0};
    double R4Prob = 0;
    double total; //Keeps track of all possible transitions
        for (int j=0; j<size; j++) {
            uint32_t temp = ABDTi[alpha][0][betar2][0][j];
            R4Prob+=temp;
            if (temp) {
                // printf("ABDTi[%x][0][%x][0][%x]=%ld | ", alpha, betar2, j, ABDTi[alpha][0][betar2][0][j]);
                word_t betap = ROL2(j);
                // printf("After ROL2: %x->%x\n", j, betap);
                valid[betap]+=temp;
                total+=temp;
            }
        }
    R4Prob = R4Prob/64;
    // printf("Total = %lf, %lf\n---\n", total, log2(R4Prob));

    word_t alphal2 = ROL2(alpha);
    double switch_prob;
    for (int i=0; i<8; i++) {
        double roundProb;
        switch_prob = 0;
        if (valid[i]) {
                switch_prob=ABCT[0][alphal2][0][i]/64.0;
        }
        roundProb = (valid[i]/total)*switch_prob;
        prob+=roundProb;
    }
    printf("Prob of success = %lf\n", log2(prob*R4Prob));
}
