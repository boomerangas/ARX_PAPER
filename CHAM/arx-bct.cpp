#include <iostream>
#include <stdio.h>
using namespace std;

typedef uint8_t word_t;

int main(int argc, char * argv[]) {

    if (argc != 4) {
        printf("Please enter all target differences. E.g. ./ABCT-ori.elf 1 1 1\n");
        exit(0);
    }

    word_t delta_i = atoi(argv[1]);
    word_t delta_ip = atoi(argv[2]);
    word_t delta_o = atoi(argv[3]);

    uint64_t BCT[8][8][8]={{0},{0},{0}};

    word_t x, xp, diff;
    for(word_t Di=0; Di<=7; Di++)
        for(word_t Dip=0; Dip<=7; Dip++)
            for(word_t Do=0; Do<=7; Do++)
                for (word_t x=0; x<=7; x++)
                    for (word_t xp=0; xp<=7; xp++)
                    {   //((x+xp)^Do-xp)
                        word_t x3 = ( (((x+xp)%8) ^ Do) - xp);
                        x3 = x3%8;
                        // ((x^Di)+(xp^Dip))^Do
                        word_t exp2 = (((x^Di) + (xp^Dip))%8) ^ Do;
                        word_t exp3 = xp^Dip;
                        word_t exp4 = exp2 - exp3;
                        exp4 = exp4 % 8;
                        diff = x3 ^ exp4;
                        if (diff == Di)
                            BCT[Di][Dip][Do]++;
                    }
    printf("BCT[%x][%x][%x]=%ld\n", delta_i, delta_ip, delta_o, BCT[delta_i][delta_ip][delta_o]);
    
}
