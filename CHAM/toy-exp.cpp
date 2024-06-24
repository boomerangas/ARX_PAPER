/* 
Toy cipher with 3-bit additions/subtractions
*/

#include <cstdio>
#include <vector>
#include <math.h>
#include <cassert>
#include <stdlib.h>     /* srand, rand */
#include <time.h>       /* time */
#include <cstdint> // include this header for uint64_t

using namespace std;

#define word_t uint32_t
#define ROTL16(x,r) (((x)<<(r)) | (x>>(16-(r))))
#define ROTR16(x,r) (((x)>>(r)) | ((x)<<(16-(r))))
#define ROTL16_1(x) (((x)<<(1)) | (x>>(16-(1))))
#define ROTR16_1(x) (((x)>>(1)) | ((x)<<(16-(1))))
#define ROTL16_8(x) (((x)<<(8)) | (x>>(16-(8))))
#define ROTR16_8(x) (((x)>>(8)) | ((x)<<(16-(8))))
#define ROTL16_11(x) (((x)<<(11)) | (x>>(16-(11))))
#define ROTR16_11(x) (((x)>>(11)) | ((x)<<(16-(11)))) 

#define ROTL3_1(x) (((x)<<(1)) | (x>>(3-(1)))) & 0x7
#define ROTR3_1(x) (((x)>>(1)) | ((x)<<(3-(1)))) & 0x7
#define ROTL3_2(x) (((x)<<(2)) | (x>>(3-(2)))) & 0x7
#define ROTR3_2(x) (((x)>>(2)) | ((x)<<(3-(2)))) & 0x7

#define ROL1 ROTL3_1
#define ROL2 ROTL3_2
#define ROR1 ROTR3_1
#define ROR2 ROTR3_2


#define ER16_0(a,b,k,i) (a^=i, b=ROTL16_1(b), b^=k, a+=b, a=ROTL16_8(a)) 
#define DR16_0(a,b,k,i) (a=ROTR16_8(a), b = ROTL16_1(b), b^=k, a-=b, a^=i)

#define ER16_1(a,b,k,i) (a^=i, b=ROTL16_8(b), b^=k, a+=b, a=ROTL16_1(a))  
#define DR16_1(a,b,k,i) (a=ROTR16_1(a), b = ROTL16_8(b), b^=k, a-=b, a^=i)

#define MAX 8 //2^3

//Modular addition/subtraction
word_t sub(word_t a, word_t b)
{
    a-=b;
    return a%MAX;
}

word_t add(word_t a, word_t b)
{
    return (a+b)%MAX;
}

#define offset 8

#define ER0(a,b,k,i) ER16_0(a,b,k,i)
#define ER1(a,b,k,i) ER16_1(a,b,k,i)
#define DR0(a,b,k,i) DR16_0(a,b,k,i)
#define DR1(a,b,k,i) DR16_1(a,b,k,i)

//32 rounds max
word_t ks[32] = {};

void keySchedule(uint32_t seed, uint32_t nrounds) { //Generate a random master key based on a given seed
    srand (seed); 
    for (int i=0; i<32; i++) {
        ks[i] = rand()%MAX;
    }
}

void encrypt(word_t *pt, int nrounds, int odd) {
    word_t temp[4]; //Word indexes 0,1,2,3

    for (int i=0; i<nrounds; i++) {
        temp[0] = pt[1];
        temp[1] = pt[2];
        temp[2] = pt[3];
        if ((i%2)==odd) {
            temp[3] = add(pt[0]^ks[i], ROL1(pt[1]));
            pt[3] = ROL2(temp[3]);
        } else {
            temp[3] = add(pt[0]^ks[i], ROL2(pt[1]));
            pt[3] = ROL1(temp[3]);
        }
        pt[0] = temp[0];
        pt[1] = temp[1];
        pt[2] = temp[2];
    }
}
void encryptPair(word_t *pt1, word_t *pt2, int nrounds) {
    word_t temp[4]; //Word indexes 0,1,2,3
    word_t tmp;
    for (int i=0; i<nrounds; i++) {
        //Pt1
        temp[0] = pt1[1];
        temp[1] = pt1[2];
        temp[2] = pt1[3];
        if (i%2) {
            // printf("E_R%d ROL1 Addends = (%x,%x) : %x, %x = ",i, ROL1(pt1[1]),ROL1(pt2[1]), pt1[0]^pt2[0],ROL1(pt1[1])^ROL1(pt2[1]));
            temp[3] = add(pt1[0]^ks[i], ROL1(pt1[1]));
            tmp = temp[3];
            pt1[3] = ROL2(temp[3]);
        } else {
            // printf("E_R%d ROL2 Addends = (%x,%x) : %x, %x = ",i, ROL2(pt1[1]),ROL2(pt2[1]), pt1[0]^pt2[0],ROL2(pt1[1])^ROL2(pt2[1]));
            temp[3] = add(pt1[0]^ks[i], ROL2(pt1[1]));
            tmp = temp[3];
            pt1[3] = ROL1(temp[3]);
        }
        pt1[0] = temp[0];
        pt1[1] = temp[1];
        pt1[2] = temp[2];

        //Pt2
        temp[0] = pt2[1];
        temp[1] = pt2[2];
        temp[2] = pt2[3];
        if (i%2) {
            temp[3] = add(pt2[0]^ks[i], ROL1(pt2[1]));
            tmp ^= temp[3];
            pt2[3] = ROL2(temp[3]);
        } else {
            temp[3] = add(pt2[0]^ks[i], ROL2(pt2[1]));
            tmp ^= temp[3];
            pt2[3] = ROL1(temp[3]);
        }
        // printf("%x\n", tmp);
        pt2[0] = temp[0];
        pt2[1] = temp[1];
        pt2[2] = temp[2];        
        //printf("EncD = %x, %x, %x, %x\n", pt1[0]^pt2[0], pt1[1]^pt2[1], pt1[2]^pt2[2], pt1[3]^pt2[3]);

    }
}


void decrypt(word_t *ct, int nrounds, int odd) {
    word_t temp[4]; //Word indexes 0,1,2,3

    for (int i=nrounds-1; i>=0; i--) {
        if ((i%2)==odd) {
            temp[0] = sub(ROR2(ct[3]),ROL1(ct[0]))^ks[i];
        } else {
            temp[0] = sub(ROR1(ct[3]),ROL2(ct[0]))^ks[i];
        }
        temp[1] = ct[0];
        temp[2] = ct[1];
        temp[3] = ct[2];
        ct[0] = temp[0];
        ct[1] = temp[1];
        ct[2] = temp[2];
        ct[3] = temp[3];
    }
}

void decryptPair(word_t *ct1, word_t *ct2, int nrounds) {
    word_t temp[4]; //Word indexes 0,1,2,3
    word_t tmp;
    for (int i=nrounds-1; i>=0; i--) {
        //Ct1
        if (i%2) {
            // printf("D_R%d ROR2 ROL1 In = (%x,%x), SUBends = (%x,%x) : n0 = %x, np0 = %x, n1 = ",i,ROR2(ct1[3]),ROR2(ct2[3]), ROL1(ct1[0]),ROL1(ct2[0]), ROR2(ct1[3])^ROR2(ct2[3]),ROL1(ct1[0])^ROL1(ct2[0]));
            temp[0] = sub(ROR2(ct1[3]),ROL1(ct1[0]))^ks[i];
        } else {
            // printf("D_R%d ROR1 ROL2 In = (%x,%x), SUBends = (%x,%x) : n0 = %x, np0 = %x, n1 = ",i,ROR1(ct1[3]),ROR1(ct2[3]), ROL2(ct1[0]),ROL2(ct2[0]),  ROR1(ct1[3])^ROR1(ct2[3]),ROL2(ct1[0])^ROL2(ct2[0]));
            temp[0] = sub(ROR1(ct1[3]),ROL2(ct1[0]))^ks[i];
        }
        tmp = temp[0];
        temp[1] = ct1[0];
        temp[2] = ct1[1];
        temp[3] = ct1[2];
        ct1[0] = temp[0];
        ct1[1] = temp[1];
        ct1[2] = temp[2];
        ct1[3] = temp[3];

        //Ct2
        if (i%2) {
            temp[0] = sub(ROR2(ct2[3]),ROL1(ct2[0]))^ks[i];
        } else {
            temp[0] = sub(ROR1(ct2[3]),ROL2(ct2[0]))^ks[i];
        }
        tmp ^= temp[0];
        // printf("%x\n", tmp);
        temp[1] = ct2[0];
        temp[2] = ct2[1];
        temp[3] = ct2[2];
        ct2[0] = temp[0];
        ct2[1] = temp[1];
        ct2[2] = temp[2];
        ct2[3] = temp[3];
        //printf("DecD = %x, %x, %x, %x\n", ct1[0]^ct2[0], ct1[1]^ct2[1], ct1[2]^ct2[2], ct1[3]^ct2[3]);
    }
}

int main(int argc, char * argv[]) {
    
    srand (time(NULL));
    uint32_t seed = rand(), nrounds = 1;
    if (argc != 2) {
        printf("Please enter number of rounds (1,2,4 or 6).\n");
        exit(0);
    }
    nrounds = atoi(argv[1]); //Number of rounds

    if ((nrounds!=1)&&(nrounds!=2)&&(nrounds!=4)&&(nrounds!=6)) {
        printf("Please enter either 1,2,4 or 6 rounds.\n");
        exit(0);
    }

    int odd = 1; //Set to 0 to start on second round
    keySchedule(seed,nrounds);
    printf("Key Seed = %d\n", seed);

    // for (int i = 0; i<nrounds; i++) printf("%d ",ks[i]);
    // printf("\n");


    word_t x1[4], x2[4], x3[4], x4[4];
    word_t pdiff[4] = {0}, cdiff[4] = {0};
    vector<word_t> check;

    if (nrounds == 1) {
        pdiff[0]=2;
        pdiff[1]=2;
        cdiff[0]=7;
        cdiff[3]=6;
        printf("1-round switch experiment \n");
    } else if (nrounds == 2) {
        printf("2-round (non-deterministic) switch experiment  \n");
    } else if (nrounds == 4) {
        printf("4-round deterministic switch experiment  \n");
    } else if (nrounds == 6) {
        printf("6-round (non-deterministic) switch experiment  \n");
    }

    for (word_t pd=1; pd<8; pd++) //Active pdiff word
        for (word_t cd=1; cd<8; cd++) { //Active cdiff word

            if (nrounds == 2) {        
                pdiff[1]=pd;
                cdiff[3]=cd;
            } else if (nrounds == 4) {        
                pdiff[3]=pd;
                cdiff[1]=cd;
            } else if (nrounds == 6) {        
                pdiff[3]=pd;
                cdiff[1]=cd;
            }
            // word_t pdiff[4] = {0x0, 0x0, 0x0, pd}; //Upper difference to sandwich distinguisher
            // word_t cdiff[4] = {0x0, cd, 0x0, 0x0}; //Lower difference to sandwich distinguisher

            //Debug experiment
            // word_t pdiff[4] = {0, pd, 0x0, 0}; //Upper difference to sandwich distinguisher
            // word_t cdiff[4] = {cd, 0x0, 0x0, 0}; //Lower difference to sandwich distinguisher
            
            printf("Upper = (%x %x %x %x) | Lower = (%x %x %x %x) | ", pdiff[0],pdiff[1],pdiff[2],pdiff[3],cdiff[0],cdiff[1],cdiff[2],cdiff[3]);
            
            float iteration=0, success=0, prob=0; //Reset variables for probability calculation
            check.clear(); //Clear vector for pairwise checks

            //The following goes through all 4096 plaintext values
            for (word_t i0=0; i0<8; i0++)
                for (word_t i1=0; i1<8; i1++)
                    for (word_t i2=0; i2<8; i2++)
                        for (word_t i3=0; i3<8; i3++) {
                            iteration+=1;
                            x1[0] = i0;
                            x1[1] = i1; //This is the addend
                            x1[2] = i2;
                            x1[3] = i3;
                            for (int i=0; i<4; i++) {
                                x2[i] = x1[i]^pdiff[i];
                            }

                            //=========== Repetition check
                            word_t val = 0, val1 = 0;

                            for (int v=0; v<4; v++) {
                                val = (val | x1[v])<<3;
                            }
                            for (int v=0; v<3; v++) {
                                val = (val | x2[v])<<3;
                            }
                            val|=x2[3];

                            for (int v=0; v<4; v++) {
                                val1 = (val1 | x2[v])<<3;
                            }
                            for (int v=0; v<3; v++) {
                                val1 = (val1 | x1[v])<<3;
                            }
                            val1|=x1[3];

                            int flag = 0;
                            for(word_t v=0; v<check.size(); v++) {
                                if ((check[v]==val)||(check[v]==val1)) {
                                    iteration-=1; //If the pair has already been used, decrement iteration
                                    flag = 1;
                                    break;
                                } 
                            } 
                            if (flag) continue; //If pair has already been used, skip
                            check.push_back(val); //Mark pair as used
                            //=========== End repetition check

                            encryptPair(x1,x2,nrounds);

                            //Calculate x3 and x4
                            for (int i=0; i<4; i++) {
                                x3[i] = x1[i]^cdiff[i];
                                x4[i] = x2[i]^cdiff[i];
                            }
                            
                            decryptPair(x1,x3,nrounds);
                            decryptPair(x2,x4,nrounds);

                            if ( ((x3[0]^x4[0])==pdiff[0]) && ((x3[1]^x4[1])==pdiff[1]) && ((x3[2]^x4[2])==pdiff[2]) && ((x3[3]^x4[3])==pdiff[3]) ) {
                                success += 1;
                                prob = success/iteration;

                            } else {
                                prob = success/iteration;
                            }


                        }
            printf("%f/%f, Prob = %f\n", success, iteration, log2(prob)); 
            if (nrounds == 1) exit(0);
        }
}