
#include <cstdio>
#include <vector>
#include <math.h>
#include <cassert>
#include <stdlib.h>     /* srand, rand */
#include <time.h>       /* time */
#include <cstdint> // include this header for uint64_t

using namespace std;

#define word_t unsigned short
#define ROTL16(x,r) (((x)<<(r)) | (x>>(16-(r))))
#define ROTR16(x,r) (((x)>>(r)) | ((x)<<(16-(r))))
#define ROTL16_1(x) (((x)<<(1)) | (x>>(16-(1))))
#define ROTR16_1(x) (((x)>>(1)) | ((x)<<(16-(1))))
#define ROTL16_8(x) (((x)<<(8)) | (x>>(16-(8))))
#define ROTR16_8(x) (((x)>>(8)) | ((x)<<(16-(8))))
#define ROTL16_11(x) (((x)<<(11)) | (x>>(16-(11))))
#define ROTR16_11(x) (((x)>>(11)) | ((x)<<(16-(11)))) 
#define ROL1 ROTL16_1
#define ROL8 ROTL16_8
#define ROL11 ROTL16_11


#define ER16_0(a,b,k,i) (a^=i, b=ROTL16_1(b), b^=k, a+=b, a=ROTL16_8(a)) 
#define DR16_0(a,b,k,i) (a=ROTR16_8(a), b = ROTL16_1(b), b^=k, a-=b, a^=i)

#define ER16_1(a,b,k,i) (a^=i, b=ROTL16_8(b), b^=k, a+=b, a=ROTL16_1(a))  
#define DR16_1(a,b,k,i) (a=ROTR16_1(a), b = ROTL16_8(b), b^=k, a-=b, a^=i)

#define offset 8

#define ER0(a,b,k,i) ER16_0(a,b,k,i)
#define ER1(a,b,k,i) ER16_1(a,b,k,i)
#define DR0(a,b,k,i) DR16_0(a,b,k,i)
#define DR1(a,b,k,i) DR16_1(a,b,k,i)

word_t ks[16] = {};

void ChamKeySchedule(word_t K[8]) {
    //We generate all 16 RKs based on the master key
    for (int i=0; i<8; i++) {

        ks[i] = ROL1(K[i])^ROL8(K[i])^K[i];
        ks[(i+offset)^1] = ROL1(K[i])^ROL11(K[i])^K[i];
    }
}

void encrypt(word_t *pt, int nrounds, int even) {
    word_t a, b; //temp 
    //generate encryption trace
    for(int i=0; i<nrounds; i++){
        //Encrypt first plaintext
        a = pt[0];
        b = pt[1];

        //Cham encryption
        if (i%2==even) {
            ER0(a,b,ks[i%(2*offset)],i); //ER(a,b,k)
        }
        else {
            ER1(a,b,ks[i%(2*offset)],i);
        }
        //Rotation
        pt[0] = pt[1]; //a=b
        pt[1] = pt[2]; //b=c
        pt[2] = pt[3]; //c=d
        pt[3] = a; //Encrypted a
    }
}

void decrypt(word_t *ct, int nrounds, int even) {
    word_t a, b; //temp //Decrypt
    for(int i=nrounds-1; i>=0; i--){
        //Unshuffle
        a = ct[3];
        b = ct[0];

        //Cham encryption
        if (i%2==even) {
            DR0(a,b,ks[i%(2*offset)],i); //ER(a,b,k)
        }
        else {
            DR1(a,b,ks[i%(2*offset)],i);
        }
        //Rotation
        ct[3] = ct[2];
        ct[2] = ct[1];
        ct[1] = ct[0];
        ct[0] = a;
    }

}

int main() {

    uint64_t iterations, nrounds;
    int even; //Set to 0 to start from odd round
    uint64_t seed = time(NULL);
    srand (seed);
    seed = rand();
    srand (seed);
    word_t MASTER[8] = {};
    printf("Seed = %ld\n", seed);

    //Trying all possible values
    if (0) {
        //Use for loop to try all possible input differences to find deterministic trail
        iterations = 1000;
        for (word_t pd = 1; pd<0xFFFF; pd++)
            for (word_t cd=1; cd<0xFFFF; cd++)
            {
                word_t upperDiff[4] = {pd,  0x0000,  0x0000,  0};
                word_t lowerDiff[4] = {cd,  0,  0x0000,  0x0000};

                word_t x1[4]={0}, x2[4]={0}, x3[4]={0}, x4[4]={0};
                uint64_t val = 0;
                srand (time(NULL));
                x1[0] = rand();
                x1[1] = rand();
                x1[2] = rand();
                x1[3] = rand();

                double success=0, prob;
                for (uint64_t i=0; i<iterations; i++) {
                    val += 0x36a9f1d9b3a2ee68;
                    x1[0] += val;
                    x1[1] += val>>16;
                    x1[2] += val>>32;
                    x1[3] += val>>48;
                
                    for (int j=0; j<4; j++) {
                        x2[j]=x1[j]^upperDiff[j];
                    }

                    // printf("%x, %x, %x, %x\n", x1[0], x1[1], x1[2], x1[3]);
                    // printf("%x, %x, %x, %x\n", x2[0], x2[1], x2[2], x2[3]);
                    // printf("%x, %x, %x, %x\n", x1[0]^x2[0], x1[1]^x2[1], x1[2]^x2[2], x1[3]^x2[3]);
                    
                    encrypt(x1,nrounds, even);
                    encrypt(x2,nrounds, even);

                    // printf("%x, %x, %x, %x\n", x1[0], x1[1], x1[2], x1[3]);
                    // printf("%x, %x, %x, %x\n", x2[0], x2[1], x2[2], x2[3]);
                    // printf("y1y2 diff: %x, %x, %x, %x\n", x1[0]^x2[0], x1[1]^x2[1], x1[2]^x2[2], x1[3]^x2[3]);
                    
                    for (int j=0; j<4; j++) {
                        x3[j]=x1[j]^lowerDiff[j];
                    }
                    
                    for (int j=0; j<4; j++) {
                        x4[j]=x2[j]^lowerDiff[j];
                    }
                    // printf("%x, %x, %x, %x\n", x3[0], x3[1], x3[2], x3[3]);
                    // printf("%x, %x, %x, %x\n", x4[0], x4[1], x4[2], x4[3]);
                    // printf("y1y3 diff: %x, %x, %x, %x\n", x1[0]^x3[0], x1[1]^x3[1], x1[2]^x3[2], x1[3]^x3[3]);
                    // printf("y2y4 diff: %x, %x, %x, %x\n", x2[0]^x4[0], x2[1]^x4[1], x2[2]^x4[2], x2[3]^x4[3]);
                    // printf("y3y4 diff: %x, %x, %x, %x\n---\n", x3[0]^x4[0], x3[1]^x4[1], x3[2]^x4[2], x3[3]^x4[3]);

                    decrypt(x1,nrounds,even);
                    decrypt(x2,nrounds,even);
                    decrypt(x3,nrounds,even);
                    decrypt(x4,nrounds,even);
                    
                    // printf("%x, %x, %x, %x\n", x1[0], x1[1], x1[2], x1[3]);
                    // printf("%x, %x, %x, %x\n", x2[0], x2[1], x2[2], x2[3]);
                    // printf("%x, %x, %x, %x\n---\n", x1[0]^x2[0], x1[1]^x2[1], x1[2]^x2[2], x1[3]^x2[3]);
                    // printf("%x, %x, %x, %x\n", x3[0], x3[1], x3[2], x3[3]);
                    // printf("%x, %x, %x, %x\n", x4[0], x4[1], x4[2], x4[3]);
                    //printf("%x, %x, %x, %x\n---\n", x3[0]^x4[0], x3[1]^x4[1], x3[2]^x4[2], x3[3]^x4[3]);
                    if (((x3[0]^x4[0])==upperDiff[0])&&((x3[1]^x4[1])==upperDiff[1])&&((x3[2]^x4[2])==upperDiff[2])&&((x3[3]^x4[3])==upperDiff[3])) {
                        success += 1;
                    }
                    prob = success/(i+1);
                    // printf("P=2^%lf (%.0lf/%ld)\n", log2(prob), success, i+1);
                }
                if (success == iterations) {
                    printf("P=2^%lf (%.0lf/%ld): ", log2(prob), success, iterations);
                    printf("%x, %x, %x, %x --> ", upperDiff[0], upperDiff[1], upperDiff[2], upperDiff[3]);
                    printf("%x, %x, %x, %x\n", lowerDiff[0], lowerDiff[1], lowerDiff[2], lowerDiff[3]);

                }
            }
    }

    //Try specific input (single key)
    if (1) {
        //Use for loop to try all possible input differences to find deterministic trail
            even = 0;
            nrounds = 4;
            iterations = 4294967296;
            // uint64_t numpairs = 1073741824; //2^30 pairs
            uint64_t numpairs = 1048576; //2^20
            word_t upperDiff[4] = {0x0004,0x0502,0x0000,0x0084};
            word_t lowerDiff[4] = {0x9000,0x0084,0x0000,0x4000};


            word_t x1[4]={0}, x2[4]={0}, x3[4]={0}, x4[4]={0};
            uint64_t val = 0, val2 = 0, fullInputDiff=0;
            srand (time(NULL));
            
            for (int i=0; i<4; i++) {
                uint64_t temp = upperDiff[i];
                temp = temp << (64-(16+i*16));
                fullInputDiff |= temp;
            }
            
            printf("Input difference = %lx\n", fullInputDiff);

            double success=0, prob, dev=0; 
            uint64_t count = 0;
            for (uint64_t i=0; i<iterations; i++) {
                //Set up key
                for (int i=0; i<8; i++) 
                {
                    MASTER[i]=rand();
                }
                ChamKeySchedule(MASTER);


                val += 0x36a9f1d9b3a2ee68;
                x1[0] = val>>48;
                x1[1] = val>>32;
                x1[2] = val>>16;
                x1[3] = val;
                
                val2 = val^fullInputDiff;
                x2[0] = val2>>48;
                x2[1] = val2>>32;
                x2[2] = val2>>16;
                x2[3] = val2;

                //Ignore repeated pairs
                if (val > val2) continue;
                count++;
                    
                encrypt(x1,nrounds,even);
                encrypt(x2,nrounds,even);

                for (int j=0; j<4; j++) {
                    x3[j]=x1[j]^lowerDiff[j];
                }
                    
                for (int j=0; j<4; j++) {
                    x4[j]=x2[j]^lowerDiff[j];
                }

                decrypt(x1,nrounds,even);
                decrypt(x2,nrounds,even);
                decrypt(x3,nrounds,even);
                decrypt(x4,nrounds,even);

                // for (int i=0; i<16; i++) printf("%x,", ks[i]);
                // printf("\n");
                // for (int i=0; i<4; i++) printf("%x,", x1[i]);
                // printf("\n");
                // for (int i=0; i<4; i++) printf("%x,", x2[i]);
                // printf("\n");
                // for (int i=0; i<4; i++) printf("%x,", x3[i]);
                // printf("\n");
                // for (int i=0; i<4; i++) printf("%x,", x4[i]);
                // printf("\n");
                // exit(0);
                    
                if (((x3[0]^x4[0])==upperDiff[0])&&((x3[1]^x4[1])==upperDiff[1])&&((x3[2]^x4[2])==upperDiff[2])&&((x3[3]^x4[3])==upperDiff[3])) {
                    success += 1;
                }
                prob = success/(count);
                //Binomial proportion confidence interval
                //For 1% confidence interval, alpha = 0.01
                // 1 - alpha/2 = 0.995, z = 2.57
                dev = 2.57*sqrt(prob*(1-prob)/count);
                if (count == numpairs) break;
                if (count % 10000000 == 0) {
                    printf("Number of pairs = %ld\n", count);
                    printf("P=2^%lf (%.0lf/%ld), stdev = %lf\n ", log2(prob), success, count, log2(dev));
                }
            }
            printf("Number of pairs = %ld\n", count);
            printf("P=2^%lf (%.0lf/%ld)+- 2^%lf: ", log2(prob), success, count, log2(dev));
            printf("%x, %x, %x, %x --> ", upperDiff[0], upperDiff[1], upperDiff[2], upperDiff[3]);
            printf("%x, %x, %x, %x\n", lowerDiff[0], lowerDiff[1], lowerDiff[2], lowerDiff[3]);

    }


}
	