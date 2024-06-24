
#include <cstdio>
#include <string.h>
#include <iostream>
#include <fstream>
#include<sstream>
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
word_t ks2[16] = {};
word_t ks3[16] = {};
word_t ks4[16] = {};

void ChamKeySchedule(word_t K[8], int index) {

    if (index == 1)
        for (int i=0; i<8; i++) {

            ks[i] = ROL1(K[i])^ROL8(K[i])^K[i];
            ks[(i+offset)^1] = ROL1(K[i])^ROL11(K[i])^K[i];
        }
    if (index == 2)
        for (int i=0; i<8; i++) {

            ks2[i] = ROL1(K[i])^ROL8(K[i])^K[i];
            ks2[(i+offset)^1] = ROL1(K[i])^ROL11(K[i])^K[i];
        }
    if (index == 3)
        for (int i=0; i<8; i++) {

            ks3[i] = ROL1(K[i])^ROL8(K[i])^K[i];
            ks3[(i+offset)^1] = ROL1(K[i])^ROL11(K[i])^K[i];
        }
    if (index == 4)
        for (int i=0; i<8; i++) {

            ks4[i] = ROL1(K[i])^ROL8(K[i])^K[i];
            ks4[(i+offset)^1] = ROL1(K[i])^ROL11(K[i])^K[i];
        }
}

void encrypt(word_t *pt, int nrounds, int even, int index) {

    
    word_t rk[16] = {};

    if (index == 1)
        for (int i=0; i< 16; i++)
            rk[i] = ks[i];
    if (index == 2)
        for (int i=0; i< 16; i++)
            rk[i] = ks2[i];
    if (index == 3)
        for (int i=0; i< 16; i++)
            rk[i] = ks3[i];
    if (index == 4)
        for (int i=0; i< 16; i++)
            rk[i] = ks4[i];

    word_t a, b; //temp 
    //generate encryption trace
    for(int i=0; i<nrounds; i++){
        //Encrypt first plaintext
        a = pt[0];
        b = pt[1];

        //Cham encryption
        if (i%2==even) {
            ER0(a,b,rk[i%(2*offset)],i); //ER(a,b,k)
        }
        else {
            ER1(a,b,rk[i%(2*offset)],i);
        }
        //Rotation
        pt[0] = pt[1]; //a=b
        pt[1] = pt[2]; //b=c
        pt[2] = pt[3]; //c=d
        pt[3] = a; //Encrypted a
    }
}

void decrypt(word_t *ct, int nrounds, int even, int index) {

    
    word_t rk[16] = {};

    if (index == 1)
        for (int i=0; i< 16; i++)
            rk[i] = ks[i];
    if (index == 2)
        for (int i=0; i< 16; i++)
            rk[i] = ks2[i];
    if (index == 3)
        for (int i=0; i< 16; i++)
            rk[i] = ks3[i];
    if (index == 4)
        for (int i=0; i< 16; i++)
            rk[i] = ks4[i];

    word_t a, b; //temp //Decrypt
    for(int i=nrounds-1; i>=0; i--){
        //Unshuffle
        a = ct[3];
        b = ct[0];

        //Cham encryption
        if (i%2==even) {
            DR0(a,b,rk[i%(2*offset)],i); //ER(a,b,k)
        }
        else {
            DR1(a,b,rk[i%(2*offset)],i);
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
    word_t MASTER2[8] = {};
    word_t MASTER3[8] = {};
    word_t MASTER4[8] = {};

    printf("Seed = %ld\n", seed);

    //Try specific input (related key)
    if (0) {
            iterations = 4294967296;
            // uint64_t numpairs = 1073741824; //2^30 pairs
            uint64_t numpairs = 1000000; //2^20

            //*****************************************************************************
            // 20 + 7 + 19 = 46-round boomerang distinguisher
            // 15 + 12 = 27 * 2 = 54 + 9.51 = 63.51 (valid but pushing it)            
            // 20R E_0 (w=15)
            word_t upperDiff[4] = {0x4200,0x0000,0x0000,0x0084};
            word_t keyDiff[8] = {0x0000,0x0000,0x0000,0x0000,0x0000,0x4000,0x4000,0x0000};
            nrounds = 7;
            even = 0;
            //E_1 starting from R27, 19 rounds, w=12 (no cluster)
            word_t lowerDiff[4] = {0x0000,0x0000,0x0000,0x8401};
            //Set up key difference
            word_t lowerKeyDiff[8] = {0x0000,0x0000,0x0000,0x0000,0x0080,0x0000,0x0000,0x8000};

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
                
                //Set up key difference
                for (int i=0; i<8; i++) 
                {
                    MASTER[i]=rand();
                    MASTER2[i] = MASTER[i] ^ keyDiff[i];
                }
                ChamKeySchedule(MASTER, 1);
                ChamKeySchedule(MASTER2,2);

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
                    
                encrypt(x1,nrounds,even,1);
                encrypt(x2,nrounds,even,2);

                for (int j=0; j<4; j++) {
                    x3[j]=x1[j]^lowerDiff[j];
                }
                    
                for (int j=0; j<4; j++) {
                    x4[j]=x2[j]^lowerDiff[j];
                }

                //TODO: ERROR HERE. We need 2 new keys for x3 and x4 but the other 2 remain.
                //TODO: Modify encrypt/decrypt to accept the key as the input so we do not need to create so many functions
                //Set up key difference
                for (int i=0; i<8; i++) 
                {
                    MASTER3[i] = MASTER[i] ^ lowerKeyDiff[i];
                    MASTER4[i] = MASTER2[i] ^ lowerKeyDiff[i];
                }
                ChamKeySchedule(MASTER3,3);
                ChamKeySchedule(MASTER4,4);

                decrypt(x1,nrounds,even,1);
                decrypt(x2,nrounds,even,2);
                decrypt(x3,nrounds,even,3);
                decrypt(x4,nrounds,even,4);
                    
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

    //Read a CSV file with a list of inputs and outputs to test boomerang connectivity, automatically calculate overall weight
    if (1) {
            iterations = 4294967296;
            double probsum = 0;
            uint64_t numpairs = 16777216; //2^24 pairs
            // uint64_t numpairs = 1048576; //2^20
	        uint64_t combinations = 0;
            //*****************************************************************************
            //20 + 7 + 19 = 46-round boomerang distinguisher         
            //20R E_0 (w=15)

            //Key differences are fixed
            word_t keyDiff[8] = {0x0000,0x0000,0x0000,0x0000,0x0000,0x4000,0x4000,0x0000};
            word_t lowerKeyDiff[8] = {0x0000,0x0000,0x0000,0x0000,0x0080,0x0000,0x0000,0x8000};
            nrounds = 7;
            even = 0;
            int upperweight = 0;
            int lowerweight = 12;
            word_t upperDiff[4] = {0x4200,0x0000,0x0000,0x0084};
            word_t lowerDiff[4] = {0x0000,0x0000,0x0000,0x8401};

            word_t x1[4]={0}, x2[4]={0}, x3[4]={0}, x4[4]={0};
            uint64_t val = 0, val2 = 0, fullInputDiff=0;
            srand (time(NULL));
            
            string line, line2;
            stringstream ss, ss2;
            std::ifstream fin("uppertrail.csv");
	    std::ifstream lin("lowertrail.csv");
            while (getline(lin,line2)) { 
		ss2.clear();
		ss2 << line2;
		for (int w=0; w<5; w++) {
                    string substr;
                    getline(ss2, substr, ','); //get first string delimited by comma
                    if (w!=4) {
                        lowerDiff[w]=strtol(substr.c_str(), NULL, 16);
                    }
                    else {
                        lowerweight = strtol(substr.c_str(), NULL, 10);
                    }

                }
		fin.clear();
		fin.seekg(0,ios::beg);
		while(getline(fin,line)) {
                    cout << "----\n" << line << " " << line2 << endl;
		    ss.clear(); 
                    ss << line;

                    for (int w=0; w<5; w++) {
                        string substr;
                        getline(ss, substr, ','); //get first string delimited by comma
                        if (w!=4) {
                            upperDiff[w]=strtol(substr.c_str(), NULL, 16);
                        }
                        else {
                            upperweight = strtol(substr.c_str(), NULL, 10);
                        }

                    }

                    fullInputDiff = 0;
                    for (int i=0; i<4; i++) {
                        uint64_t temp = upperDiff[i];
                        temp = temp << (64-(16+i*16));
                        fullInputDiff |= temp;
                    }
                    
                    printf("Input difference = %lx, Weight = %d\n", fullInputDiff, upperweight);
		    printf("Output difference = %x,%x,%x,%x, Weight = %d\n", lowerDiff[0],lowerDiff[1],lowerDiff[2],lowerDiff[3], lowerweight);
                    double success=0, prob=0, dev=0; 
                    uint64_t count = 0;
		    int skip = 0;
                    for (uint64_t i=0; i<iterations; i++) {
                        
                        //Set up key difference
                        for (int i=0; i<8; i++) 
                        {
                            MASTER[i]=rand();
                            MASTER2[i] = MASTER[i] ^ keyDiff[i];
                        }
                        ChamKeySchedule(MASTER, 1);
                        ChamKeySchedule(MASTER2,2);

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
                            
                        encrypt(x1,nrounds,even,1);
                        encrypt(x2,nrounds,even,2);

                        for (int j=0; j<4; j++) {
                            x3[j]=x1[j]^lowerDiff[j];
                        }
                            
                        for (int j=0; j<4; j++) {
                            x4[j]=x2[j]^lowerDiff[j];
                        }

                        //TODO: ERROR HERE. We need 2 new keys for x3 and x4 but the other 2 remain.
                        //TODO: Modify encrypt/decrypt to accept the key as the input so we do not need to create so many functions
                        //Set up key difference
                        for (int i=0; i<8; i++) 
                        {
                            MASTER3[i] = MASTER[i] ^ lowerKeyDiff[i];
                            MASTER4[i] = MASTER2[i] ^ lowerKeyDiff[i];
                        }
                        ChamKeySchedule(MASTER3,3);
                        ChamKeySchedule(MASTER4,4);

                        decrypt(x1,nrounds,even,1);
                        decrypt(x2,nrounds,even,2);
                        decrypt(x3,nrounds,even,3);
                        decrypt(x4,nrounds,even,4);
                            
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
			    fflush(stdout);
			}
                    }
                    printf("Number of pairs = %ld\n", count);
                    printf("P=2^%lf (%.0lf/%ld)+- 2^%lf\n", log2(prob), success, count, log2(dev));
                    if (prob) {
			combinations++;
                        probsum+=prob*pow(2,-1*upperweight*2)*pow(2,-1*lowerweight*2);
                        printf("Total weight = %lf, Number of boomerangs = %ld\n", log2(probsum), combinations);
                    }
		    fflush(stdout);

                }
		//fin.clear();
		//fin.seekg(0,ios::beg);
            }
    
}


}
	
