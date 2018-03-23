#include "FHE.h"
#include "EncryptedArray.h"
#include <NTL/lzz_pXFactoring.h>
NTL_CLIENT

#include <fstream>
#include <sstream>
#include <sys/time.h>

#include <string>
#include <iostream>
#include <vector>

std::vector<long> read_image(std::string fname) {
    float w, h;
    std::vector<long> im;
    std::ifstream myfile;
    
    myfile.open(fname.c_str());
    myfile >> w;
    myfile >> h;
    std::cout << "Read in " << fname << "with dimensions: " << w << " x " << h << std::endl;

    float tmp;
    for (int i = 0; i < w*h; i++) {
        myfile >> tmp;
        im.push_back(tmp);
    }
    return im; 
}


/* Test function that lays out a 16x16 images into the 2x2 squares needed
 * to add them and average to get a 8x8 image result. The 16x16 image is laid
 * out in a 1D matrix, with rows, then going down with columns 
 */
void split_image16(std::vector<long> &original, 
                   std::vector<long> &r1,
                   std::vector<long> &r2,
                   std::vector<long> &r3,
                   std::vector<long> &r4) {
    int i, j;
    for (i = 0; i < 8; i++) {
        for (j = 0; j < 8; j++) {
            r1.push_back(original[2*i*16 + 2*j]);
            r2.push_back(original[2*i*16 + 2*j+1]);
            r3.push_back(original[(2*i+1)*16 + 2*j]);
            r4.push_back(original[(2*i+1)*16 + 2*j+1]);
        } 
    }
}


/* We have to encode floats into our plaintext space for our scheme to work,
 * so we will work with 1 = 0.01, and a large prime. 
 */
const long PRIME_MOD = 982451653;          // everything will be modulo this
const long SCALE_FACTOR = 100;           // factor to represent floats as longs

int main(int argc, char **argv)
{
    
    std::cout << "OH DAMN" << std::endl;
    std::vector<long> image = read_image("/home/robocup/crypto/raymond/image/kung.txt");
    // Need to multiply plaintext by scaling factor to convert to float
    for (int i = 0; i < image.size(); i++) { image[i] *= SCALE_FACTOR;}
    //for (int i = 0; i < image.size(); i++) {
    //    std::cout << image[i] << " ";
    //}
    std::cout << std::endl << std::endl << "EHH" << std::endl;

    std::vector<long> r1, r2, r3, r4; 
    split_image16(image, r1, r2, r3, r4);
    
    //for (int i = 0; i < r1.size(); i++) {
    //    std::cout << r1[i] << " ";
    //}


        /* On our trusted system we generate a new key
        * (or read one in) and encrypt the secret data set.
        */
    
    long m=0, p=PRIME_MOD, r=1; // Native plaintext space
                        // Computations will be 'modulo p'
    long L=16;          // Levels
    long c=3;           // Columns in key switching matrix
    long w=64;          // Hamming weight of secret key
    long d=0;
    long security = 128;
    ZZX G;
    m = FindM(security,L,c,p, d, 0, 0);


    FHEcontext context(m, p, r);
    // initialize context
    buildModChain(context, L, c);
    // modify the context, adding primes to the modulus chain
    FHESecKey secretKey(context);
    // construct a secret key structure
    const FHEPubKey& publicKey = secretKey;
    // an "upcast": FHESecKey is a subclass of FHEPubKey

    //if(0 == d)
    G = context.alMod.getFactorsOverZZ()[0];

    secretKey.GenSecKey(w);
    // actually generate a secret key with Hamming weight w

    addSome1DMatrices(secretKey);
    cout << "Generated key" << endl;


    EncryptedArray ea(context, G);
    // constuct an Encrypted array object ea that is
    // associated with the given context and the polynomial G

    long nslots = ea.size();
    // long nslots = 10;
    std::cout << "Number of slots: " << nslots << std::endl;

    std::vector<long> encrypted_four;
    for (int i = 0; i < nslots; i++) {
        encrypted_four.push_back(SCALE_FACTOR * 1/4);
    }
    r1.resize(nslots, 0);
    r2.resize(nslots, 0);
    r3.resize(nslots, 0);
    r4.resize(nslots, 0);

    Ctxt ct1(publicKey);
    ea.encrypt(ct1, publicKey, r1);

    Ctxt ct2(publicKey);
    ea.encrypt(ct2, publicKey, r2);

    Ctxt ct3(publicKey);
    ea.encrypt(ct3, publicKey, r3);

    Ctxt ct4(publicKey);
    ea.encrypt(ct4, publicKey, r4);

    Ctxt ctfour(publicKey);    
    ea.encrypt(ctfour, publicKey, encrypted_four);
    // On the public (untrusted) system we
    // can now perform our computation
    Ctxt ct_average = ct1;
    ct_average += ct2;
    ct_average += ct3;
    ct_average += ct4;
    ct_average *= ctfour;
    // To divide by 4 we will XOR out to make everything (mod 4), and then find 
    // the (4)^{-1} of the prime we are working with, and multiply by that...
    Ctxt ct_testdiv = ct_average;
    //ct_testdiv.divideBy2();

    std::vector<long> res;
    ea.decrypt(ct_average, secretKey, res);

    for (int i = 0; i < res.size() && i < 64; i++) {
        std::cout << res[i] << " ";
        if (i % 8 == 7) std::cout << std::endl;
    }
    return 0;
}
