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



int main(int argc, char **argv)
{
    
    std::cout << "OH DAMN" << std::endl;
    std::vector<long> image = read_image("/home/robocup/crypto/raymond/image/kung.txt");
    for (int i = 0; i < image.size(); i++) {
        std::cout << image[i] << " ";
    }
    std::cout << std::endl << std::endl << "EHH" << std::endl;

    std::vector<long> r1, r2, r3, r4; 
    split_image16(image, r1, r2, r3, r4);
    for (int i = 0; i < r1.size(); i++) {
        std::cout << r1[i] << " ";
    }



    /* On our trusted system we generate a new key
        * (or read one in) and encrypt the secret data set.
        */
    /*
    long m=0, p=65537, r=1; // Native plaintext space
                        // Computations will be 'modulo p'
    long L=256;          // Levels
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

    vector<long> v1;
    for(int i = 0 ; i < nslots; i++) {
        v1.push_back(i);
    }
    Ctxt ct1(publicKey);
    ea.encrypt(ct1, publicKey, v1);

    vector<long> v2;
    Ctxt ct2(publicKey);
    for(int i = 0 ; i < nslots; i++) {
        v2.push_back(i);
    }
    ea.encrypt(ct2, publicKey, v2);

    // On the public (untrusted) system we
    // can now perform our computation

    Ctxt ctSum = ct1;
    Ctxt ctProd = ct1;

    ctSum += ct2;
    ctProd *= ct2;

    vector<long> res;
    ea.decrypt(ctSum, secretKey, res);

    cout << "All computations are modulo " << p << "." << endl;
    for(int i = 0; i < 20; i ++) {
        cout << v1[i] << " + " << v2[i] << " = " << res[i] << endl;
    }

    ea.decrypt(ctProd, secretKey, res);
    for(int i = 0; i < 20; i ++) {    /* On our trusted system we generate a new key
        * (or read one in) and encrypt the secret data set.
        */
    /*
    long m=0, p=65537, r=1; // Native plaintext space
                        // Computations will be 'modulo p'
    long L=256;          // Levels
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

    vector<long> v1;
    for(int i = 0 ; i < nslots; i++) {
        v1.push_back(i);
    }
    Ctxt ct1(publicKey);
    ea.encrypt(ct1, publicKey, v1);

    vector<long> v2;
    Ctxt ct2(publicKey);
    for(int i = 0 ; i < nslots; i++) {
        v2.push_back(i);
    }
    ea.encrypt(ct2, publicKey, v2);

    // On the public (untrusted) system we
    // can now perform our computation

    Ctxt ctSum = ct1;
    Ctxt ctProd = ct1;

    ctSum += ct2;
    ctProd *= ct2;

    vector<long> res;
    ea.decrypt(ctSum, secretKey, res);

    cout << "All computations are modulo " << p << "." << endl;
    for(int i = 0; i < 20; i ++) {
        cout << v1[i] << " + " << v2[i] << " = " << res[i] << endl;
    }

    ea.decrypt(ctProd, secretKey, res);
    for(int i = 0; i < 20; i ++) {
        cout << v1[i] << " * " << v2[i] << " = " << res[i] << endl;
    }


    */

    return 0;
}
