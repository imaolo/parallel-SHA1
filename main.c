// -fopenmp -lycrypto
// Compartes the run time of openssl's SAH1 hash function
// to my parallel OpenMP implementation

// Arguments:
// 1. Min message size(GB)
// 2. Max message size(GB)
// 3. Min threads
// 4. Max threads
// 5. Granularity
// 6. Number of tests

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/sha.h>
#include <omp.h>

#define SHA1_DIGEST_LENGTH 20
#define FILE_NAME "results.csv"

typedef uint8_t BYTE;
typedef uint32_t WORD;
union eight_bytes {uint64_t u64; BYTE b8[sizeof(uint64_t)]; };

void SHA1P(unsigned char*,uint64_t,unsigned char*,BYTE);
void printArguments();
int checkArguments(int,char**);

int main(int argc, char **argv){

    //checking that the proper arguments were used 
    if (!checkArguments(argc,argv))
        return 0;
    const size_t MIN_MESSAGE_SIZE = atof(argv[1]) * pow(10,9);
    const size_t MAX_MESSAGE_SIZE = atof(argv[2]) * pow(10,9);
    const size_t MIN_THREADS      = atoi(argv[3]);
    const size_t MAX_THREADS      = atoi(argv[4]);
    const size_t GRANULARITY      = atoi(argv[5]);
    const size_t NUMBER_OF_TESTS  = atoi(argv[6]);
    const size_t INCREMENT        = (MAX_MESSAGE_SIZE-MIN_MESSAGE_SIZE)/GRANULARITY;
    double *serialTime            = calloc(GRANULARITY+1,sizeof(double));
    double *parallelTime          = calloc(GRANULARITY+1,sizeof(double));
    double start                  = 0; 
    BYTE* message                 = calloc(MAX_MESSAGE_SIZE,sizeof(BYTE));
    BYTE serialResult[SHA1_DIGEST_LENGTH];
    BYTE parallelResult[SHA1_DIGEST_LENGTH];
    

    //output file configuration
    FILE *of;
    of = fopen(FILE_NAME,"w");
    fprintf(of,"Parallel SHA1 Metric Data\n");
    fprintf(of,"Min Message Size(GB): %0.6f\n",MIN_MESSAGE_SIZE/pow(10,9));
    fprintf(of,"Max Message Size(GB): %0.6f\n",MAX_MESSAGE_SIZE/pow(10,9));
    fprintf(of,"Min Threads         : %ld\n",MIN_THREADS);
    fprintf(of,"Max Threads         : %ld\n",MAX_THREADS);
    fprintf(of,"Granularity         : %ld\n",GRANULARITY);
    fprintf(of,"Tests per Cycle     : %ld\n\n",NUMBER_OF_TESTS);
    fclose(of);

    printf("running...\n");
    int i;
    int j;
    size_t size = MIN_MESSAGE_SIZE;
    //collect industry implementation data
    for (i = 0;i<=GRANULARITY;i++){
        for (j = 0;j<NUMBER_OF_TESTS;j++){
            start = omp_get_wtime();
            SHA1(message,size,serialResult);
            serialTime[i] += omp_get_wtime()-start;
        }
        size+= INCREMENT;
    }
    //collect parallel implementation data
    for (int threads = MIN_THREADS;threads<=MAX_THREADS;threads++){
        size = MIN_MESSAGE_SIZE;
        of = fopen(FILE_NAME,"a");
        fprintf(of,"Threads: %d\n",threads);
        fprintf(of,"Message Size(GB), Parallel Time, Serial Time, Serial Speedup\n");
        fclose(of);
        for (i = 0;i<=GRANULARITY;i++){
            of = fopen(FILE_NAME,"a");
            fprintf(of,"%0.6f,",(float)size/pow(10,9));
            fclose(of);
            for (j = 0;j<NUMBER_OF_TESTS;j++){
                start = omp_get_wtime();
                SHA1P(message,size,parallelResult,threads);
                parallelTime[i] += omp_get_wtime()-start;
            }
            of = fopen(FILE_NAME,"a");
            fprintf(of,"            %0.4f,        %0.4f,    %0.2f\n",
            (float)parallelTime[i]/NUMBER_OF_TESTS,
            (float)serialTime[i]/NUMBER_OF_TESTS,
            (float)parallelTime[i]/serialTime[i]);
            fclose(of);
            parallelTime[i] = 0;
            size += INCREMENT;
        }
        of = fopen(FILE_NAME,"a");
        fprintf(of,"\n");
        fclose(of);
    }

    //comparing the industry hash result to the parallel hash result
    BYTE passed = 1;
    for (int i=0;i<SHA1_DIGEST_LENGTH;i++){
        if (serialResult[i] != parallelResult[i]){
            passed = 0;
            break;
        }
    }

    of = fopen(FILE_NAME,"a");
    if (passed == 1){
        printf("PASSED\n");
        fprintf(of,"PASSED\n");
    }
    else{
        printf("FAILED\n");
        fprintf(of,"FAILED\n");
    }
    fclose(of);

    free(serialTime);
    free(parallelTime);
    free(message);
    return 0;
}
void printArguments(){
    printf("The arguments are: \n");
    printf("1. Min message size(GB)\n");
    printf("2. Max message size(GB)\n");
    printf("3. Min threads\n");
    printf("4. Max threads\n");
    printf("5. Granularity\n");
    printf("6. Number of tests\n");
}
int checkArguments(int argc, char **argv){
    if (argc != 7){
        printf("Please include the proper amount of arguments.\n");
        printArguments();
        return 0;
    }
    else if (atof(argv[1]) <= 0| atof(argv[2]) <= 0){
        printf("Please enter a float greater than zero for message size.\n");
        printArguments();
        return 0;
    }
    else if (atof(argv[1]) >= atof(argv[2])){
        printf("Ensure the min message size is less than the max message size.\n");
        printArguments();
        return 0 ; 
    }
    else if (atoi(argv[3]) <= 0 | atoi(argv[4]) <= 0){
        printf("Please enter an integer greater than zero for number of threads.\n");
        printArguments();
        return 0;
    }
    else if (atoi(argv[3]) > atoi(argv[4])){
        printf("Ensure the min number of threads is less than the max number of threads.\n");
        printArguments();
        return 0 ; 
    }
    else if (atoi(argv[4]) > omp_get_max_threads()){
        printf("There are only %d threads available.\n",omp_get_max_threads());
        printArguments();
        return 0;
    }
    else if (atoi(argv[5]) <= 0){
        printf("Please enter an integer greater than zero for granularity.\n");
        printArguments();
        return 0;
    }
    else if (atoi(argv[5]) <= 0){
        printf("Please enter an integer greater than zero for number of tests.\n");
        printArguments();
        return 0;
    }
    return 1;
}

//Parallel SHA1 Alg
#define H0 0x67452301
#define H1 0xEFCDAB89
#define H2 0x98BADCFE
#define H3 0x10325476
#define H4 0xC3D2E1F0
#define K0 0x5A827999
#define K1 0x6ED9EBA1
#define K2 0x8F1BBCDC
#define K3 0xCA62C1D6
#define R0(q,col,a,b,c,d,e,f,temp) \
    temp = rol(a,5) + ((b & c) | ((~b) & d)) + e + K0 + q[col]; \
    e = d; d = c; c = rol(b,30); b = a; a = temp;
#define R1(q,col,a,b,c,d,e,f,temp) \
    temp = rol(a,5) + (b ^ c ^ d) + e + K1 + q[col];    \
    e = d; d = c; c = rol(b,30); b = a; a = temp;
#define R2(q,col,a,b,c,d,e,f,temp) \
    temp = rol(a,5) + ((b & c) | (b & d) | (c & d)) + e + K2 + q[col]; \
    e = d; d = c; c = rol(b,30); b = a; a = temp;
#define R3(q,col,a,b,c,d,e,f,temp) \
    temp = rol(a,5) + (b ^ c ^ d) + e + K3 + q[col]; \
    e = d; d = c; c = rol(b,30); b = a; a = temp;
#define rol(x,n) ((x<<n) | (x>>(32-n)))

void SHA1P(unsigned char *message,uint64_t l, unsigned char * result,BYTE threads){

    int zeroes = 1 + ((447 - l*8) % 512)/8;
    BYTE *padded  = calloc(l+zeroes+64,sizeof(BYTE));
    WORD numChunks = (l+zeroes+8)/64;
    memcpy(padded,message,l);
    padded[l] = 0x80;
    for (int i = l+1;i<zeroes;i++)
        padded[i] = 0x00;
    union eight_bytes end = (union eight_bytes)(l*8);
    padded[numChunks*64-8] = end.b8[7];
    padded[numChunks*64-7] = end.b8[6];
    padded[numChunks*64-6] = end.b8[5];
    padded[numChunks*64-5] = end.b8[4];
    padded[numChunks*64-4] = end.b8[3]; 
    padded[numChunks*64-3] = end.b8[2];
    padded[numChunks*64-2] = end.b8[1];
    padded[numChunks*64-1] = end.b8[0];

    
    size_t height = numChunks;
    size_t width  = 80; //80 columns
    size_t x      = 0;  //indicate the beginning of a row in the 1d array
    size_t y      = 0;  //helps navigate the padded array
    size_t row    = 0;  //refers to the chunk
    size_t col    = 0;  //referes to the block number within the chunks (0-80);
    WORD *blocks = calloc(width*height,sizeof(WORD));   //array used to represent the grid
    WORD *q;            //a temporary pointer used within the loops
    WORD a,b,c,d,e,f,temp;
    WORD state[5] = {H0,H1,H2,H3,H4};
    BYTE *z;            //a temporary pointer used within the loops

    #pragma omp parallel for          \
        num_threads(threads)          \
        shared (height,blocks,padded) \
        private(row,x,y,z,q,col)  
    for(row=0;row<height;row++){
        y = row*width; 
        x = row*64; 
        for(col=0;col<16;col++){
            z = &padded[x + col*4];
            blocks[y+col] = (z[0] << 24) + 
                            (z[1] << 16) +
                            (z[2] <<  8) + 
                            (z[3]);
        }
        for(col=16;col<80;col++){
            q = &blocks[y+col-16];
            blocks[y+col] = rol(
                (q[13] ^
                 q[8]  ^ 
                 q[2]  ^ 
                 q[0]), 
                 1);
        }
    }
    

    #pragma omp parallel for ordered  \
        num_threads(threads)          \
        shared (height,blocks,state,width) \
        private(row,a,b,c,d,e,q,temp) 
    for(row=0;row<height;row++){
        #pragma omp ordered
        a = state[0];
        b = state[1];
        c = state[2];
        d = state[3];
        e = state[4];
        q = &blocks[row*width];

        R0(q, 0,a,b,c,d,e,f,temp) R0(q, 1,a,b,c,d,e,f,temp)
        R0(q, 2,a,b,c,d,e,f,temp) R0(q, 3,a,b,c,d,e,f,temp)
        R0(q, 4,a,b,c,d,e,f,temp) R0(q, 5,a,b,c,d,e,f,temp)
        R0(q, 6,a,b,c,d,e,f,temp) R0(q, 7,a,b,c,d,e,f,temp)
        R0(q, 8,a,b,c,d,e,f,temp) R0(q, 9,a,b,c,d,e,f,temp)
        R0(q,10,a,b,c,d,e,f,temp) R0(q,11,a,b,c,d,e,f,temp)
        R0(q,12,a,b,c,d,e,f,temp) R0(q,13,a,b,c,d,e,f,temp)
        R0(q,14,a,b,c,d,e,f,temp) R0(q,15,a,b,c,d,e,f,temp)
        R0(q,16,a,b,c,d,e,f,temp) R0(q,17,a,b,c,d,e,f,temp)
        R0(q,18,a,b,c,d,e,f,temp) R0(q,19,a,b,c,d,e,f,temp)

        R1(q,20,a,b,c,d,e,f,temp) R1(q,21,a,b,c,d,e,f,temp)
        R1(q,22,a,b,c,d,e,f,temp) R1(q,23,a,b,c,d,e,f,temp)
        R1(q,24,a,b,c,d,e,f,temp) R1(q,25,a,b,c,d,e,f,temp)
        R1(q,26,a,b,c,d,e,f,temp) R1(q,27,a,b,c,d,e,f,temp)
        R1(q,28,a,b,c,d,e,f,temp) R1(q,29,a,b,c,d,e,f,temp)
        R1(q,30,a,b,c,d,e,f,temp) R1(q,31,a,b,c,d,e,f,temp)
        R1(q,32,a,b,c,d,e,f,temp) R1(q,33,a,b,c,d,e,f,temp)
        R1(q,34,a,b,c,d,e,f,temp) R1(q,35,a,b,c,d,e,f,temp)
        R1(q,36,a,b,c,d,e,f,temp) R1(q,37,a,b,c,d,e,f,temp)
        R1(q,38,a,b,c,d,e,f,temp) R1(q,39,a,b,c,d,e,f,temp)

        R2(q,40,a,b,c,d,e,f,temp) R2(q,41,a,b,c,d,e,f,temp)
        R2(q,42,a,b,c,d,e,f,temp) R2(q,43,a,b,c,d,e,f,temp)
        R2(q,44,a,b,c,d,e,f,temp) R2(q,45,a,b,c,d,e,f,temp)
        R2(q,46,a,b,c,d,e,f,temp) R2(q,47,a,b,c,d,e,f,temp)
        R2(q,48,a,b,c,d,e,f,temp) R2(q,49,a,b,c,d,e,f,temp)
        R2(q,50,a,b,c,d,e,f,temp) R2(q,51,a,b,c,d,e,f,temp)
        R2(q,52,a,b,c,d,e,f,temp) R2(q,53,a,b,c,d,e,f,temp)
        R2(q,54,a,b,c,d,e,f,temp) R2(q,55,a,b,c,d,e,f,temp)
        R2(q,56,a,b,c,d,e,f,temp) R2(q,57,a,b,c,d,e,f,temp)
        R2(q,58,a,b,c,d,e,f,temp) R2(q,59,a,b,c,d,e,f,temp)

        R3(q,60,a,b,c,d,e,f,temp) R3(q,61,a,b,c,d,e,f,temp)
        R3(q,62,a,b,c,d,e,f,temp) R3(q,63,a,b,c,d,e,f,temp)
        R3(q,64,a,b,c,d,e,f,temp) R3(q,65,a,b,c,d,e,f,temp)
        R3(q,66,a,b,c,d,e,f,temp) R3(q,67,a,b,c,d,e,f,temp)
        R3(q,68,a,b,c,d,e,f,temp) R3(q,69,a,b,c,d,e,f,temp)
        R3(q,70,a,b,c,d,e,f,temp) R3(q,71,a,b,c,d,e,f,temp)
        R3(q,72,a,b,c,d,e,f,temp) R3(q,73,a,b,c,d,e,f,temp)
        R3(q,74,a,b,c,d,e,f,temp) R3(q,75,a,b,c,d,e,f,temp)
        R3(q,76,a,b,c,d,e,f,temp) R3(q,77,a,b,c,d,e,f,temp)
        R3(q,78,a,b,c,d,e,f,temp) R3(q,79,a,b,c,d,e,f,temp)

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
    }

    result[0]  = (state[0] & 0xFF000000) >> 24;
    result[1]  = (state[0] & 0x00FF0000) >> 16;
    result[2]  = (state[0] & 0x0000FF00) >>  8;
    result[3]  =  state[0] & 0x000000FF       ;
    result[4]  = (state[1] & 0xFF000000) >> 24;
    result[5]  = (state[1] & 0x00FF0000) >> 16;
    result[6]  = (state[1] & 0x0000FF00) >>  8;
    result[7]  =  state[1] & 0x000000FF       ;
    result[8]  = (state[2] & 0xFF000000) >> 24;
    result[9]  = (state[2] & 0x00FF0000) >> 16;
    result[10] = (state[2] & 0x0000FF00) >>  8;
    result[11] =  state[2] & 0x000000FF       ;
    result[12] = (state[3] & 0xFF000000) >> 24;
    result[13] = (state[3] & 0x00FF0000) >> 16;
    result[14] = (state[3] & 0x0000FF00) >>  8;
    result[15] =  state[3] & 0x000000FF       ;
    result[16] = (state[4] & 0xFF000000) >> 24;
    result[17] = (state[4] & 0x00FF0000) >> 16;
    result[18] = (state[4] & 0x0000FF00) >>  8;
    result[19] =  state[4] & 0x000000FF       ;

    free(blocks);
    free(padded);
    return;
}


//these macros print the binary pattern of their data types
//they are highly useful for debugging
// #define BYTEPATTERN "%c%c%c%c%c%c%c%c\n"

// #define bytetobin(byte) \
//     (byte & 0x80 ? '1' : '0'), \
//     (byte & 0x40 ? '1' : '0'), \
//     (byte & 0x20 ? '1' : '0'), \
//     (byte & 0x10 ? '1' : '0'), \
//     (byte & 0x08 ? '1' : '0'), \
//     (byte & 0x04 ? '1' : '0'), \
//     (byte & 0x02 ? '1' : '0'), \
//     (byte & 0x01 ? '1' : '0')

// #define WORDPATTERN "%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c\n"

// #define wordtobin(word) \
//     (word & 0x80000000 ? '1' : '0'), \
//     (word & 0x40000000 ? '1' : '0'), \
//     (word & 0x20000000 ? '1' : '0'), \
//     (word & 0x10000000 ? '1' : '0'), \
//     (word & 0x08000000 ? '1' : '0'), \
//     (word & 0x04000000 ? '1' : '0'), \
//     (word & 0x02000000 ? '1' : '0'), \
//     (word & 0x01000000 ? '1' : '0'), \
//     (word & 0x00800000 ? '1' : '0'), \
//     (word & 0x00400000 ? '1' : '0'), \
//     (word & 0x00200000 ? '1' : '0'), \
//     (word & 0x00100000 ? '1' : '0'), \
//     (word & 0x00080000 ? '1' : '0'), \
//     (word & 0x00040000 ? '1' : '0'), \
//     (word & 0x00020000 ? '1' : '0'), \
//     (word & 0x00010000 ? '1' : '0'), \
//     (word & 0x00008000 ? '1' : '0'), \
//     (word & 0x00004000 ? '1' : '0'), \
//     (word & 0x00002000 ? '1' : '0'), \
//     (word & 0x00001000 ? '1' : '0'), \
//     (word & 0x00000800 ? '1' : '0'), \
//     (word & 0x00000400 ? '1' : '0'), \
//     (word & 0x00000200 ? '1' : '0'), \
//     (word & 0x00000100 ? '1' : '0'), \
//     (word & 0x00000080 ? '1' : '0'), \
//     (word & 0x00000040 ? '1' : '0'), \
//     (word & 0x00000020 ? '1' : '0'), \
//     (word & 0x00000010 ? '1' : '0'), \
//     (word & 0x00000008 ? '1' : '0'), \
//     (word & 0x00000004 ? '1' : '0'), \
//     (word & 0x00000002 ? '1' : '0'), \
//     (word & 0x00000001 ? '1' : '0')

