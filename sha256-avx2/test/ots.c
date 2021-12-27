#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "../wots.h"
#include "../api.h"
#include "../params.h"
#include "../randombytes.h"

#define SPX_MLEN 32
#define SPX_SIGNATURES 1

int main()
{
    int ret = 0;
    int i;

    /* Make stdout buffer more responsive. */
    setbuf(stdout, NULL);

    unsigned char pk[SPX_N*SPX_WOTS_LEN];
    unsigned char sig[SPX_N*SPX_WOTS_LEN];
    unsigned char pub_seed[SPX_N];
    unsigned char m[SPX_MLEN];
    uint32_t addr[8];

    randombytes(m, SPX_MLEN);


    memset(sig,0,sizeof(sig));
    memset(addr,0,sizeof(addr));
    memset(pub_seed,0,sizeof(pub_seed));
    
    
    
    double st=clock();
    for(int T=0;T<1000;T++){
        wots_pk_from_sig(pk,sig,m,pub_seed,addr);
    }
    printf("%.6f\n",(clock()-st)/CLOCKS_PER_SEC);


    return ret;
}

