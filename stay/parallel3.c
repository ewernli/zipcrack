#include <stdio.h>
#include <time.h>
#include <signal.h>
#include <math.h>

/****
   Parrallel.c

	Attack on ZIP files as described by Michael Stay in "ZIP Attacks
	with Reduced Known Plaintext"

	Parallel implementation

****/

/*
	We need 5 archive and the 5 first clear and ciphered
	bytes of each archive.
*/

unsigned char plaintext[5][5] =
{
	{ 0x88, 0xF0, 0x46, 0xab, 0x32 },
	{ 0xdb, 0x5e, 0xab, 0x18, 0x61 },
	{ 0x78, 0xbb, 0x66, 0xf0, 0x8e },
	{ 0xd0, 0xc3, 0x35, 0x3e, 0x25 },
	{ 0xa1, 0xc4, 0x97, 0x82, 0x4d }
};

unsigned char data[5][5] =
{
	{ 0x13,0x20,0x6e,0x89,0x66 },
	{ 0x02,0xa9,0x3c,0x61,0x0c },
	{ 0x02,0xa9,0x3c,0x61,0x0c },
	{ 0x02,0xa9,0x3c,0x61,0x0c },
	{ 0x02,0xa9,0x3c,0x61,0x0c }
};

//#define PRINTF(x) printf x;
#define PRINTF( x ) ;

// precomputed tables
unsigned short temp_table[256][64];

static unsigned long crc_table[256];
static unsigned long crc_inv[256];

unsigned int	k1_all[ (1<<24) ];
unsigned int*	k1_table[256];
int				k1_size[256];

unsigned int	mulTab[256];
unsigned char	mTab2[256][2];
int				mTab2Counter[256];

#define C1 (data[0][0])
#define C2 (data[0][1])
#define S1 (plaintext[0][0])
#define S2 (plaintext[0][1])


unsigned char 		P1[5];  // P1_i
unsigned char		P2[5];  // P2_i
unsigned char 		P3[5];  // P3_i

unsigned int	crc0; 	// crc(k0_0,0)
unsigned int	crc2; 	// crc(k2_0,0)
unsigned int	msb;		// MSB( k1_0*K )
unsigned int	msb2;		// MSB( k1_0*K2 )
unsigned char	k3_0;		// k3_0
unsigned int 	k1_0;
unsigned	int 	k2_0;
unsigned int	k0_0;

/* first encryption */
unsigned int	k0_1[5];
unsigned int	k1_1[5];
unsigned int 	k2_1[5];
unsigned char	k3_1[5];
unsigned int	k0_2[5];
unsigned int	k1_2[5];
unsigned int 	k2_2[5];
unsigned char	k3_2[5];
unsigned int	k0_3[5];
unsigned int	k1_3[5];
unsigned int 	k2_3[5];
unsigned char	k3_3[5];
/* second encryption */
unsigned int	k0t_1[5];
unsigned int	k1t_1[5];
unsigned int 	k2t_1[5];
unsigned char	k3t_1[5];
unsigned int	k0t_2[5];
unsigned int	k1t_2[5];
unsigned int 	k2t_2[5];
unsigned char	k3t_2[5];
unsigned int	k0t_3[5];
unsigned int	k1t_3[5];
unsigned int 	k2t_3[5];
unsigned char	k3t_3[5];

unsigned int 		low[10];		// bounds on k1_0*K
unsigned int		up[10];
unsigned int 		low2[10];	// bounds on k1_0*K2
unsigned int		up2[10];

unsigned int	intk0,intk1,intk2;
unsigned char	intk3;

// Macro
#define MSB(x) (((x) & 0xFF000000 ) >> 24)
#define LSB(x) ((x) & 0x000000FF )
#define MULT(x)         ((mulTab[((x)>>24)&0xff]<<24) + \
                         (mulTab[((x)>>16)&0xff]<<16) + \
                         (mulTab[((x)>> 8)&0xff]<< 8) + \
                         (mulTab[((x)    )&0xff]    ))

#define K_INV    	0xD94fa8cd
#define K   		0x8088405
#define K2  		0xD4652819

#define crc32(crc,ch) (( (crc)>>8) ^ crc_table[ ((crc)^(ch)) & 0xFF ])

struct statistics{
	unsigned int	lsb;
	unsigned long  stage0;
	unsigned long  stage1;
	unsigned long  stage1pass;
	unsigned long  stage1drop;
	unsigned long stage2;
	unsigned long stage2pass;
	unsigned long stage2drop;
	unsigned long stage3;
	unsigned long stage3pass;
	unsigned long stage3drop;
	unsigned long stage4pass;
	unsigned long stage5;
	unsigned long stage6;
	unsigned long stage6pass;
	unsigned long stage6drop;
};

struct statistics	stat;

#define STAT 1

#if STAT
#define INC0		stat.stage0++;
#define INC1		stat.stage1++;
#define INC1PASS 	stat.stage1pass++;
#define INC1DROP 	stat.stage1drop++;
#define INC2		stat.stage2++;
#define INC2PASS 	stat.stage2pass++;
#define INC2DROP 	stat.stage2drop++;
#define INC3		stat.stage3++;
#define INC3PASS 	stat.stage3pass++;
#define INC3DROP 	stat.stage3drop++;
#define INC4PASS  stat.stage4pass++;
#define INC5  		stat.stage5++;
#define INC6	   stat.stage6++;
#define INC6PASS  stat.stage6pass++;
#define INC6DROP  stat.stage6drop++;
#define INCLSB		stat.lsb++;
#else

#endif
// prototypes

void gen_temp_table( unsigned short [][64] );
void gen_crc_table(unsigned long* crc_table, unsigned long* crc_inv);
void gen_k1_table(unsigned int* k1_ptr[], unsigned int table[], int k1_size[] );
void initMulTab( unsigned int mulTab[], unsigned char mTab2[256][2], int mTab2Counter[]);
void update_keys( unsigned char p);

void attack();
void stage1();
void stage2();
void stage3();
void stage4(int i);
void stage5();
void stage6(int j);
void stage7();
void stage8();
void filter();

/* NOTATIONS:
	keys from 1st encryption are written in the form: kN_i, with N = key number, i = index
	keys froms 2nd encryption are written in the form: ktN_i, with N = key number, i = index

	Plaintext bytes: Si
	First encryption: Pi
	Ciphered bytes (2nd encryption): Ci

*/


void set_plaintext( int i, unsigned char* buf)
{
	int j;
	for(j=0;j<5;j++)
		plaintext[i][j] = buf[j];
}

void set_ciphertext( int i, unsigned char* buf)
{
	int j;
	for(j=0;j<5;j++)
		data[i][j] = buf[j];
}

void attack()
{
	int i,j,l;
	unsigned int 	known_rest, known_msb;

	/* guess LSB crc(k0_0,0) */
   	// Hack j=0x10
   	for(j=0;j<256;j++)
	//for(j=0x10;j<0x12;j++)
	{
		INCLSB;
		printf("+ LSB %X\n",j);

		crc0 = j;
		k0_1[0] = crc0 ^ crc_table[ S1 ];

		/* guess MSB( k1_0 ) + carry */
		known_msb = known_rest = LSB( k0_1[0] )*K + 1;
		known_msb &= 0xFF000000;
		known_rest &= 0x00FFFFFF;
		for(l=0;l<256;l++)
		{
			msb = l<<24;
			// if carry bit
			low[0] = msb + 0x01000000 - known_rest;
			up[0] = msb + 0x01000000;
			k1_1[0] = msb + known_msb + 0x01000000;
			stage2();

			// if no carry bit
			low[0] = msb;
			up[0] = msb + 0x00FFFFFF - known_rest;
			k1_1[0] = msb + known_msb;
			stage2();
		}

	}
}


void stage2()
{
	int i,j;
	/* guess P2 */
	for(i=0;i<256;i++)
	{
		P2[0] = i;
		k3_1[0] = i ^ S2;

		/* k3i -> 64 k2i */
		for(j=0;j<64;j++)
		{
			k2_1[0] = temp_table[ k3_1[0] ][j];
			crc2 =  k2_1[0] ^ crc_table[ MSB(k1_1[0]) ];
			stage3();
		}
	}
}

void stage3()
{
	int i,t;
	unsigned int 	known_rest, known_msb;

	INC0;

	/* guess P1 */
	#if 1
	for(i=0;i<256;i++)
	{
		P1[0] = i;
		k3_0 = P1[0] ^ S1;
		k0t_1[0] = crc0 ^ crc_table[ P1[0] ];

		known_msb = known_rest = LSB( k0t_1[0] )*K + 1;
		known_msb &= 0xFF000000;
		known_rest &= 0x00FFFFFF;
		for(t=2;t>0;t--)
		{
			if( t==2 )
			{	/* carry */
				low[1] = msb + 0x01000000 - known_rest;
				up[1] = msb + 0x01000000;
				k1t_1[0] = msb + known_msb + 0x01000000;
			} else
			{ /* no carry */
				low[1] = msb;
				up[1] = msb + 0x00FFFFFF - known_rest;
				k1t_1[0] = msb + known_msb;
			}

			k2t_1[0] = crc2 ^ crc_table[ MSB(k1t_1[0]) ];
			k2t_1[0] &= 0xFFFFFFFC;
			k3t_1[0] = (( k2t_1[0] | 3) * ( k2t_1[0] | 2 )) >> 8;

			/* filter */
			INC1;
			if( (P2[0] ^ k3t_1[0]) == data[0][1] )
			{
				INC1PASS;
				INC2;
				stage4(0);
			} else {
				INC1DROP;
			}
		}
	}
	#endif
}

void stage4(int i)
{
	int t,u;
	unsigned int	m0_1,m1_1,m2_1;
	unsigned char	m3_1;
	unsigned int	n0_1,n1_1,n2_1;
	unsigned char	n3_1;
	unsigned int 	known_rest, known_msb;
	unsigned int 	known_rest2, known_msb2;
	int PRINT;

	/* PRINT */

	PRINT = 0;

	if(i==4)
	{
		INC2PASS;
		stage5();
		return;
	}

	k0_1[i+1] = crc0 ^ crc_table[ plaintext[i+1][0] ];
	#if 0
	if(PRINT) printf("%d > S1 %X\n",i,plaintext[i+1][0]);
	if(PRINT) printf("%d > m0_1 %X\n",i,k0_1[i+1]);
	#endif

	known_msb = known_rest = LSB( k0_1[i+1] )*K + 1;
	known_msb &= 0xFF000000;
	known_rest &= 0x00FFFFFF;

	for(t=2;t>0;t--)
	{
		if( t==2 )
		{	/* carry */
			low[2+i] = msb + 0x01000000 - known_rest;
			up[2+i] = msb + 0x01000000;
			k1_1[i+1] = msb + known_msb + 0x01000000;
		} else
		{ /* no carry */
			low[2+i] = msb;
			up[2+i] = msb + 0x00FFFFFF - known_rest;
			k1_1[i+1] = msb + known_msb;
		}



		k2_1[i+1] = crc2 ^ crc_table[ MSB( k1_1[i+1] ) ];
		k2_1[i+1] &= 0xFFFFFFFC;
		k3_1[i+1] = (( k2_1[i+1] | 3) * ( k2_1[i+1] | 2 )) >> 8;
		/* P2 for archive 1..5 */
		P2[i+1] = plaintext[i+1][1] ^ k3_1[i+1];

		P1[i+1] = plaintext[i+1][0] ^ k3_0;
		k0t_1[i+1] = crc0 ^ crc_table[ P1[i+1] ];

		#if 0
		if(PRINT) printf("%d > MSB m1_1 %X\n",i,k1_1[i+1]);
		if(PRINT) printf("%d > m2_1 %X\n",i,k2_1[i+1]);
		if(PRINT) printf("%d > m3_1 %X\n",i,k3_1[i+1]);
		if(PRINT) printf("%d > P2 %X\n",i,P2[i+1]);
		if(PRINT) printf("%d > P1 %X\n",i, P1[i+1] );
		if(PRINT) printf("%d > n0_1 %X\n",i,k0t_1[i+1]);
		#endif

		known_msb2 = known_rest2 = LSB( k0t_1[i+1] )*K + 1;
		known_msb2 &= 0xFF000000;
		known_rest2 &= 0x00FFFFFF;

		for(u=2;u>0;u--)
		{
			if( u==2 )
			{	/* carry */
				low[6+i] = msb + 0x01000000 - known_rest2;
				up[6+i] = msb + 0x01000000;
				k1t_1[i+1] = msb + known_msb2 + 0x01000000;
			} else
			{ /* no carry */
				low[6+i] = msb;
				up[6+i] = msb + 0x00FFFFFF - known_rest2;
				k1t_1[i+1] = msb + known_msb2;
			}


			k2t_1[i+1] = crc2 ^ crc_table[ MSB(k1t_1[i+1]) ];
			k2t_1[i+1] &= 0xFFFFFFFC;
			k3t_1[i+1] = (( k2t_1[i+1] | 3) * ( k2t_1[i+1] | 2 )) >> 8;
			#if 0
			if(PRINT) printf("%d > n1_1 %X\n",i,k1t_1[i+1]);
			if(PRINT) printf("%d > n2_1 %X\n",i,k2t_1[i+1]);
			if(PRINT) printf("%d > n3_1 %X\n",i,k3t_1[i+1]);
			if(PRINT) printf("%d > C %X\n",i,k3t_1[i+1] ^ P2[i+1]);
			#endif

			/* filter P2,i xor k3_1,i == C2,i*/
			if( ( P2[i+1] ^ k3t_1[i+1]) == data[i+1][1] )
			{
				stage4(i+1);
			}
			else
				INC2DROP;
		}
	}
}

void stage5()
{
	int i;
	int c;
	unsigned int crci, crcj;

	PRINTF((">\nGuess 23 bits + carry passed. Guess 26 more bits\n"));
	PRINTF(("P1 %X, P2 %X\n", P1[0],P2[0]));
	PRINTF(("crc0 [0..8] %X, MSB(k1_0*K) %X, crc2 [2..16] %X\n",crc0,msb,crc2));
	fflush(stdout);

	/* guess 8..15 of crc(k0_0,0) */
	for(c=0;c<256;c++)
	{
		crc0 = (crc0&0xFF) | (c<<8);

		/* guess MSB(k1_0*K2) */
		for(i=0;i<256;i++)
		{
			msb2 = i<<24;

			/* guess crc2 16..23 and 0..1 */
			for(crci=0;crci<256;crci++)
			{
				for(crcj=0;crcj<4;crcj++)
				{
					crc2 = (crc2&0xFFFC) | (crci<<16) | crcj ;
					/* run through all archives */
					INC3;
					stage6(0);
				}
			}
		}
	}

}

void stage6(int j)
{
	int t,u;
	unsigned int 	known_rest, known_msb;
	unsigned int 	known_rest2, known_msb2;
	int PRINT = 0;

	if(j==5)
	{
		INC3PASS;
		PRINTF(("Guess 26 bits + carry passed. \n"));
		PRINTF(("crc0 [0..15] %X, MSB(k1_0*K) %X, MSB(k1_0*K2) %X, crc2 [0..23] %X\n",crc0,msb,msb2,crc2));fflush(stdout);
		stage7();
		return;
	}

	/* first encryption */
	/* update k0_1 bit 8..15 */
	k0_1[j] = crc0 ^ crc_table[ plaintext[j][0] ];
	k0_2[j] = crc32(k0_1[j], plaintext[j][1] );
	known_msb = known_rest =  LSB( k0_1[j] )*K2
									+ LSB( k0_2[j] )*K
									+ K + 1;

	#if 0
	if(PRINT) printf("%d > k0_1 [0..15] %X, k0_2 [0..7] %X\n",j,k0_1[j],k0_2[j]);fflush(stdout);
	#endif

	known_msb &= 0xFF000000;
	known_rest &= 0x00FFFFFF;

	/* guess carry */
	for(t=2;t>0;t--)
	{
		if( t==2 )
		{	/* carry */
			low2[j] = msb2 + 0x01000000 - known_rest;
			up2[j] = msb2 + 0x01000000;
			k1_2[j] = msb2 + known_msb + 0x01000000;
		} else
		{ /* no carry */
			low2[j] = msb2;
			up2[j] = msb2 + 0x00FFFFFF - known_rest;
			k1_2[j] = msb2 + known_msb;
		}

		k2_1[j] = crc2 ^ crc_table[ MSB( k1_1[j] ) ];
		k2_2[j] = crc32( k2_1[j], MSB(k1_2[j]) );
		k3_2[j] = ( ( (k2_2[j]&0xFFFFFC) | 2) * ((k2_2[j]&0xFFFFFC) | 3) ) >> 8;
		P3[j] = plaintext[j][2] ^ k3_2[j] ;

		#if 0
		if(PRINT) printf( "%d > MSB k1_2 %X, MSB k1_1 %X, k2_1 [0..23] %X, k2_2 [0..15] %X, 8-bit k3_2 %X\n",
			j,k1_2[j], k1_1[j], k2_1[j], k2_2[j], k3_2[j]);
		#endif

		/* second encryption */
		/* update k0_1 bit 8..15 */
		k0t_1[j] = crc0 ^ crc_table[ P1[j] ];
		k0t_2[j] = crc32(k0t_1[j], P2[j] );
		known_msb2 = known_rest2 =  LSB( k0t_1[j] )*K2
										  + LSB( k0t_2[j] )*K
										  + K + 1;

		known_msb2 &= 0xFF000000;
		known_rest2 &= 0x00FFFFFF;

		/* guess carry */
		for(u=2;u>0;u--)
		{
			if( u==2 )
			{	/* carry */
				low2[5+j] = msb2 + 0x01000000 - known_rest2;
				up2[5+j] = msb2 + 0x01000000;
				k1t_2[j] = msb2 + known_msb2 + 0x01000000;
			} else
			{ /* no carry */
				low2[5+j] = msb2;
				up2[5+j] = msb2 + 0x00FFFFFF - known_rest2;
				k1t_2[j] = msb2 + known_msb2;
			}

			k2t_1[j] = crc2 ^ crc_table[ MSB( k1t_1[j] ) ];
			k2t_2[j] = crc32( k2t_1[j], MSB(k1t_2[j]) );
			k3t_2[j] = ( ((k2t_2[j]&0xFFFFFC) | 2) * ((k2t_2[j]&0xFFFFFC) | 3) ) >> 8;
			if( data[j][2] == (P3[j] ^ k3t_2[j]) )
			{
				stage6(j+1);
			}
			else
				INC3DROP;
		}
	}
}

void stage7()
{
	int i;
	unsigned char temp;

	for(i=0;i<256;i++)
	{
		k2_0 =  ( (crc2 ^ crc_table[i]) << 8) | i;
		temp = ((k2_0 | 3) * ((k2_0 | 3)^1) ) >> 8;  // LSB only
		if (k3_0 == temp)
		{
			INC4PASS;
			PRINTF(("Could complete 32-bit k2_0 : %X\n", k2_0));
			stage8();
		}
	}
}

unsigned int min( unsigned int t[], int size) {
	unsigned int minv = t[0];
	int	cnt;
	for(cnt=1;cnt<size;cnt++)
		minv = t[cnt] < minv ? t[cnt] : minv;
	return minv;
}

unsigned int max( unsigned int t[], int size) {
	unsigned int maxv = t[0];
	int	cnt;
	for(cnt=1;cnt<size;cnt++)
		maxv = t[cnt] > maxv ? t[cnt] : maxv;
	return maxv;
}

void stage8()
{
	unsigned int	i,j,k;
	unsigned low_bound,up_bound,low_bound2,up_bound2;
	unsigned int k_square;


	low_bound = max(low,10);
	up_bound = min(up,10);
	low_bound2 = max(low2,10);
	up_bound2 = min(up2,10);

	PRINTF(("bounds 1 [ %X ; %X ] range %X\n",low_bound,up_bound, up_bound-low_bound));
	PRINTF(("bounds 2 [ %X ; %X ] range %X\n",low_bound2,up_bound2, up_bound2-low_bound2));

	#if 1
	/* guess crc(k0_0,0) [16..23] */
	for(i=0;i<256;i++)
	{
		crc0 = (crc0&0xFFFF) | (i<<16);

		#if 0
		/* progress percentage */
		PRINTF(("Stage 8 %3.3f%%\r", i*100000/(256)/1000.));fflush(stdout);
		#endif

		/* iterate over k1_0 32-bit */
		k1_0 = low_bound*K_INV;
		k_square = low_bound*K;

		/* k1_0 within bounds */
		for(k=low_bound;k<=up_bound;k++)
		{
			INC5;
			if ( (k_square > low_bound2) && (k_square < up_bound2) ){
				INC6;
				filter();
			}

			/* k0_1*K = i <=> k0_1 = i*K_INV
				k0_1*K2 = k0_1*K*K = i*K
			*/
			k1_0 += K_INV;
			k_square += K;
		}
	}
	#endif
}


void filter()
{
	int i,j,k;
	unsigned char temp[5][5];
	unsigned char cipher[5];
	unsigned short t; // 16 bit
	int PRINT =0;
	int success;

	for(i=0;i<5;i++)
	{
		// intk0 = k0_0;
		intk1 = k1_0;
		intk2 = k2_0;
		intk3 = k3_0;
		temp[i][0] = plaintext[i][0] ^ intk3;

		for(j=0;j<3;j++)
		{
			if( j==0 ) {
				/* we have no value for k0_0; but we have crc0 [0..23] */
				intk0 = crc0 ^ crc_table[plaintext[i][0]];
				intk1 = ( intk1 + LSB( intk0) )*134775813 + 1;
				intk2 = crc32( intk2, MSB(intk1) );
				t = intk2 | 3;
				intk3 = LSB( (t*(t ^ 1)) >> 8 );
			} else {
				update_keys( plaintext[i][j] );
			}
			temp[i][j+1] = plaintext[i][j+1] ^ intk3;
		}
		/* save values */
		k0_3[i] = intk0;
		k1_3[i] = intk1;
		k2_3[i] = intk2;
		k3_3[i] = intk3;
		/* reset ; note that intk0 is unknown */
		intk1 = k1_0;
		intk2 = k2_0;
		intk3 = k3_0;
		cipher[0] = temp[i][0] ^ intk3;
		for(j=0;j<3;j++)
		{
			if( j==0 ) {
				/* we have no value for k0_0; but we have crc0 [0..23] */
				intk0 = crc0 ^ crc_table[temp[i][0]];
				intk1 = ( intk1 + LSB( intk0) )*134775813 + 1;
				intk2 = crc32( intk2, MSB(intk1) );
				t = intk2 | 3;
				intk3 = LSB( (t*(t ^ 1)) >> 8 );
			} else {
				update_keys( temp[i][j] );
			}
			cipher[j+1] = temp[i][j+1] ^ intk3;
		}
		/* save values */
		k0t_3[i] = intk0;
		k1t_3[i] = intk1;
		k2t_3[i] = intk2;
		k3t_3[i] = intk3;

		/* filter */
		if (cipher[3] != data[i][3])
		{
			INC6DROP
			return;
		}
	}
	INC6PASS
	PRINTF(("Completed crc(k0_0,0) [16..23] and checked with byte 4\n"));
	PRINTF(("crc0 %X, k1_0 %X, k2_0 %X, k3_0 %X\n",crc0, k1_0, k2_0, k3_0));

	#if 1
	/* guess last 8 bit of crc0 and compute k0_0 */
	for(k=0;k<256;k++)
	{
		/*
		PRINT = 0;
		if (k==0x3c)
			PRINT = 1;
		*/
		
		k0_0 =  ( (crc0 ^ crc_table[k]) << 8) | k;
		success =0;
		/* run through all archives */
		for(i=0;i<5;i++)
		{
			/* compute 32-bit k0_i */
			k0_1[i] = crc32( k0_0, plaintext[i][0] );
			k0_2[i] = crc32( k0_1[i], plaintext[i][1] );
			k0_3[i] = crc32( k0_2[i], plaintext[i][2] );
			k0t_1[i] = crc32( k0_0, temp[i][0] );
			k0t_2[i] = crc32( k0t_1[i], temp[i][1] );
			k0t_3[i] = crc32( k0t_2[i], temp[i][2] );

			/* restore values */
			intk0 = k0_3[i];
			intk1 = k1_3[i];
			intk2 = k2_3[i];
			intk3 = k3_3[i];
			update_keys( plaintext[i][3] );
			temp[i][4] = plaintext[i][4] ^ intk3;

			#if 0
			if (PRINT) printf("%d (1st) > k0_0 %X k0_1 %X k0_2 %X k0_3 %X\n",k0_0,k0_1[i],k0_2[i],k0_3[i]);
			if (PRINT) printf("%d > k0_3 %X, k1_3 %X, k2_3 %X, k3_3 %X, S4 %X, S5 %X, k3_4 %X, P5 %X\n",
				i,k0_3[i],k1_3[i],k2_3[i],k3_3[i],plaintext[i][3],plaintext[i][4],intk3,temp[i][4]);
			#endif
			/* restore values */
			intk0 = k0t_3[i];
			intk1 = k1t_3[i];
			intk2 = k2t_3[i];
			intk3 = k3t_3[i];
			update_keys( temp[i][3] );
			cipher[4] = temp[i][4] ^ intk3;

			#if 0
			if(PRINT) printf("%d (1st) > k0_0 %X k0_1 %X k0_2 %X k0_3 %X\n",k0_0,k0t_1[i],k0t_2[i],k0t_3[i]);
			if(PRINT) printf("%d > k0_3 %X, k1_3 %X, k2_3 %X, k3_3 %X, S4 %X, S5 %X, k3_4 %X, P5 %X\n",
				i,k0t_3[i],k1t_3[i],k2t_3[i],k3t_3[i],temp[i][3],temp[i][4],intk3,cipher[4]);
			#endif
			/* filter */
			if (cipher[4] == data[i][4])
				success++;
		}
		if (success == 5)
		{
			printf("/***\n|* Found a possible representation!\n\\***\n");
			PRINTF(("crc0 [0..15] %X, MSB(k1_0*K) %X, MSB(k1_0*K2) %X, crc2 [0..23] %X\n",
																		crc0,msb,msb2,crc2));
			printf("k0_0 %X, k1_0 %X, k2_0 %X, k3_0 %X crc0 %X\n",k0_0, k1_0, k2_0, k3_0, crc0);
			fflush(stdout);
		}
	}
	#endif
}

void update_keys( unsigned char p)
{
	unsigned short temp; // 16 bit
	intk0 = crc32( intk0, p);
	intk1 = ( intk1 + LSB( intk0) )*134775813 + 1;
	intk2 = crc32( intk2, MSB(intk1) );
	temp = intk2 | 3;
	intk3 = LSB( (temp*(temp ^ 1)) >> 8 );
}


void handler (int signum) {
	printf("STATISTICS:\n----------\n");
	printf("LSB crc0: %d / 256\n", stat.lsb);
	printf("Stage0 (guess 23 bit + P2) :\n");
	printf("total: %d \n",stat.stage0);
	printf("Stage1 (guess P1 + carry + filter):\n");
	printf("total: %d  pass: %d, drop %d\n",stat.stage1,stat.stage1pass,stat.stage1drop);
	printf("Stage2 (verify with 4 archives):\n");
	printf("total: %d  pass: %d, drop %d\n",stat.stage2,stat.stage2pass,stat.stage2drop);
	printf("Stage3 (guess 26 bits, verify with 5 archives)\n");
	printf("total: %d, pass: %d, drop: %d\n",stat.stage3,stat.stage3pass,stat.stage3drop);
	printf("Stage4 Complete 32-bit k2_0\n");
	printf("successed: %d\n",stat.stage4pass);
	printf("Guess [16..23] crc(k0_0,0) and run through k1_0\n");
	printf("total: %d\n",stat.stage5);
	printf("Filter with 5 archives\n");
	printf("total: %d, pass: %d, drop: %d\n",stat.stage6,stat.stage6pass,stat.stage6drop);
	fflush(stdout);
	//exit(0);
 }


#define INTK0 0x0808973C
#define INTK1 0xDB5923E5
#define INTK2 0x7A9E8B29
#define INTK3 0x2E

//#define _GENRANDOM

int main_attack()
{
	unsigned int i;
	time_t	t1,t2,now;
	double diff;

	int m,n;
	unsigned char c;

	t1 = time(NULL);
	gen_temp_table( temp_table );
	gen_crc_table( crc_table, crc_inv );
 	initMulTab( mulTab, mTab2, mTab2Counter);
	memset(&stat, 0, sizeof(struct statistics));

#ifdef _GENRANDOM
	/* generate double encrypted stream bytes */
	printf("First encryption\n");
	for(m=0;m<5;m++)
	{
		intk0 = INTK0;
		intk1 = INTK1;
		intk2 = INTK2;
		intk3 = INTK3;

	 	for(n=0;n<5;n++)
		{
			data[m][n] = plaintext[m][n] ^ intk3;
			update_keys( (unsigned  char) plaintext[m][n] );
			printf("%02x ",data[m][n]);
		}
		printf("\n");
	}
	printf("Second encryption\n");
	for(m=0;m<5;m++)
	{
		intk0 = INTK0;
		intk1 = INTK1;
		intk2 = INTK2;
		intk3 = INTK3;

	 	for(n=0;n<5;n++)
		{
			c = data[m][n] ^ intk3;
			update_keys( data[m][n] );
			data[m][n] = c;
			printf("%02x ",c);
		}
		printf("\n");
	}
	printf("k0_0 %X, k1_0 %X, k2_0 %X, k3_0 %X\n",INTK0, INTK1, INTK2, INTK3);
#else
	printf("Random bytes\n");
	for(m=0;m<5;m++)
	{
	 	for(n=0;n<5;n++)
		{
			printf("%02X ",plaintext[m][n]);
		}
		printf("\n");
	}
	printf("Ciphertext\n");
	for(m=0;m<5;m++)
	{
	 	for(n=0;n<5;n++)
		{
			printf("%02X ",data[m][n]);
		}
		printf("\n");
	}
#endif

#ifdef _UNIX
	signal (SIGQUIT, handler);
#endif

	printf("Started on %s", ctime(&t1));
	attack();
	t2 = time(NULL);
	printf("Finished on %s", ctime(&t2));
	diff = difftime(t2,t1);

	printf("Attack took %d sec\n", (int) diff);

	// uncomment if you want statistics
	//handler(0);
	return;
}











