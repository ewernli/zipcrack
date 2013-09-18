#include <stdio.h>
#include <time.h>

/****
   Attack.c

   Implementation of Biham and Kocher's Attack.
   The Attack requires 13 plaintext bytes, including 8
   consecutive bytes. 32-bit values key0, key1, key2 are used
   to represent the internal key at a given position. These
   8 bytes are used to compute (2^38) possible internal representation
   of the key. The 5 extra bytes are used to filter among
   these 2^38 keys which is the one.
****/

struct  knownbyte{
	short		position;	// position within the data
	unsigned char	plaintext;	// original plaintext
} ;

// We need to know 8 CONSECUTIVE clear bytes
struct knownbyte clearbytes[8] =
{ {7,0x4c},{6,0xec},{5,0xf4},{4,0xff},
  {3,0xbb},{2,0x83},{1,0xfb},{0,0x3d} };

struct knownbyte checkbytes[6] =
{ {8,0xac},{9,0xe5},{10,0xd8},{11,0x7a},
  {12,0x5b},{13,0x45} };

unsigned char		key3[8];	// corresponding key3;  key3 = P xor C
unsigned int		key2[8];	// last key will be only 30-bit
unsigned int		key1[6];	// last key has only 8 bit (msb only)
unsigned int		key0[4];

//unsigned char* data;			// pointer to the encrypted data
char data[] = { 0x13, 0x20, 0x6e, 0x89,
 	        0x66, 0x38, 0x98, 0x54,
		0x14, 0x9f, 0xd8, 0xa5,
		0x28, 0x3e, 0x62, 0x12,
		0x3d, 0xa5, 0xc5, 0x98,
		0x9d, 0x73, 0xb4, 0x92,
		0x43, 0xe9, 0xfc, 0x1e,
		0xfb, 0xc2, 0x39 };

int size = 31;				// size of the data

/***
 SCHEMA OF THE ATTACK

 1. fing key3[13..7] - attack()
 2. guess 2^22 key2[13] - guess_K2()
 3. for each key2[13]
 	3.1 build a tree (T2) - build_T2()
 	3.2 for each path in the tree - explore_T2()
		3.2.1 guess 2^16 key1[13] - guess_K1()
		3.2.1 for each key1[13]
			3.2.1.1 build a tree (T1) - build_T1()
			3.2.1.2 for each path within the tree - explore_T1()
				3.2.1.2.1 find key0[13..9] - find_K0()
				3.2.1.2.2 find the internal representation of the key
				3.2.1.2.3 filter with 5 other known bytes
			3.2.1.4 delete tree (T1)
	3.3 delete tree (T2)

****/

// Cardinality of guesses for Key2
#define KEY2GUESS (1<<22)
#define TEMPGUESS (64)
#define HIGH16BIT (1<<16)

// precomputed tables
unsigned short temp_table[256][64];

static unsigned long crc_table[256];
static unsigned long crc_inv[256];

unsigned int*	k1_all;
unsigned int**	k1_table;
int*		k1_size;

unsigned int	mulTab[256];
unsigned char	mTab2[256][2];
int		mTab2Counter[256];

// Macro
#define MSB(x) (((x) & 0xFF000000 ) >> 24)
#define LSB(x) ((x) & 0x000000FF )
#define MULT(x)         ((mulTab[((x)>>24)&0xff]<<24) + \
                         (mulTab[((x)>>16)&0xff]<<16) + \
                         (mulTab[((x)>> 8)&0xff]<< 8) + \
                         (mulTab[((x)    )&0xff]    ))

// prototypes

void gen_temp_table( unsigned short [][64] );
void gen_crc_table(unsigned long* crc_table, unsigned long* crc_inv);
void gen_k1_table(unsigned int** k1_ptr, unsigned int* table, int* k1_size );
void initMulTab( unsigned int mulTab[], unsigned char mTab2[256][2], int mTab2Counter[]);

void guess_K2();
void build_T2(unsigned int k2);
void complete_32_bit();
void guess_K1();
void build_T1(unsigned int k1_n, int level);
void filter();

void attack()
{
	int i;
	/* compute key3 1..8 */
	for(i=0;i<8;i++)
	{
		key3[i] = clearbytes[i].plaintext ^ data[ clearbytes[i].position ];
		// printf("key3 %d = 0x%2X ",i,key3[i]);
	}


	guess_K2();
}

void guess_K2()
{
	unsigned int key2_13;
	int i,j;
	for(i=0;i<TEMPGUESS;i++)
	{
		key2_13  = temp_table[ key3[0]][ i ];	// bit 0..15 ; 0..1 unknown
		printf("\n%02d - 0x%04X\n",i,key2_13);
		fflush(stdout);

		for(j=0;j<HIGH16BIT;j++)
		{
			key2_13 &= 0x0000FFFF;  	// clear bit16..31
			key2_13 |= (j<<16);		   // set bit 16..31

			if( (j&0x000F)==0) {
				printf("%3.1f%%\r", ((float)(j*1000/HIGH16BIT))/10.0 ); fflush(stdout);
			}

			build_T2(key2_13);
		}
	}
}

void build_T2(unsigned int k2_0)
{
	unsigned int 	left;
	unsigned int	right_0, right_1, right_2, right_3, right_4, right_5, right_6, right_7;
	int		i_0, i_1, i_2, i_3, i_4, i_5, i_6, i_7;

	key2[0]=k2_0;
	// Level = 0
	right_0 = (key2[0] << 8) ^ crc_inv[ MSB(key2[0]) ];
	for(i_0=0;i_0<64;i_0++) {
		left = temp_table[ key3[1] ][i_0];
		if(  (right_0 & 0xFC00) == (left & 0xFC00) ) {
			key2[1] = (left&0x0000FFFF) | (right_0&0xFFFF0000);

			// Level = 1
			right_1 = (key2[1] << 8) ^ crc_inv[ MSB(key2[1]) ];
			for(i_1=0;i_1<64;i_1++) {
				left = temp_table[ key3[2] ][i_1];
				if( (right_1 & 0xFC00) == (left & 0xFC00) ) {
					key2[2] = (left&0x0000FFFF) | (right_1&0xFFFF0000);

					// Level = 2
					right_2 = (key2[2] << 8) ^ crc_inv[ MSB(key2[2]) ];
					for(i_2=0;i_2<64;i_2++) {
						left = temp_table[ key3[3] ][i_2];
						if( (right_2 & 0xFC00) == (left & 0xFC00) ) {
							key2[3] = (left&0x0000FFFF) | (right_2&0xFFFF0000);

							// Level = 3
							right_3 = (key2[3] << 8) ^ crc_inv[ MSB(key2[3]) ];
							for(i_3=0;i_3<64;i_3++) {
								left = temp_table[ key3[4] ][i_3];
								if( (right_3 & 0xFC00) == (left & 0xFC00) ) {
									key2[4] = (left&0x0000FFFF) | (right_3&0xFFFF0000);

									// Level = 4
									right_4 = (key2[4] << 8) ^ crc_inv[ MSB(key2[4]) ];
									for(i_4=0;i_4<64;i_4++) {
										left = temp_table[ key3[5] ][i_4];
										if( (right_4& 0xFC00) == (left & 0xFC00) ) {
											key2[5] = (left&0x0000FFFF) | (right_4&0xFFFF0000);

											// Level = 5
											right_5 = (key2[5] << 8) ^ crc_inv[ MSB(key2[5]) ];
											for(i_5=0;i_5<64;i_5++) {
												left = temp_table[ key3[6] ][i_5];
												if( (right_5& 0xFC00) == (left & 0xFC00) ) {
													key2[6] = (left&0x0000FFFF) | (right_5&0xFFFF0000);

													// Level = 6
													right_6 = (key2[6] << 8) ^ crc_inv[ MSB(key2[6]) ];
													for(i_6=0;i_6<64;i_6++) {
														left = temp_table[ key3[7] ][i_6];
														if( (right_6& 0xFC00) == (left & 0xFC00) ) {
															key2[7] = (left&0x0000FFFF) | (right_6&0xFFFF0000);

															complete_32_bit();
															guess_K1();
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
}


void complete_32_bit()
{
	int 	i;
	unsigned int	t;

	for( i=7;i>0;i--) {
		// key2_i = key2_i+1 << 8 xor crcinv[ MSB( key2_i+1 ) ] xor MSB( key1_i+1 )
		t = key2[ i ] ^ crc_inv[ MSB( key2[ i-1 ] ) ];
		key2[ i-1 ] &= ( 0xFFFFFFFC );
		key2[ i-1 ] |= ( (t & 0x00000300) >> 8 );
	}
}

#define K    	0xD94fa8cd
#define K_INV   0x8088405

void guess_K1()
{
	int i;
	unsigned char	index;
	unsigned int*	guess;
	int		size;

	// msb(key1) 0..5
	for( i= 6; i>0;i--)
	{
		key1[ i-1 ] = 0;
		key1[ i-1 ] = ( key2[ i-1 ] << 8 ) ^ crc_inv[ MSB( key2[i-1] ) ] ^ key2[i];
		key1[ i-1 ] = (key1[i-1]<<24)&0xff000000;
	}

	index = MSB( key1[1] - K*key1[0] );
	size = k1_size[ index ];
	guess = k1_table[ index ];

	for( i=0;i<size;i++ )
	{
		/*
		if(i %(1<<12)==0) {
			printf("."); fflush(stdout);
		}
		*/
		key1[0] = (key1[0] &0xFF000000) | (guess[i] & 0x00FFFFFF);
		build_T1(  key1[0], 0 );
	}
}

unsigned int	intk0,intk1,intk2;
unsigned char	intk3;
#define crc32(crc,ch) (( (crc)>>8) ^ crc_table[ ((crc)^(ch)) & 0xFF ])

void update_keys( unsigned char p)
{
	unsigned short temp; // 16 bit
	intk0 = crc32( intk0, p);
	intk1 = ( intk1 + LSB( intk0) )*134775813 + 1;
	intk2 = crc32( intk2, MSB(intk1) );
	temp = intk2 | 3;
	intk3 = LSB( (temp*(temp ^ 1)) >> 8 );
}

void filter()
{
	int i;
	unsigned char p;
	unsigned int  temp;

	/* LSB key0 0..3
	for(i=0;i<4;i++)
		key0[i]=  (key1[i]-1)*K-key1[i+1];
	*/


	// deduce 4 byte of key0_0
	temp = key0[0] ^ crc_table[ LSB(key0[1]) ^ clearbytes[1].plaintext];  // 0..7
	key0[1] &= 0x000000FF;
	key0[1] |=  ( (temp & 0x000000FF) << 8 );
	temp = key0[1] ^ crc_table[ LSB(key0[2]) ^ clearbytes[2].plaintext]; // 0..15
	key0[2] &= 0x000000FF;
	key0[2] |=  ( (temp & 0x0000FFFF) << 8 );
	temp = key0[2] ^ crc_table[ LSB(key0[3]) ^ clearbytes[3].plaintext]; // 0..23
	key0[3] &= 0x000000FF;
	key0[3] |=  ( (temp & 0x00FFFFFF) << 8 );

	intk3 = key3[3];
	intk2 = key2[3];
	intk1 = key1[3];
	intk0 = key0[3];

	for(i=3;i>=0;i--)
	{	p = data[ clearbytes[i].position ] ^ intk3;
		if( intk3 != key3[i] ) return;
		update_keys(p);
	}
	for(i=0;i<6;i++)
	{
		p = data[ checkbytes[i].position ] ^ intk3;
		if( p != checkbytes[i].plaintext ) return;
		update_keys(p);
	}

	printf("internal key [%d] : k0=%X, k1=%X, k2=%X, k3=%X\n",checkbytes[i-1].position+1, intk0,intk1,intk2,intk3 );
	printf("FOUND INTERNAL REPRESENTATION!\n");

}

int main( int argc, char* argv[])
{
	unsigned int i;
	time_t	t1,t2,now;
	double diff;

	k1_all = (int*) malloc( sizeof(int)* (1<<24) );
	k1_table = (int*) malloc( sizeof(unsigned int*) *256);
	k1_size = (int*) malloc( sizeof(unsigned int)*256);
	memset(k1_table, 0, sizeof(unsigned int*) * 256);
	memset(k1_size,0,sizeof(int)*256);

	t1 = time(NULL);
	gen_temp_table( temp_table );
	gen_crc_table( crc_table, crc_inv );
 	initMulTab( mulTab, mTab2, mTab2Counter);
	gen_k1_table( k1_table, k1_all, k1_size );

	now = time(NULL);
	printf("Starting searching on %s", ctime(&now));
	attack();
/*	key2[0]=0x46513bc5;
	key1[0]=0x4d000000;
	key1[1]=0xdc000000;
	key1[2]=0x2a000000;
	key1[3]=0xc9000000;
	key1[4]=0x72000000;
	key1[5]=0xd5000000;

	build_T1(0x4d268020,0);
*/
	now = time(NULL);
	printf("Finished on %s", ctime(&now));

	t2 = time(NULL);
	diff = difftime(t1,t2);

	printf("Attack tooked %d sec\n", (int) diff);

	return;
}

/****
   build_T1

   optimized recursive loop
****/

void build_T1(unsigned int k1_n0, int level)
{
	unsigned int 	k1_n1, k1_n2;
	int				k;
	unsigned char	diff,t;
	unsigned char	lsb0_n0;

	key1[level] = k1_n0;
	//printf("L=%d K=%X\n",level,k1_n0);
	if(level==4)
	{
		//printf("key1 %X %X %X %X %X\n",key1[0],key1[1],key1[2],key1[3],key1[4]);fflush(stdout);
		filter();
		return;
	}

	k1_n1 = MULT(k1_n0 - 1);  // k1_n1 + LSB(k1_n0)
	k1_n2 = MULT(k1_n1 - 1);
	diff = MSB( k1_n2 - (key1[level+2]&0xFF000000) );

	// test with diff and diff-1
	for(t=0; t<2; t++, diff--) {
		//printf("# k=%d\n", mTab2Counter[diff]);
		for(k=0;k<mTab2Counter[diff];k++)
		{
			lsb0_n0 = mTab2[diff][k];
			//printf("LSB=%X\n",lsb0_n0);
			if(  MSB(k1_n1 - lsb0_n0) == MSB(key1[level+1]) )
			{
				key0[level] = (unsigned int) lsb0_n0;
				build_T1( k1_n1 - lsb0_n0, level+1);
			}
		}
	}
}








