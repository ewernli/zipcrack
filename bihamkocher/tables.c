/****
	table.c
****/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/stat.h>

typedef struct
{	int index;
  	int value;
} couple;

int couple_cmp ( couple* c1, couple* c2)
{
	/* compare function should return
	   <0 if c1 < c2
	   0 if c1 == c2
	   >0 if c1 > c2
	*/
	return (c1->index > c2->index ? 1 : (c1->index < c2->index ? -1 : 0) );
}

#define MSB(x)   (((x)&0xFF000000)>> 24)
#define LSB(x)   ((x)&0x000000FF)
#define T1SIZE 	 (256*64)

void gen_temp_table(unsigned short table[][64])
{
	// unsigned short t[256][64]
	int i;
	unsigned short temp;
	unsigned char  k3;
	char filled[256];


	for( i=0;i<256;i++) filled[i]=0;

	for( i=0;i<T1SIZE;i++)
	{
		temp = (i<<2) | 3;
		k3 = LSB( (temp*(temp^1))>>8);
		table[k3][ filled[k3] ] = temp;
		filled[k3]++;
	}

	#if DEBUG
	for( i=0;i<256;i++) printf("Filled %d temp for key3=0x%2X\n" , filled[i], i);
	#endif
}

void gen_crc_table(unsigned long* crc_table, unsigned long* crc_inv) /* build the crc table */
{
    unsigned long crc, poly;
    int	i, j;

    poly = 0xEDB88320L;
    for (i = 0; i < 256; i++)
        {
        crc = i;
        for (j = 8; j > 0; j--)
            {
            if (crc & 1)
                crc = (crc >> 1) ^ poly;
            else
                crc >>= 1;
            }
        crc_table[i] = crc;
	crc_inv[crc >> 24] = (crc << 8) ^ i;
        }
}

int load_k1_table( unsigned char msb, unsigned int** t )
{
	FILE*		f;
	char		filename[16];
	struct	stat	buff;
	int		size = 0;
	int     	err;

	sprintf( filename, "tables/table%03d", msb );
/*	err = stat(filename,&buff); assert( err == -1);
	size = statb.st_size/4;
	fread( *t, 4, size, f);
*/
	f = fopen( filename, "r" ); assert( f );
	// table is maximum 258k = 2^16 + 512 entries
	*t = (unsigned int*) malloc(  ((1<<16) + 512)*4 ); assert( *t );
	size=-1;
	while( fread( &( (*t)[++size] ), 4, 1, f) )
		;
	fclose(f);
	printf("%s -> %d\n", filename, size);
	return size;
}

#define MAX (1<<24)  // 2^24
#define K 3645876429UL

void gen_k1_table(unsigned int** k1_ptr, unsigned int *table, int* k1_size )
{
	/*
		table -> MAX
		k1_ptr -> 256
		k1_size -> 256
	*/

	unsigned int i;
	unsigned int* k1_table[256];
	unsigned char 	lastval;
	int		size;
	couple*t;
	t = (couple*) malloc ( sizeof(couple)*MAX);

	printf("Compute values\n");
	for(i=0;i<MAX;i++)
	{
		t[i].index = MSB(i*K - K);
		t[i].value = i;
	}

	printf("Sort values\n");
	qsort (t, MAX, sizeof (couple), couple_cmp);

	printf("Split into separate tables \n");
	lastval=t[i].index;
	k1_ptr[ lastval ] = &(table[0]);
	size = 0;
	for(i=0;i<MAX;i++)
	{
		if (t[i].index != lastval) {
			k1_size[ lastval ] = size;
			lastval = t[i].index;
			k1_ptr[ lastval ] = &(table[i]);
			size = 0;
		}

		table[i] = t[i].value;
		size++;
	}
	k1_size[ lastval ] = size;

	/*
	for(i=0;i<256;i++)
		printf("table %03d = %d\n",i,k1_size[i]);
	*/
}

void initMulTab( unsigned int mulTab[], unsigned char mTab2[256][2], int mTab2Counter[])
{
	unsigned int	i, prod;
	unsigned char	j;

	memset(mTab2Counter, 0, sizeof(mTab2Counter));
	for( i = 0, prod = 0; i < 256; i++, prod+=K )
	{
		mulTab[i] = prod;
		j = MSB(prod);
		mTab2[j][mTab2Counter[j]++] = i;
	}

	/*
	for(i=0;i<256;i++)
	 	printf("entry %d contain %d elements\n",i,mTab2Counter[i]);
	*/
}
