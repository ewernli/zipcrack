#include <stdio.h>

/****
  usage: decrypt filename [password]

  Simple programm used to rip the compressed data of the first file in the archive.
  If data were encrypted, decrypt them with the password given in parameters and output them.
  Doesn't deal with directory structure.
****/

void printrow( unsigned char* data, int size);
void decrypt( unsigned char* data, int size, char* password );
unsigned long get_crc( FILE *fp);
void gen_table(void);
unsigned long crc32( unsigned long pval, unsigned char ch);
void update_keys( unsigned char p);
void process_keys( char* password );

void set_ciphertext( int i, unsigned char* buf);
void set_plaintext( int i, unsigned char* buf);

typedef struct {
	unsigned long	sig;
	unsigned short	version;
	unsigned short 	gpflag;
	unsigned short	compress;
	unsigned short	lasttime;
	unsigned short	lastdate;

	unsigned long	crc;
	unsigned long	cmpsize;
	unsigned long	origsize;
	unsigned short	namelength;
	unsigned short	extralength;

	unsigned char*	filename;
	unsigned char*	extra;
	unsigned char*	data;
} zheader;

char* methods[] = {
	"no compression",
	"shrunk",
	"reduced (factor 1)",
	"reduced (factor 2)",
	"reduced (factor 3)",
	"reduced (factor 4)",
	"implode",
	"tokenize",
	"deflate",
	"enhanced deflate",
	"PKWARE implode",
	"reserved",
	"BZIP2"
};

char swp;

/*******
  Depending on the architecture, you need to read little- or big-endian data
*******/

/*
#define LG(adr) fread( adr, 4, 1, f);  \
		swp = *( ((unsigned char*)adr)+3); \
		*(((unsigned char*)adr)+3) = *(((unsigned char*)adr)); \
		*(((unsigned char*)adr)) = swp; \
		swp = *(((unsigned char*)adr)+2); \
		*(((unsigned char*)adr)+2) = *(((unsigned char*)adr)+1); \
		*(((unsigned char*)adr)+1) = swp; 
		
#define SH(adr) fread( adr, 2, 1, f); \
		swp = *(((unsigned char*)adr)+1); \
		*(((unsigned char*)adr)+1) = *(((unsigned char*)adr)); \
		*(((unsigned char*)adr)) = swp;
*/

#define LG(adr) fread( adr, 4, 1, f)
#define SH(adr) fread( adr, 2, 1, f)


#define BYTE(adr) fread( adr, 1, 1, f)  // Read 1 bytes
#define VAL(x) ( x>0x20 && x<0x7F ? x : '.' )

void printrow( unsigned char* p, int size)
{
	int i,j;
	for (i=0;i<size;i+=4) {
		for(j=i;j<i+4;j++)
		{
			if (j<size) printf("%02X ", p[j] ); else printf("   ");
		}
		printf("    ");
		for(j=i;j<i+4;j++)
		{
			if (j<size) printf("%1c ", VAL(p[j])); else printf("  ");
		}
		printf("\n");
	}
	printf("\n");
}

int main( int argc, char* argv[] )
{
	char*	filename;
	FILE*	f;
	zheader* header;
	int n=0;
	unsigned char seeds[5];
	unsigned int A,B;
	unsigned long x;
	unsigned int b,b2;
	unsigned int good;
	unsigned int seed;
	unsigned char random[10];
	
	int	size;
	int	i,j;
	unsigned char*	p;

	if(argc <2) {
		printf("usage: %s <filename>\n",argv[0]);
		printf("An ariche issued by either WinZip 8.0, WinZip 7.0, NetZip or Info-Zip must be given.\n");
		return 0;
	}

	header = (zheader*) malloc( sizeof(zheader) );

	filename = argv[1];
	f = fopen(filename,"rb");
	if(!f)
	{
		printf("Couldn't open file %s.\n",argv[1]);
		return;
	}
	printf("| name        | size      | original    | method          | seed    |\n");
	printf("|-------------|-----------|-------------|-----------------|---------|\n");

	while( !feof(f) && n<5)
	{
		//printf("file %d\n",n);
		LG( &header->sig );
		if( header->sig == 0x04034b50)
		{
			//printf("Header ok!\n");
			SH( &header->version );
			SH( &header->gpflag );
			SH( &header->compress );
			SH( &header->lasttime );
			SH( &header->lastdate );
			LG( &header->crc );
			LG( &header->cmpsize );
			size = header->cmpsize;
			LG( &header->origsize );
			SH( &header->namelength );
			SH( &header->extralength );

			header->filename = (char*) malloc(header->namelength+1);
			memset(header->filename,0, header->namelength+1);
			fread(header->filename, 1, header->namelength, f);
			header->extra = (unsigned char*) malloc(header->extralength);
			fread( header->extra, 1, header->extralength, f);
			//printrow(  header->extra, header->extralength );
			header->data = (char*) malloc(size);
			fread( header->data, 1, size, f);
			
			set_ciphertext(n, header->data);
			
			seeds[n++] = header->data[0];
			printf("| %11s | %9d | %11d | %15s | %7X |\n",
				header->filename,size,header->origsize,methods[header->compress],header->data[0]);

			//printrow(header->data,size);

			free(header->filename);
			free(header->extra);
			free(header->data);
		}
	}


	printf("\n");

	/* set seed */
	#if 0
	x=0x12345678;
	for(i=0;i<5;i++)
	{
		seeds[i]=(x>>23)&0xFF;
		//x = 0x343FD*x + 0x269EC3;
		x = 0x343FD*x + 0;
		for(j=0;j<9;j++)
			//x = 0x343FD*x + 0x269EC3;
			x = 0x343FD*x + 0;
	}
	#endif

	/*
	seeds[0] = 0xb9;
	seeds[1] = 0x7f;
	seeds[2] = 0x74;
	seeds[3] = 0xb0;
	seeds[4] = 0x63;
	*/

	printf("Seeds:\n");
	for(i=0;i<5;i++)
	{
		printf("%X ",seeds[i]);
	}
	printf("\n");

	#define _VER7

	/* compute new constants for PRNG */
	#ifdef _VER7
	//printf("VER7\n");
	A=1;
	B=0;
	for(i=0;i<10;i++)
	{
		B+= A*0x269EC3;
		A *= 0x343FD;
	}
	#endif
	#ifdef _VER80
	//printf("VER80\n");
	A=1;
	B=0;
	for(i=0;i<10;i++)
	{
		A *= 0x343FD;
	}
	#endif

	seed =0;
	for(b=0;b<(1<<23);b++)
	{
		// for( b2=0;b2<2;b2++)
		{
			x= ( seeds[0] << 23) | ( (b) & 0x7FFFFF) | (b2<<31);
			good = 1;
			for(i=0;i<4;i++)
			{
				x = A*x + B;
				if (((x>>23)&0xFF)!=seeds[i+1])
				{
					good = 0;
				}
			}
			if (good ==1)
			{
				seed= ( seeds[0] << 23) | ( (b) & 0x7FFFFF) | (b2<<31) ;
				printf("possible seed: %08X\n",seed);
				
				srand(seed);
				x=seed;
				for(i=0;i<5;i++)
				{
					printf(" file %d: ",i);
					for(j=0;j<10;j++)
					{
						random[j] = (seed>>23)&0xFF;
						printf("%02X ", random[j]);
						#ifdef _VER7
						seed = 0x343FD*seed + 0x269EC3;
						#endif
						#ifdef _VER80
						seed = 0x343FD*seed + 0;
						#endif
						x=rand();	
					}
					printf("\n");
					set_plaintext(i,random);
				}
	
			}
		}
	}

	free(header);
	fclose(f);

	main_attack();
	
	return;
}

