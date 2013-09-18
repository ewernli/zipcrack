//#include <StdAfx.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

void	printrow( unsigned char* data, int size);
int		rip(char* filename, unsigned char* seeds, int MAXFILES);

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

#define LG(adr) fread( adr, 1, 4, f)  // Read 4 bytes
#define SH(adr) fread( adr, 1, 2, f)  // Read 2 bytes
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



int rip(char* argv, unsigned char* seeds, unsigned int* sizes, int MAXFILES)
{
	char*	filename;
	FILE*	f;
	zheader* header;
	int n=0;
	long	size;

	header = (zheader*) malloc( sizeof(zheader) );

	filename = argv;
	f = fopen(filename,"rb");
	if( f==NULL)
	{

		printf("Fail to open file %s\n",filename);
		exit(0);
	}

	printf("| name                      | size      | original   | method          | byte |\n");
	printf("|---------------------------|-----------|------------|-----------------|------|\n");

	while( !feof(f) && (n<MAXFILES) )
	{
		LG( &header->sig );
		if( header->sig == 0x04034b50)
		{
			SH( &header->version );
			SH( &header->gpflag );
			SH( &header->compress );
			SH( &header->lasttime );
			SH( &header->lastdate );
			LG( &header->crc );
			LG( &header->cmpsize );
			size =  header->cmpsize;
			LG( &header->origsize );
			SH( &header->namelength );
			SH( &header->extralength );

			header->filename = (unsigned char*) malloc(header->namelength+1);
			memset(header->filename,0, header->namelength+1);
			fread(header->filename, 1, header->namelength, f);
			header->extra = (unsigned char*) malloc(header->extralength);
			fread( header->extra, 1, header->extralength, f);
			//printrow(  header->extra, header->extralength );
			//header->data = (unsigned char*) malloc(size);
			//fread( header->data, 1, size, f);

			header->data = (unsigned char*) malloc(10);
			//BYTE( header->data);$
			fread( header->data, 1, 10, f);
			fseek(f,size-10,SEEK_CUR);

			if( header->gpflag & 4 )
				printf("Data descriptor\n");

			memcpy( & seeds[n*10] , &( header->data[0]), 1*10) ;
			sizes[n] = header->origsize;
			n++;

			printf("| %25s | %9d | %10d | %15s | %4X |\n",
				header->filename,size,header->origsize,methods[header->compress],header->data[0]);

			//printrow(header->data,size);

			free(header->filename);
			free(header->extra);
			free(header->data);
		}
	}


	printf("\n");
	free(header);
	fclose(f);

	return n;
}


void asktime()
{
	int	j,m,a,min,h;
	 struct tm when;
	time_t	file_t, boot_t;
	when.tm_isdst =0;

	printf("Enter date of encryption:\n");
	scanf("%d/%d/%d",&j,&m,&a);
	printf("Enter time of encryption (hh:mm)\n");
	scanf("%d:%d",&h,&min);

	when.tm_mday = j;
	when.tm_mon = m-1;
	when.tm_year = a - 1900;
	when.tm_hour = h;
	when.tm_min = min ;
	file_t = mktime( &when );

	printf("Enter boot date:\n");
	scanf("%d/%d/%d",&j,&m,&a);
	printf("Enter boot time (hh:mm)\n");
	scanf("%d:%d",&h,&min);

	when.tm_mday = j;
	when.tm_mon = m-1;
	when.tm_year = a - 1900;
	when.tm_hour = h;
	when.tm_min = min ;
	boot_t = mktime( &when );

	printf(" Approximative (ticks+time) seed %X\n", (file_t+ (file_t-boot_t)*1000) );
}