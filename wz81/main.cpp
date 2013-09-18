#include <windows.h>
#include <Winbase.h>

#include <stdio.h>
#include <string.h>
#include <sys/timeb.h>
#include <time.h>
#include <stdlib.h>
#include <windows.h>

int loadfile( char* filename);
int test_wz( char* file, unsigned int low,unsigned  int up, unsigned char* res);
void asktime(unsigned int* low, unsigned int* up);
void recover_representation();
void set_plaintext_buff(unsigned char* );
/* syntax: wz <zip archive> <low> <up> [-u]*/

void askbias()
{
	int	j,m,a,min,h,sec;
	struct tm* when;
	time_t aclock;
	time_t bias;
	time_t boot_t, file_t;
	time( &aclock );   // Get time in seconds
	when = localtime( &aclock );   // Convert time to struct tm form 

	// bias
	printf("Enter this boot date (j/m/a):\n");
	scanf("%d/%d/%d",&j,&m,&a);
	
	printf("Enter this boot time (hh:mm:ss)\n");
	scanf("%d:%d:%d",&h,&min,&sec);

	when->tm_mday = j;
	when->tm_mon = m-1;
	when->tm_year = a - 1900;
	when->tm_hour = h;
	when->tm_min = min ;	
	when->tm_isdst =0;
	when->tm_sec = sec;
	file_t = mktime( when );
	boot_t = time(NULL);
	bias = GetTickCount()/1000 - (boot_t-file_t);
	printf("Bias: %d (%x)\n",bias, bias);
}

void asktime(unsigned int* low, unsigned int* up)
{
	int	j,m,a,min,h,sec;
	struct tm* when;
	time_t	file_t, boot_t;
	time_t aclock;
	time_t bias;
	time( &aclock );   // Get time in seconds
	when = localtime( &aclock );   // Convert time to struct tm form 

	// bias
	printf("Enter bias please:\n");
	scanf("%d:",&bias);
	printf("Bias: %d (%x)\n",bias, bias);

	// file
	printf("Enter date of encryption (j/m/a):\n");
	scanf("%d/%d/%d",&j,&m,&a);
	
	printf("Enter time of encryption (hh:mm:ss)\n");
	scanf("%d:%d:%d",&h,&min,&sec);

	when->tm_mday = j;
	when->tm_mon = m-1;
	when->tm_year = a - 1900;
	when->tm_hour = h;
	when->tm_min = min ;	
	when->tm_isdst =0;
	when->tm_sec = sec;
	file_t = mktime( when );
	printf("time: %X\n",file_t);

	
	printf("Enter boot date (j/m/a):\n");
	scanf("%d/%d/%d",&j,&m,&a);
	printf("Enter boot time (hh:mm:sec)\n");
	scanf("%d:%d:%d",&h,&min,&sec);

	when->tm_mday = j;
	when->tm_mon = m-1;
	when->tm_year = a - 1900;
	when->tm_hour = h;
	when->tm_min = min ;
	when->tm_sec = sec;
	boot_t = mktime( when );
	
	printf("ticks: %X\n",(file_t-boot_t)*1000);

	printf("Approximative (ticks+time) seed %X\n",  *up = (file_t+ (file_t-boot_t+bias)*1000) );
	printf("====================================\n\n");
	*low = *up;
}

void main(int argc, char **argv)
{
	int success;
	HANDLE hProc;
	unsigned char cbuf[50];
	unsigned int low, up;

	if(argc <4) {
		printf("usage: %s <zip archive> <low seed> <high seed> [-u | -b] \n\n",argv[0]);
		printf("If option -u isn't used, <low seed> and <high seed> define\n");
		printf("the range of values for (ticks+time) xor pid.\n");
		printf("If option -u is used, the user is asked to enter information\n");
		printf("to deduce the initial (ticks+time) xor pid.\n");
		printf("<low seed> and <up seed> are respectively substracted and\n");
		printf("added to this value to define a range.\n");
		printf("Option -b is used to measure the bias on the computer.\n");
		return;
	}

	memset(cbuf,'\0',50);

	// Set Process Priority
	hProc = GetCurrentProcess();
	SetPriorityClass( hProc, IDLE_PRIORITY_CLASS);

	low = atoi(argv[2]);
	up = atoi(argv[3]);

	if((argc == 5) && (strcmp(argv[4],"-u")==0))
	{
		asktime(&low,&up);
		low = (low - atoi(argv[2]) ) & ~(0xFFF) ; 
		up = (up + atoi(argv[3]) ) | 0xFFF; 
	}
	if((argc == 5) && (strcmp(argv[4],"-b")==0))
	{
		askbias();
		return; 
	}

	if ( success = test_wz(argv[1],low,up,cbuf) )
	{
		// found a solution
		set_plaintext_buff(cbuf);
		recover_representation();
	}
	else
	{
		printf("Impossible to recover random bytes!\n");
	}
	return;
}