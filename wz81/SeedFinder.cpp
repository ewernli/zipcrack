//#include "stdafx.h"
#include <math.h>
#include <windows.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include "RandomBuffer.hpp"


/* global variables */

#define MAXFILES	20
unsigned int		init_time;
unsigned int		init_ticks;
unsigned int		pid;
unsigned int		t;
unsigned char		seeds[MAXFILES*10];
unsigned int		sizes[MAXFILES];
unsigned int		nbfiles;

unsigned char		k3;

/* options */

#define NO_TIME_GLITCH	0
#define TIME_GLITCH		1
#define NO_TICKS_GLITCH	2
#define TICKS_GLITCH	3

/* approximation function */

#define PROCESS_TIME( x )   ( (x) / (4*1024) )
#define DELTA( x )			( (x) / (2*1024) )

/* files in archives */

							////
#define MAX_LEVEL	7		// number of files to handle
							////
/* results */

unsigned int		rand_data[ MAX_LEVEL ][10];
unsigned int		dt_history[ MAX_LEVEL-2 ];
unsigned int		delta_history[ MAX_LEVEL-2];
unsigned int		ticks_history[ MAX_LEVEL-2 ];
unsigned int		time_history[ MAX_LEVEL-2 ];
/* statistics */

unsigned int		stat[MAX_LEVEL];

/* prototypes */

void recover();
int rip(char*, unsigned char*, unsigned int*, int);
void guess_enc( int level, int timeg, int ticksg);
void randomize(int timeg, int ticksg);
void asktime();
void set_data_buff( unsigned char* );

/* Buffers */

extern int* ptr;
extern int  buff[0x64+0x38d];

time_t		start_t = 0;




void printTime()
{
	time_t seconds;
	DWORD t = GetTickCount();
	seconds = time (NULL);
	printf ("%ld (%X) seconds since January 1, 1970\n", seconds, seconds);
	printf ("%ld (%X) milliseconds since Windows started\n", t, t);
	if( start_t == 0)
		start_t = seconds;
	else
		printf("Attack took %d seconds\n", seconds - start_t);
}

unsigned int	seed;

unsigned int success;
unsigned char rand_suc[5][10]; 

int test_wz( char* file, unsigned int low, unsigned int up, unsigned char* res)
{
	unsigned int i,k;
	unsigned int v;
	unsigned char b;

	printf("Recover random prepended bytes from the archive\n");
	printf("====================================\n\n");

	memset( stat, 0, MAX_LEVEL*4);

	printf("Archive: %s\n",file);
	nbfiles = rip( file, seeds, sizes, MAXFILES);
	set_data_buff( seeds );

	for(i=0;i<nbfiles;i++)
		seeds[i]=seeds[i*10];

#if 0
	printf("Seeds: ");
	for(i=0;i<nbfiles;i++)
		printf("%X ",seeds[i]);
	printf("\n");	
	
	printTime();
#endif


	init_time=0;
	success =0;

	/* DEBUG
	low = 0xBC25AB2E - 1000;
	up = 0xBC25AB2F;

	low =  (0x589e05c7 + 0x404373ab) - 2000;
	up = (0x589e05c7 + 0x404373ab) ;
	*/

	printf("seed range [%x ; %x]\n",low,up);
	printf("seed range [%u ; %u]\n",low,up);

	for( seed = low ; seed < up; seed++)
	{
		initialize_P1(seed & 0x0FFFFFFF);
		initialize_P2();

		memcpy( rand_data[0], ptr, 4*10 );

		/* KEY 3 */
		v=*ptr;	
		_asm{
			sar v,16h
		}
		k3 = v ^ seeds[0];	// k3 is 8-bit value
		
		recover();
	}
	
	printTime();
	printf("-- STATISTICS --\n");
	for(i=0;i<MAX_LEVEL;i++)
		printf("Level %02d: %d\n",i,stat[i]);
	printf("Done\n");

	/* return result if any */
	for(k=0;k<5;k++)
	{
		for(i=0;i<10;i++)
		{
			res[k*10+i] = rand_suc[k][i];
		}
	}
	return success;
}

void recover()
{
	int		p1[P1SIZE];
	int		p2[P2SIZE];
	int		p3[P3SIZE];

	int		q1[P1SIZE];
	int		q2[P2SIZE];
	int		q3[P3SIZE];

	unsigned char	b;
	unsigned int	v;
	unsigned int	i;
	unsigned int	highbits;

	unsigned int	s;
	unsigned int	oldn, n;

	int				done;

	t = 0;
	save_buffers(q1,q2,q3);	

	{
		/* fill bit 32-29 of the seed */
	//	seed = (highbits << 28) | (seed & 0x0FFFFFFF);

		oldn=0;
		restore_buffers(q1,q2,q3);	

		/**
		 SEEDS:
		 - time + ticks is a 27-bit to 32-bit seed  
		 - PID is a 10-bit seed ; pid = n*4 with n in  {0,1024}
		**/

		for(init_ticks= seed  & 0xFFFFF003; init_ticks< (seed&0xFFFFF003)+0x1000; init_ticks+=4)
		{
			pid = seed ^ init_ticks;

			stat[0]++;

			/**
			 ASSUMPTIONS
			 - we are still in the same 10ms frame
			 - no glitch occured 
			**/

			ptr = buff + 10;
			s = init_ticks % 0x2710;
			if( s < (0x64-10) )
			{
				ptr = ptr + s + 1;
			}
			else
			{
				s -= (0x64-10);
				n = (s/0x64)+1;
				
				if( n > oldn )
				{
					for(i=oldn;i<n;i++)
						initialize_P2();
					oldn = n;
				}

				ptr = buff + (s%0x64) + 1;
			}

			/**
			 OPTIMIZATION
			 - initialize_P1 has no effect on buff
			 - if *ptr != -1, delay initialize_P1 after the filter
			 - if the byte doesn't pass the filter, we spare initialize_P1
			 - if *ptr == -1 ; initialize_P2 must take place before initialize_P2
			**/
#define OPTIM
			
			
			
#ifdef OPTIM
			done = false;
			
			if( *ptr < 0)
			{
				save_buffers(p1,p2,p3);
				initialize_P1( (pid ^ *(ptr-1) ) & 0x0FFFFFFF );
				initialize_P2();
				memcpy( rand_data[1], ptr, 4*10 );
				v = *ptr;
				ptr+=10;

				done = true;
			}
			else 
				v = *ptr;
#else
			save_buffers(p1,p2,p3);
			done=true;
			initialize_P1( (pid ^ *(ptr-1) ) & 0x0FFFFFFF );
			
			for(i=0;i<10;i++)
			{
				if( *ptr < 0)
					initialize_P2();
				if(i==0) v=*ptr;
				ptr++;
			}	
#endif
			_asm{
				sar v,16h
			}
			b = (v&0x000000FF) ^ k3;

			if( (b == seeds[1]) )
			{	
			
				stat[1]++;
#ifdef OPTIM		
				if( done==false)
				{
					save_buffers(p1,p2,p3);
					initialize_P1( (pid ^ *(ptr-1) ) & 0x0FFFFFFF );
					

					for(i=0;i<10;i++)
					{
						if( *ptr < 0)
							initialize_P2();
						rand_data[1][i]=*ptr;
						ptr++;
					}
					//memcpy( rand_data[1], ptr, 4*10 );
					done=true;
				}
#endif
				guess_enc( 0, NO_TIME_GLITCH,	NO_TICKS_GLITCH );
				guess_enc( 0, NO_TIME_GLITCH,	TICKS_GLITCH );
				guess_enc( 0, TIME_GLITCH,		NO_TICKS_GLITCH );
				guess_enc( 0, TIME_GLITCH,		TICKS_GLITCH );

				
			}
			if(done==true) restore_buffers(p1,p2,p3);
		}
	}
}

#define ROUND( x ) ((x/10)*10)

unsigned int round_ticks( int t, int glitch )
{
	if (glitch == NO_TICKS_GLITCH)
		return init_ticks + ROUND( t );
	else
		return init_ticks + ROUND( t ) + 1;
}

unsigned int round_time( int t, int glitch )
{
	if (glitch == NO_TIME_GLITCH)
		return init_time;
	else
		return init_time + 1;
}

void randomize(int timeg, int ticksg)
{
	unsigned int seed;

	seed = round_time(t,timeg) + round_ticks(t,ticksg) ;
	seed = seed % 0x2710;

	while(seed-- >0)
	{
		if( *ptr < 0)
			initialize_P2(); 
		ptr++;
	}

	if( *ptr < 0)
		initialize_P2();
	
	initialize_P1( (pid ^ *ptr)&0x0FFFFFFF );
	ptr++;

} 

void guess_enc( int level, int timeg, int ticksg)
{
	int		p1[P1SIZE];
	int		p2[P2SIZE];
	int		p3[P3SIZE];
	int*	saved_ptr;

	unsigned int  dt;
	unsigned int  v;
	unsigned char b;
	unsigned int  saved_t;
	int			  i,k;

	unsigned int size = sizes[ level ];
	int lw = PROCESS_TIME(size) - DELTA(size) ;
	unsigned int low_t;
	unsigned int up_t = PROCESS_TIME(size) + DELTA(size) ;

	low_t = lw <= 0 ? 0 : lw;

	low_t = ROUND( low_t );
	up_t =  ROUND( up_t ) + 10;

	delta_history[level] = (up_t-low_t);

//	printf("low %d up %d \n",low_t, up_t);

	for(dt=low_t;dt<=up_t;dt+=10)
	{
		saved_t = t;
		save_buffers(p1,p2,p3);		
		saved_ptr = ptr;
		

		t = t+dt;
		randomize(timeg, ticksg);
		//memcpy( rand_data[level+2], ptr, 4*10 );

		dt_history[level] = dt;
		ticks_history[ level ] = (ticksg == NO_TICKS_GLITCH ? 0 : 1);
		time_history[ level ] = (timeg == NO_TIME_GLITCH ? 0 : 1);

		for(i=0;i<10;i++)
		{
			if( *ptr < 0)
				initialize_P2();
			if(i==0) v=*ptr;
			rand_data[level+2][i]=*ptr;
			ptr++;
		}

		_asm{ 
			sar v,16h
		}
		b = (v&0x000000FF) ^ k3;
		if( b == seeds[level+2] )
		{		
			stat[level+2]++;

			if( level == MAX_LEVEL - 3)
			{
				/* candidate succeded */
				printf("----\n");
				printf("Succes for (time + ticks) = %X and PID = %d\n", init_time + init_ticks, pid);
				
				printf("dt sequence:   ");
				for(i=0;i<(MAX_LEVEL-2);i++)
					printf("%02d ",dt_history[i]);
				printf("\n");
				
				printf("delta:         ");
				for(i=0;i<(MAX_LEVEL-2);i++)
					printf("%02d ",delta_history[i]);
				printf("\n");

				printf("ticks glitches:");
				for(i=0;i<(MAX_LEVEL-2);i++)
					printf("%02d ",ticks_history[i]);
				printf("\n");

				printf("time glitches: ");
				for(i=0;i<(MAX_LEVEL-2);i++)
					printf("%02d ",time_history[i]);
				printf("\n");

				printf("random data for file 1:");
				for(k=0;k<5;k++)
				{
					for(i=0;i<10;i++)
					{
						v = rand_data[k][i];
						_asm{ 
							sar v,16h
						}
						b=v&0x000000FF;
						rand_suc[k][i]=b;
					}
				}
				for(i=0;i<10;i++)
					printf("%02X ",rand_suc[0][i]);
				printf("\n");



				success++;

				return;
			}

			/* propagate or generate glitches */

			if( timeg == NO_TIME_GLITCH )
			{
				if( ticksg == NO_TICKS_GLITCH )
					guess_enc( level+1, NO_TIME_GLITCH, NO_TICKS_GLITCH );
				guess_enc( level+1, NO_TIME_GLITCH, TICKS_GLITCH );
			}
			if( ticksg == NO_TICKS_GLITCH )
				guess_enc( level+1, TIME_GLITCH, NO_TICKS_GLITCH );
			guess_enc( level+1, TIME_GLITCH, TICKS_GLITCH );
			
		
		}	
		
		restore_buffers(p1,p2,p3);
		t = saved_t;
		ptr = saved_ptr;
	}
	return;
}