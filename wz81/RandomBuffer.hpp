#define P1SIZE 0xc7
#define P2SIZE (0x64+0x38d)
#define P3SIZE 0x64

void save_buffers( int* p1, int* p2, int* p_3);
void restore_buffers( int* p1, int* p2, int* p_3);
void initialize_P1(int seed);
void initialize_P2();