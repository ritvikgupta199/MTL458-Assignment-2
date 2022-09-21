#define RAM_SIZE (200 * 1024 * 1024) // 200 MB

#define OS_MEM_SIZE (72 * 1024 * 1024) // 72 MB

#define PAGE_SIZE (4 * 1024) // 4 KB


// interpret each page table entry as unsigned int
// 32 bits should be enough to store all the info
typedef unsigned int page_table_entry;
#define PAGE_TABLE_ENTRY_SIZE sizeof(page_table_entry) 
#define FREE_BIT_SIZE sizeof(char)


#define PS_VIRTUAL_MEM_SIZE (4 * 1024 * 1024)  // Each process has 4 MB of virtual memory

#define MAX_PROCS 100  // Assume that the maximum number of processes that can exist at a time is 100
                       // Total processes created may be more than 100(as some of them will exit).
                       

// Block for storing information of each process
struct PCB {
    int pid;
    int num_pages;
    int code_start_add, ro_data_start_add, rw_data_start_add, heap_start_add, stack_start_add;
    page_table_entry* page_table;
};


// Protections associated with each page
enum PAGE_PROTECTIONS {
    O_READ  = 1,    // read allowed
    O_WRITE = 2,    // write allowed
    O_EX    = 4     // execute allowed
};

enum PAGE_STATUS {
    PG_PRESENT = 8,    // page is present in physical memory
};

enum ERROR {
    ERR_SEG_FAULT
};




// See mmu.c file for description of functions

void os_init();

struct PCB* find_process(int pid);

int find_free_page();

int create_ps(int code_size, int ro_data_size, int rw_data_size,
                 int max_stack_size, unsigned char* code_and_ro_data);

void exit_ps(int pid);

int fork_ps(int pid);

void allocate_pages(int pid, int vmem_addr, int num_pages, int flags);

void deallocate_pages(int pid, int vmem_addr, int num_pages);

unsigned char read_mem(int pid, int vmem_addr);

void write_mem(int pid, int vmem_addr, unsigned char byte);



int pte_to_frame_num(page_table_entry pte);

int is_readable(page_table_entry pte);

int is_writeable(page_table_entry pte);

int is_executable(page_table_entry pte);

int is_present(page_table_entry pte);


void print_page_table(int pid);