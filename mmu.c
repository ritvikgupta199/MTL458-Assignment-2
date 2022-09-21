#include "mmu.h"
#include <stdlib.h>
#include <stdio.h>


// byte addressable memory
unsigned char RAM[RAM_SIZE];  


// OS's memory starts at the beginning of RAM.
// Store the process related info, page tables or other data structures here.
// do not use more than (OS_MEM_SIZE: 72 MB).
unsigned char* OS_MEM = RAM;  

// memory that can be used by processes.   
// 128 MB size (RAM_SIZE - OS_MEM_SIZE)
unsigned char* PS_MEM = RAM + OS_MEM_SIZE; 

// This first frame has frame number 0 and is located at start of RAM(NOT PS_MEM).
// We also include the OS_MEM even though it is not paged. This is 
// because the RAM can only be accessed through physical RAM addresses.  
// The OS should ensure that it does not map any of the frames, that correspond
// to its memory, to any process's page. 
int NUM_FRAMES = ((RAM_SIZE) / PAGE_SIZE); // 50 KB

// Actual number of usable frames by the processes.
int NUM_USABLE_FRAMES = ((RAM_SIZE - OS_MEM_SIZE) / PAGE_SIZE); // 32 KB

const int NUM_OS_FRAMES = (OS_MEM_SIZE / PAGE_SIZE);
const int PCB_SIZE = sizeof(struct PCB);
const int PS_VM_PAGES = (PS_VIRTUAL_MEM_SIZE / PAGE_SIZE); 
const int PAGE_TABLE_SIZE = PS_VM_PAGES * PAGE_TABLE_ENTRY_SIZE; // 4 KB
const int PCB_PAGE_SIZE = PCB_SIZE + PAGE_TABLE_SIZE;
const int PCB_START = ((RAM_SIZE - OS_MEM_SIZE) / PAGE_SIZE) * FREE_BIT_SIZE + 1024; // address 33 KB
const int PROC_COUNTER = PCB_START + PCB_PAGE_SIZE * MAX_PROCS + 1024;

/*
 *  OS Memory Layout: 
 *  --------------------------------------- (os memory start)
 *           free list for frames 
 *     (1 B * NUM_USABLE_FRAMES) = 32 KB
 *  ---------------------------------------  
 *           1 KB free margin space
 *  ---------------------------------------
 *         PCBs for MAX_PROCS processes
 *    (PCB_PAGE_SIZE * MAX_PROCS) = 400 KB)
 *       ----------------------------
 *              PCB for process
 *                  (16 B)
 *       ----------------------------
 *          Page table for process
 *         (PS_VM_PAGES * 4B) = 4 KB
 *       ----------------------------
 *  ---------------------------------------  
 *           1 KB free margin space
 *  ---------------------------------------
 *           Process Counter (int)
 *  --------------------------------------- (os memory end)
 */

/*
 *  Process Virtual Memory layout: 
 *  ---------------------- (virt. memory start 0x00)
 *        code
 *  ----------------------  
 *     read only data 
 *  ----------------------
 *     read / write data
 *  ----------------------
 *        heap
 *  ----------------------
 *        stack  
 *  ----------------------  (virt. memory end 0x3fffff)
 * 
 * 
 *  code            : read + execute only
 *  ro_data         : read only
 *  rw_data         : read + write only
 *  stack           : read + write only
 *  heap            : (protection bits can be different for each heap page)
 * 
 *  assume:
 *  code_size, ro_data_size, rw_data_size, max_stack_size, are all in bytes
 *  code_size, ro_data_size, rw_data_size, max_stack_size, are all multiples of PAGE_SIZE
 *  code_size + ro_data_size + rw_data_size + max_stack_size < PS_VIRTUAL_MEM_SIZE
 *  
 * 
 *  The rest of memory will be used dynamically for the heap.
 * 
 *  This function should create a new process, 
 *  allocate code_size + ro_data_size + rw_data_size + max_stack_size amount of physical memory in PS_MEM,
 *  and create the page table for this process. Then it should copy the code and read only data from the
 *  given `unsigned char* code_and_ro_data` into processes' memory.
 *   
 *  It should return the pid of the new process.  
 *  
 */


// To be set in case of errors. 
int error_no;


void os_init() {
    char* free_list = (char*) (&OS_MEM[0]); // Using char as it has same size as bool
    for (int i = 0; i < NUM_USABLE_FRAMES; i++) {
        free_list[i] = '1';
    }
    for (int i = 0; i < MAX_PROCS; i++) {
        int start_add = PCB_START + i * PCB_PAGE_SIZE;
        struct PCB* pcb = (struct PCB*) (&OS_MEM[start_add]);
        pcb->pid = -1;
        pcb->num_pages = 0;
        pcb->page_table = (page_table_entry*) (&OS_MEM[start_add + PCB_SIZE]);
    }
    int* proc_counter = (int*) (&OS_MEM[PROC_COUNTER]);
    *proc_counter = 0;
}

void print_procs(int pid){
    struct PCB* pcb = find_process(0);
    printf("START\n");
    printf("%d\n", pcb->pid);
    for (int i=0; i< 10; i++){
        unsigned int number = pcb->page_table[i];
        for (int i = 0; i < 32; ++i) {
            if (number >> i & 0x1) putchar('1');
            else putchar('0');
        }
        printf(" Frame:%d R:%d, W:%d, X:%d, P:%d",
                pte_to_frame_num(number),
                is_readable(number),
                is_writeable(number),
                is_executable(number),
                is_present(number)
                );
        putchar('\n');
    }
    
}

int main(){
    os_init();
    int pid = create_ps(PAGE_SIZE*3, PAGE_SIZE*2, PAGE_SIZE*2, PAGE_SIZE*6, NULL);
    print_procs(0);
    return 0;
}

// ----------------------------------- Functions for managing memory --------------------------------- //
struct PCB* find_process(int pid) {
    struct PCB* pcb;
    for (int i = 0; i < MAX_PROCS; i++) {
        pcb = (struct PCB*) (&OS_MEM[PCB_START + (i * PCB_PAGE_SIZE)]);
        if (pcb->pid == pid) {
            return pcb;
        }
    }
    return NULL;
}

int find_free_page() {
    char* free_list = (char*) (&OS_MEM[0]);
    for (int i = 0; i < NUM_USABLE_FRAMES; i++) {
        if (free_list[i] == '1') {
            free_list[i] = '0';
            return NUM_OS_FRAMES + i;
        }
    }
    return -1;
}

/*
 *  Each page table entry is a 32 bit unsigned integer
 *  Total page addresses = 128 MB / 4 KB= 2^15 pages
 *  [___Physical Address (16 bits)___] [___Buffer bits (12 bits)___] [___Protection Bits (3 bits)___] [___Present Bit (1 bit)___]
 */
void init_page_table(struct PCB* pcb) {
    page_table_entry* page_table = pcb->page_table;
    for (int i = 0; i < PS_VM_PAGES; i++) {
        if (i >= pcb->heap_start_add && i < pcb->stack_start_add) {
            page_table[i] = 0x00000000;
            continue; // Heap pages are not allocated
        }
        int add = find_free_page();
        if (i < pcb->ro_data_start_add) { // Code data (only read and execute)
            page_table[i] = (add <<16) | O_READ | O_EX | PG_PRESENT;
        } else if (i < pcb->rw_data_start_add) { // Read only data
            page_table[i] = (add <<16) | O_READ | PG_PRESENT;
        } else if (i < pcb->stack_start_add) { // Read write data
            page_table[i] = (add <<16) | O_READ | O_WRITE | PG_PRESENT;
        } else { // stack data (read and write)
            page_table[i] = (add <<16) | O_READ | O_WRITE | PG_PRESENT;
        }
    }
}

int create_ps(int code_size, int ro_data_size, int rw_data_size, int max_stack_size, unsigned char* code_and_ro_data) {   
    struct PCB* pcb = find_process(-1);
    int* proc_counter = (int*) (&OS_MEM[PROC_COUNTER]);
    int pid = (*proc_counter)++;
    pcb->pid = pid;

    int code_num_pages = code_size / PAGE_SIZE;
    int ro_data_num_pages = ro_data_size / PAGE_SIZE;
    int rw_data_num_pages = rw_data_size / PAGE_SIZE;
    int stack_num_pages = max_stack_size / PAGE_SIZE;

    pcb->code_start_add = 0;
    pcb->ro_data_start_add = pcb->code_start_add + code_num_pages;
    pcb->rw_data_start_add = pcb->ro_data_start_add + ro_data_num_pages;
    pcb->heap_start_add = pcb->rw_data_start_add + rw_data_num_pages;
    pcb->stack_start_add = (PS_VIRTUAL_MEM_SIZE/PAGE_SIZE) - stack_num_pages;

    init_page_table(pcb);

    // Copy code and ro data into memory
    for (int i = 0; i < code_num_pages + ro_data_num_pages; i++) {
        page_table_entry pte = pcb->page_table[i];
        int frame_num = pte_to_frame_num(pte);
        int start_add = frame_num * PAGE_SIZE;
        for (int j = 0; j < PAGE_SIZE; j++) {
            RAM[start_add + j] = code_and_ro_data[i * PAGE_SIZE + j];
        }
    }
    return pid;
}


/*
 * This function should deallocate all the resources for this process. 
 */
void exit_ps(int pid) {
    struct PCB* pcb = find_process(pid);
    pcb->pid = -1;
}

/*
 * Create a new process that is identical to the process with given pid. 
 */
int fork_ps(int pid) {
    struct PCB* pcb = find_process(pid);
    struct PCB* pcb_new = find_process(-1);
    int* proc_counter = (int*) (&OS_MEM[PROC_COUNTER]);
    int pid_new = (*proc_counter)++;
    pcb_new->pid = pid_new;
    return pid_new;
}

// dynamic heap allocation
//
// Allocate num_pages amount of pages for process pid, starting at vmem_addr.
// Assume vmem_addr points to a page boundary.  
// Assume 0 <= vmem_addr < PS_VIRTUAL_MEM_SIZE
//
//
// Use flags to set the protection bits of the pages.
// Ex: flags = O_READ | O_WRITE => page should be read & writeable.
//
// If any of the pages was already allocated then kill the process, deallocate all its resources(ps_exit) 
// and set error_no to ERR_SEG_FAULT.
void allocate_pages(int pid, int vmem_addr, int num_pages, int flags) 
{
   // TODO student
}



// dynamic heap deallocation
//
// Deallocate num_pages amount of pages for process pid, starting at vmem_addr.
// Assume vmem_addr points to a page boundary
// Assume 0 <= vmem_addr < PS_VIRTUAL_MEM_SIZE

// If any of the pages was not already allocated then kill the process, deallocate all its resources(ps_exit) 
// and set error_no to ERR_SEG_FAULT.
void deallocate_pages(int pid, int vmem_addr, int num_pages) 
{
   // TODO student
}

// Read the byte at `vmem_addr` virtual address of the process
// In case of illegal memory access kill the process, deallocate all its resources(ps_exit) 
// and set error_no to ERR_SEG_FAULT.
// 
// assume 0 <= vmem_addr < PS_VIRTUAL_MEM_SIZE
unsigned char read_mem(int pid, int vmem_addr) 
{
    // TODO: student
    return 0;
}

// Write the given `byte` at `vmem_addr` virtual address of the process
// In case of illegal memory access kill the process, deallocate all its resources(ps_exit) 
// and set error_no to ERR_SEG_FAULT.
// 
// assume 0 <= vmem_addr < PS_VIRTUAL_MEM_SIZE
void write_mem(int pid, int vmem_addr, unsigned char byte) 
{
    // TODO: student
}





// ---------------------- Helper functions for Page table entries ------------------ // 

// return the frame number from the pte
int pte_to_frame_num(page_table_entry pte) {
    return pte >> 16;
}


// return 1 if read bit is set in the pte
// 0 otherwise
int is_readable(page_table_entry pte) {
    return pte & O_READ ? 1 : 0;
}

// return 1 if write bit is set in the pte
// 0 otherwise
int is_writeable(page_table_entry pte) {
    return pte & O_WRITE ? 1 : 0;
}

// return 1 if executable bit is set in the pte
// 0 otherwise
int is_executable(page_table_entry pte) {
    return pte & O_EX ? 1 : 0;
}


// return 1 if present bit is set in the pte
// 0 otherwise
int is_present(page_table_entry pte) {
    return pte & PG_PRESENT ? 1 : 0;
}

// -------------------  functions to print the state  --------------------------------------------- //

void print_page_table(int pid) {
    
    page_table_entry* page_table_start = NULL; // TODO student: start of page table of process pid
    int num_page_table_entries = -1;           // TODO student: num of page table entries

    // Do not change anything below
    puts("------ Printing page table-------");
    for (int i = 0; i < num_page_table_entries; i++) 
    {
        page_table_entry pte = page_table_start[i];
        printf("Page num: %d, frame num: %d, R:%d, W:%d, X:%d, P%d\n", 
                i, 
                pte_to_frame_num(pte),
                is_readable(pte),
                is_writeable(pte),
                is_executable(pte),
                is_present(pte)
                );
    }

}