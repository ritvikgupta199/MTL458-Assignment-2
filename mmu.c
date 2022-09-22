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

#define NUM_OS_FRAMES (OS_MEM_SIZE / PAGE_SIZE)
#define PCB_SIZE sizeof(struct PCB)
#define PS_VM_PAGES (PS_VIRTUAL_MEM_SIZE / PAGE_SIZE) 
#define PAGE_TABLE_SIZE (PS_VM_PAGES * PAGE_TABLE_ENTRY_SIZE) // 4 KB
#define PCB_PAGE_SIZE (PCB_SIZE + PAGE_TABLE_SIZE)
#define PCB_START (((RAM_SIZE - OS_MEM_SIZE) / PAGE_SIZE) * FREE_BIT_SIZE) + 1024 // address 33 KB
#define PROC_COUNTER PCB_START + (PCB_PAGE_SIZE * MAX_PROCS) + 1024

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
    struct PCB* pcb = find_process(pid);
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
    for (int i=PS_VM_PAGES-1; i > PS_VM_PAGES-10; i--){
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

#include <assert.h>
#define MB (1024 * 1024)
#define KB (1024)

// just a random array to be passed to ps_create
unsigned char code_ro_data[10 * MB];

// Tester code begins
int main() {
	os_init();  
	code_ro_data[10 * PAGE_SIZE] = 'c';   // write 'c' at first byte in ro_mem
	code_ro_data[10 * PAGE_SIZE + 1] = 'd'; // write 'd' at second byte in ro_mem

	int p1 = create_ps(10 * PAGE_SIZE, 1 * PAGE_SIZE, 2 * PAGE_SIZE, 1 * MB, code_ro_data);
	error_no = -1; // no error
    
	unsigned char c = read_mem(p1, 10 * PAGE_SIZE);
	assert(c == 'c');
	unsigned char d = read_mem(p1, 10 * PAGE_SIZE + 1);
	assert(d == 'd');

	assert(error_no == -1); // no error
    write_mem(p1, 10 * PAGE_SIZE, 'd');   // write at ro_data
	assert(error_no == ERR_SEG_FAULT);  
	int p2 = create_ps(1 * MB, 0, 0, 1 * MB, code_ro_data);	// no ro_data, no rw_data

	error_no = -1; // no error
	int HEAP_BEGIN = 1 * MB;  // beginning of heap

	// allocate 250 pages
	allocate_pages(p2, HEAP_BEGIN, 250, O_READ | O_WRITE);
	write_mem(p2, HEAP_BEGIN + 1, 'c');
	write_mem(p2, HEAP_BEGIN + 2, 'd');
	assert(read_mem(p2, HEAP_BEGIN + 1) == 'c');
	assert(read_mem(p2, HEAP_BEGIN + 2) == 'd');
	deallocate_pages(p2, HEAP_BEGIN, 10);
	print_page_table(p2); // output should atleast indicate correct protection bits for the vmem of p2.
	write_mem(p2, HEAP_BEGIN + 1, 'd'); // we deallocated first 10 pages after heap_begin
	assert(error_no == ERR_SEG_FAULT);


	int ps_pids[100];
	// requesting 2 MB memory for 64 processes, should fill the complete 128 MB without complaining.   
	for (int i = 0; i < 64; i++) {
    	ps_pids[i] = create_ps(1 * MB, 0, 0, 1 * MB, code_ro_data);
    	print_page_table(ps_pids[i]);	// should print non overlapping mappings.  
	}
	exit_ps(ps_pids[0]);
    

	ps_pids[0] = create_ps(1 * MB, 0, 0, 500 * KB, code_ro_data);
	print_page_table(ps_pids[0]);   
	// allocate 500 KB more
	allocate_pages(ps_pids[0], 1 * MB, 125, O_READ | O_READ | O_EX);
	for (int i = 0; i < 64; i++) {
    	print_page_table(ps_pids[i]);	// should print non overlapping mappings.  
	}
}
// Tester code ends


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

void free_page(int page_num) {
    char* free_list = (char*) (&OS_MEM[0]);
    free_list[page_num - NUM_OS_FRAMES] = '1';
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
        int addr = find_free_page();
        if (i < pcb->ro_data_start_add) { // Code data (only read and execute)
            page_table[i] = (addr << 16) | O_READ | O_EX | PG_PRESENT;
        } else if (i < pcb->rw_data_start_add) { // Read only data
            page_table[i] = (addr << 16) | O_READ | PG_PRESENT;
        } else if (i < pcb->stack_start_add) { // Read write data
            page_table[i] = (addr << 16) | O_READ | O_WRITE | PG_PRESENT;
        } else { // stack data (read and write)
            page_table[i] = (addr << 16) | O_READ | O_WRITE | PG_PRESENT;
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
    // Set pages as free
    for (int i = 0; i < PS_VM_PAGES; i++) {
        if (is_present(pcb->page_table[i])) {
            int frame_num = pte_to_frame_num(pcb->page_table[i]);
            free_page(frame_num);
            pcb->page_table[i] = 0;
        }
    }
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

    pcb_new->code_start_add = pcb->code_start_add;
    pcb_new->ro_data_start_add = pcb->code_start_add;
    pcb_new->rw_data_start_add = pcb->code_start_add;
    pcb_new->heap_start_add = pcb->code_start_add;
    pcb_new->stack_start_add = pcb->code_start_add;

    init_page_table(pcb_new);

    // Copy code from old process
    for (int i = 0; i < PS_VM_PAGES; i++) {
        page_table_entry pte = pcb->page_table[i];
        page_table_entry pte_new = pcb_new->page_table[i];
        if (is_present(pte)){
            int frame_num = pte_to_frame_num(pte);
            int frame_num_new = pte_to_frame_num(pte_new);
            int start_add = frame_num * PAGE_SIZE;
            int start_add_new = frame_num_new * PAGE_SIZE;
            for (int j = 0; j < PAGE_SIZE; j++) {
                RAM[start_add_new + j] = RAM[start_add + j];
            }
        }
    }
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
void allocate_pages(int pid, int vmem_addr, int num_pages, int flags) {
    struct PCB* pcb = find_process(pid);
    int start_page = vmem_addr / PAGE_SIZE;
    int end_page = start_page + num_pages;
    for (int i = start_page; i < end_page; i++) {
        if (is_present(pcb->page_table[i])) {
            exit_ps(pid);
            error_no = ERR_SEG_FAULT;
            return;
        }
        int addr = find_free_page();
        pcb->page_table[i] = (addr << 16) | flags | PG_PRESENT;
    }
}



// dynamic heap deallocation
//
// Deallocate num_pages amount of pages for process pid, starting at vmem_addr.
// Assume vmem_addr points to a page boundary
// Assume 0 <= vmem_addr < PS_VIRTUAL_MEM_SIZE

// If any of the pages was not already allocated then kill the process, deallocate all its resources(ps_exit) 
// and set error_no to ERR_SEG_FAULT.
void deallocate_pages(int pid, int vmem_addr, int num_pages) {
   struct PCB* pcb = find_process(pid);
   int start_page = vmem_addr / PAGE_SIZE;
   int end_page = start_page + num_pages;
   for (int i = start_page; i < end_page; i++) {
        if (!is_present(pcb->page_table[i])) {
            exit_ps(pid);
            error_no = ERR_SEG_FAULT;
            return;
        } else {
            int frame_num = pte_to_frame_num(pcb->page_table[i]);
            free_page(frame_num);
            pcb->page_table[i] = 0;
        }
   }
   
}

// Read the byte at `vmem_addr` virtual address of the process
// In case of illegal memory access kill the process, deallocate all its resources(ps_exit) 
// and set error_no to ERR_SEG_FAULT.
// 
// assume 0 <= vmem_addr < PS_VIRTUAL_MEM_SIZE
unsigned char read_mem(int pid, int vmem_addr) {
    struct PCB* pcb = find_process(pid);
    int vm_page_num = vmem_addr / PAGE_SIZE;
    page_table_entry pte = pcb->page_table[vm_page_num];
    if (!is_present(pte)) {
        exit_ps(pid);
        error_no = ERR_SEG_FAULT;
        return 0;
    } else {
        int frame_num = pte_to_frame_num(pte);
        int start_add = frame_num * PAGE_SIZE;
        return RAM[start_add + vmem_addr % PAGE_SIZE];
    }
}

// Write the given `byte` at `vmem_addr` virtual address of the process
// In case of illegal memory access kill the process, deallocate all its resources(ps_exit) 
// and set error_no to ERR_SEG_FAULT.
// 
// assume 0 <= vmem_addr < PS_VIRTUAL_MEM_SIZE
void write_mem(int pid, int vmem_addr, unsigned char byte) {
    struct PCB* pcb = find_process(pid);
    int vm_page_num = vmem_addr / PAGE_SIZE;
    page_table_entry pte = pcb->page_table[vm_page_num];
    if (!is_present(pte) || !is_writeable(pte)) {
        exit_ps(pid);
        error_no = ERR_SEG_FAULT;
    } else {
        int frame_num = pte_to_frame_num(pte);
        int start_add = frame_num * PAGE_SIZE;
        RAM[start_add + vmem_addr % PAGE_SIZE] = byte;
    }
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
    struct PCB* pcb = find_process(pid);
    page_table_entry* page_table_start = pcb->page_table;
    int num_page_table_entries = PS_VM_PAGES;

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