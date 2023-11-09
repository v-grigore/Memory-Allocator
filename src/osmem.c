// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"

#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "block_meta.h"

#define MMAP_THRESHOLD (128 * 1024)
#define PAGE_SIZE ((size_t) getpagesize())
#define MIN(a, b) ((a) > (b) ? (b) : (a))

static struct block_meta *head;
static unsigned char pre_alloc_heap = 1;

size_t m_size(size_t size)
{
	return size + (8 - size % 8) % 8;
}

void add_block(struct block_meta *block)
{
	if (!head) {
		head = block;
		head->next = head;
		head->prev = head;
		return;
	}

	block->next = head;
	block->prev = head->prev;
	block->next->prev = block;
	block->prev->next = block;
}

void free_block(struct block_meta *block)
{
	block->prev->next = block->next;
	block->next->prev = block->prev;

	if (block == head) {
		if (head->next == head->prev)
			head = NULL;
		else
			head = block->next;
	}

	munmap(block, 32 + m_size(block->size));
}

struct block_meta *find_best(size_t size)
{
	size_t best_size = SIZE_MAX;
	struct block_meta *best_block = NULL;
	struct block_meta *block = head;

	do {
		if (block->status == STATUS_FREE && size <= block->size && block->size < best_size) {
			best_size = block->size;
				best_block = block;
		}

		block = block->next;
	} while (block != head);

	return best_block;
}

void split_block(struct block_meta *block, size_t size)
{
	if (m_size(size) + 32 >= block->size)
		return;

	struct block_meta *free_block = (struct block_meta *)((unsigned char *) block + 32 + m_size(size));

	free_block->size = block->size - m_size(size) - 32;
	free_block->status = STATUS_FREE;
	free_block->next = block->next;
	free_block->prev = block;
	free_block->next->prev = free_block;
	free_block->prev->next = free_block;
	block->size = m_size(size);
}

struct block_meta *get_last(void)
{
	struct block_meta *last = head->prev;

	while (last->status == STATUS_MAPPED && last->prev != head)
		last = last->prev;
	return last;
}

void *os_malloc(size_t size)
{
	if (!size)
		return NULL;

	if (size + 32 > MMAP_THRESHOLD) {
		struct block_meta *block = mmap(NULL, 32 + m_size(size), PROT_READ | PROT_WRITE,
										MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

		block->size = m_size(size);
		block->status = STATUS_MAPPED;
		add_block(block);
		return (unsigned char *) block + 32;
	}

	if (pre_alloc_heap) {
		struct block_meta *block = sbrk(MMAP_THRESHOLD);

		block->size = MMAP_THRESHOLD - 32;
		block->status = STATUS_FREE;
		add_block(block);
		pre_alloc_heap = 0;
	}

	struct block_meta *block = find_best(size);

	if (block) {
		split_block(block, size);
		block->status = STATUS_ALLOC;
		return (unsigned char *) block + 32;
	}

	struct block_meta *last = get_last();

	if (last->status == STATUS_FREE) {
		block = last;
		sbrk((intptr_t)(m_size(size - block->size)));
		block->size = m_size(size);
		block->status = STATUS_ALLOC;
		return (unsigned char *) block + 32;
	}

	block = sbrk((intptr_t)(32 + m_size(size)));
	block->size = m_size(size);
	block->status = STATUS_ALLOC;
	add_block(block);
	return (unsigned char *) block + 32;
}

void coalesce_blocks(struct block_meta *block)
{
	struct block_meta *left = block->prev;
	struct block_meta *right = block->next;

	if (block == right)
		return;

	if (right->status == STATUS_FREE && right != head) {
		block->size = m_size(block->size) + 32 + right->size;
		block->next = right->next;
		right->next->prev = block;
	}

	if (left == right)
		return;

	if (left->status == STATUS_FREE && block != head) {
		left->size = m_size(left->size) + 32 + block->size;
		left->next = block->next;
		block->next->prev = left;
	}
}

void os_free(void *ptr)
{
	if (!ptr)
		return;

	struct block_meta *block = head;

	while (block && (unsigned char *) block + 32 != ptr) {
		block = block->next;
		if (block == head)
			return;
	}

	if (!block)
		return;

	if (block->status == STATUS_MAPPED) {
		free_block(block);
		return;
	}

	block->status = STATUS_FREE;
	coalesce_blocks(block);
}

void *os_calloc(size_t nmemb, size_t size)
{
	size_t malloc_size = nmemb * size;

	if (!malloc_size)
		return NULL;

	if (malloc_size + 32 > PAGE_SIZE) {
		struct block_meta *block = mmap(NULL, 32 + m_size(malloc_size), PROT_READ | PROT_WRITE,
										MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

		block->size = m_size(malloc_size);
		block->status = STATUS_MAPPED;
		add_block(block);
		memset((unsigned char *) block + 32, 0, malloc_size);
		return (unsigned char *) block + 32;
	}

	if (pre_alloc_heap) {
		struct block_meta *block = sbrk(MMAP_THRESHOLD);

		block->size = MMAP_THRESHOLD - 32;
		block->status = STATUS_FREE;
		add_block(block);
		pre_alloc_heap = 0;
	}

	struct block_meta *block = find_best(malloc_size);

	if (block) {
		split_block(block, malloc_size);
		block->status = STATUS_ALLOC;
		memset((unsigned char *) block + 32, 0, malloc_size);
		return (unsigned char *) block + 32;
	}

	if (head->prev->status == STATUS_FREE) {
		block = head->prev;
		sbrk((intptr_t)(m_size(malloc_size - block->size)));
		block->size = m_size(malloc_size);
		block->status = STATUS_ALLOC;
		memset((unsigned char *) block + 32, 0, malloc_size);
		return (unsigned char *) block + 32;
	}

	block = sbrk((intptr_t)(32 + m_size(malloc_size)));
	block->size = m_size(malloc_size);
	block->status = STATUS_ALLOC;
	add_block(block);
	memset((unsigned char *) block + 32, 0, malloc_size);
	return (unsigned char *) block + 32;
}

unsigned char is_last(struct block_meta *block)
{
	while (block->next != head && block->next->status == STATUS_MAPPED)
		block = block->next;
	if (block->next == head)
		return 1;
	return 0;
}

void *os_realloc(void *ptr, size_t size)
{
	if (!ptr)
		return os_malloc(size);

	if (size == 0) {
		os_free(ptr);
		return NULL;
	}

	struct block_meta *block = head;

	while (block && (unsigned char *) block + 32 != ptr) {
		block = block->next;
		if (block == head)
			return NULL;
	}

	if (!block || block->status == STATUS_FREE)
		return NULL;

	if (block->status == STATUS_MAPPED) {
		void *new_mem = os_malloc(size);

		memcpy(new_mem, ptr, MIN(size, block->size));
		struct block_meta *temp = block->next;

		free_block(block);
		coalesce_blocks(temp);
		return new_mem;
	}

	if (is_last(block)) {
		if (size <= block->size) {
			split_block(block, size);
			block->size = m_size(size);
			block->status = STATUS_ALLOC;
			return (unsigned char *) block + 32;
		}

		sbrk((intptr_t)(m_size(size - block->size)));
		block->size = m_size(size);
		block->status = STATUS_ALLOC;
		return (unsigned char *) block + 32;
	}

	int status = block->prev->status;

	if (block != head)
		block->prev->status = STATUS_MAPPED;
	coalesce_blocks(block);
	block->prev->status = status;

	if (size <= block->size) {
		split_block(block, size);
		return (unsigned char *) block + 32;
	}

	block->status = STATUS_FREE;
	void *new_mem = os_malloc(size);

	coalesce_blocks(block);
	memcpy(new_mem, ptr, MIN(size, block->size));
	return new_mem;
}
