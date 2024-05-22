#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <rpi_gpio.h>

#define PERIPH_BASE 0x3F000000
#define GPIO_BASE (PERIPH_BASE + 0x200000)
#define BLOCK_SIZE (4 * 1024)

rpi_peripheral_t gpio = {GPIO_BASE, 0, NULL, NULL};

int map_peripheral(rpi_peripheral_t *p)
{
	if ((p->mem_fd = open("/dev/gpiomem", O_RDWR|O_SYNC) ) < 0) {
		fprintf(stderr, "Failed to open /dev/mem\n");
		return -1;
	}
	p->map = mmap(NULL, BLOCK_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED,
			p->mem_fd, p->addr_p
	);
	if (p->map == MAP_FAILED) {
		perror("Mmap");
		return -1;
	}

	p->addr = (volatile unsigned int *)p->map;
	return 0;
}

void unmap_peripheral(rpi_peripheral_t *p)
{
	munmap(p->map, BLOCK_SIZE);
	close(p->mem_fd);
}
