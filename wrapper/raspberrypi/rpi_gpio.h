#ifndef _RPI_GPIO_H_
#define _RPI_GPIO_H_

typedef struct rpi_peripheral_s {
	unsigned long addr_p;
	int mem_fd;
	void *map;
	volatile unsigned int *addr;
} rpi_peripheral_t;

extern rpi_peripheral_t gpio;

/* Configure GPIO as input */
#define GPIO_IN(g) *(gpio.addr + ((g) / 10)) &= ~(7 << (((g) % 10) * 3))
/* Configure GPIO as output, always to be used after GPIO_IN */
#define GPIO_OUT(g) *(gpio.addr + ((g) / 10)) |=  (1 << (((g) % 10) * 3))

/* Set GPIO for which bits are 1, ignore bits which are 0 */
#define GPIO_SET *(gpio.addr + 7)
/* Clear GPIO for which bits are 1, ignore bits which are 0 */
#define GPIO_CLR  *(gpio.addr + 10)

/* Get GPIO value */
#define GPIO_GET(g)  *(gpio.addr + 13) &= (1 << (g))

#ifdef __cplusplus
extern "C" {
#endif

int map_peripheral(rpi_peripheral_t *p);
void unmap_peripheral(rpi_peripheral_t *p);

#ifdef __cplusplus
}
#endif

#endif /* _RPI_GPIO_H_ */
