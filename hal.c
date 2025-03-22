/* -------------------- hal.c - HAL Stub Implementation -------------------- */
#include "hal.h"
#include <stdio.h>
#include <time.h>

#ifdef MULTI_THREAD
#include <pthread.h>
#endif

// Conditional compilation for different platforms
#ifdef PLATFORM_ARM
    #include "arm_specific.h"
#elif defined(PLATFORM_ESP32)
    #include "esp_system.h"
#elif defined(PLATFORM_STM32)
    #include "stm32f4xx.h"
#else
    // Default stub for demonstration
#endif

void hal_init(void) {
#ifdef PLATFORM_ARM
    printf("HAL (ARM): Initialization done.\n");
#elif defined(PLATFORM_ESP32)
    printf("HAL (ESP32): Initialization done.\n");
#elif defined(PLATFORM_STM32)
    printf("HAL (STM32): Initialization done.\n");
#else
    printf("HAL (Default): Initialization done.\n");
#endif
}

void hal_start_timer(void) {
#ifdef PLATFORM_ARM
    printf("HAL (ARM): Timer started.\n");
#elif defined(PLATFORM_ESP32)
    printf("HAL (ESP32): Timer started.\n");
#elif defined(PLATFORM_STM32)
    printf("HAL (STM32): Timer started.\n");
#else
    printf("HAL (Default): Timer started.\n");
#endif
}

void hal_lock_memory(void) {
#ifdef PLATFORM_ARM
    printf("HAL (ARM): Memory locked.\n");
#elif defined(PLATFORM_ESP32)
    printf("HAL (ESP32): Memory locked.\n");
#elif defined(PLATFORM_STM32)
    printf("HAL (STM32): Memory locked.\n");
#else
    printf("HAL (Default): Memory locked.\n");
#endif
}

void hal_context_switch(void *next_task_ptr) {
    (void)next_task_ptr;
#ifdef PLATFORM_ARM
    printf("HAL (ARM): Context switch invoked.\n");
#elif defined(PLATFORM_ESP32)
    printf("HAL (ESP32): Context switch invoked.\n");
#elif defined(PLATFORM_STM32)
    printf("HAL (STM32): Context switch invoked.\n");
#else
    printf("HAL (Default): Context switch invoked.\n");
#endif
}

uint32_t hal_get_timestamp(void) {
#ifdef PLATFORM_ARM
    return (uint32_t)clock(); // Replace with hardware counter for ARM
#elif defined(PLATFORM_ESP32)
    return (uint32_t)esp_timer_get_time(); // Microseconds on ESP32
#elif defined(PLATFORM_STM32)
    return (uint32_t)HAL_GetTick(); // Milliseconds on STM32
#else
    return (uint32_t)clock();
#endif
}

#ifdef MULTI_THREAD
int hal_create_thread(void *(*func)(void *), void *arg) {
    pthread_t thread;
    int ret = pthread_create(&thread, NULL, func, arg);
    if(ret == 0) {
        pthread_detach(thread);
    }
    return ret;
}
#endif

int hal_register_interrupt(uint32_t interrupt_id, void (*handler)(void)) {
    (void)interrupt_id;
    (void)handler;
#ifdef PLATFORM_ARM
    printf("HAL (ARM): Interrupt %u registered.\n", interrupt_id);
#elif defined(PLATFORM_ESP32)
    printf("HAL (ESP32): Interrupt %u registered.\n", interrupt_id);
#elif defined(PLATFORM_STM32)
    printf("HAL (STM32): Interrupt %u registered.\n", interrupt_id);
#else
    printf("HAL (Default): Interrupt %u registered.\n", interrupt_id);
#endif
    return 0;
}
