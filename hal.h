/* -------------------- hal.h - Hardware Abstraction Layer Interface -------------------- */
#ifndef HAL_H
#define HAL_H

#include <stdint.h>

/**
 * @brief Initialize the hardware abstraction layer.
 *
 * @note Platform-specific initializations (e.g., timers, interrupts, memory locks)
 *       should be performed here.
 */
void hal_init(void);

/**
 * @brief Start the system timer.
 *
 * @note This function should start the hardware timer that triggers the system tick.
 */
void hal_start_timer(void);

/**
 * @brief Lock all memory pages in RAM.
 *
 * @note This is useful to prevent paging and ensure real-time performance.
 */
void hal_lock_memory(void);

/**
 * @brief Perform a low-level context switch.
 *
 * @param next_task_ptr [in] Pointer to the next task's control block.
 *
 * @note The actual context switch is platform-specific and may be implemented in assembly.
 */
void hal_context_switch(void *next_task_ptr);

/**
 * @brief Get a platform-specific timestamp.
 *
 * @return uint32_t [out] Returns a timestamp (in microseconds or milliseconds,
 *         depending on platform configuration) for execution time measurement.
 */
uint32_t hal_get_timestamp(void);

#ifdef MULTI_THREAD
/**
 * @brief Create a new OS thread for a task.
 *
 * @param func [in] Function pointer to the task function.
 * @param arg [in] Argument passed to the task function.
 *
 * @return int [out] Returns 0 on success or a nonzero error code on failure.
 */
int hal_create_thread(void *(*func)(void *), void *arg);
#endif // MULTI_THREAD

/**
 * @brief Register an interrupt handler for a given interrupt source.
 *
 * @param interrupt_id [in] Unique identifier for the interrupt source.
 * @param handler [in] Function pointer to the interrupt handler.
 *
 * @return int [out] Returns 0 on success or a nonzero error code on failure.
 *
 * @note This function abstracts platform-specific interrupt registration.
 */
int hal_register_interrupt(uint32_t interrupt_id, void (*handler)(void));

#endif // HAL_H
