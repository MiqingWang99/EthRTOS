/* -------------------- EthRTOS.c - Enhanced RTOS Kernel for Ethereum -------------------- */
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "hal.h"
#include "sha256.h"
#include "uECC.h"


#ifdef MULTI_THREAD
#include <pthread.h>
#endif

/* -------------------- Configuration Macros -------------------- */
#define MAX_TASKS            16         // Maximum allowed number of tasks
#define STACK_SIZE           (1024 * 8) // Stack size for each task
#define PRIORITY_LEVELS      256        // Number of priority levels for the ready list

/* Task priority definitions: higher value indicates higher priority */
#define PRIORITY_HIGH        80
#define PRIORITY_MID         60
#define PRIORITY_LOW         40
#define IDLE_TASK_PRIORITY   0

/* STACK_CANARY definition: used for detecting stack overflow */
#define STACK_CANARY         0x88888888

/* Maximum execution ticks allowed; if exceeded, the task returns an error code */
#define MAX_EXECUTION_TICKS  10

/* -------------------- Global Data -------------------- */
#define DATA_BUFFER_SIZE 1024   /**< Size of each ring buffer */
 
/**
 * @brief Ring buffer structure for interrupt data.
 */
typedef struct {
    uint8_t buffer[DATA_BUFFER_SIZE];  /**< Data buffer */
    volatile uint32_t head;            /**< Head index */
    volatile uint32_t tail;            /**< Tail index */
} ring_buffer_t;

/* We assume a maximum of 256 possible interrupt IDs */
ring_buffer_t interrupt_buffers[256] = {0};

/* -------------------- Memory Backup for Strict Memory Control -------------------- */
typedef struct tcb tcb_t;  // Forward declaration for backup
tcb_t backup_tasks[MAX_TASKS];

/* -------------------- TCB Data Structure and Error Codes -------------------- */
/**
 * @brief Enumeration for Ethereum task error codes.
 *
 * @note These error codes are based on CIP-style error codes.
 */
typedef enum {
    /* Core Errors (0-99) */
    ETH_SUCCESS                        = 0,   /**< Operation succeeded */
    ETH_ERROR_TX_VERIFICATION_TIMEOUT  = 1,   /**< Transaction verification timeout */
    ETH_ERROR_BLOCK_HASH_TIMEOUT       = 2,   /**< Block hash calculation timeout */
    ETH_ERROR_TX_SORT_GAS_TIMEOUT      = 3,   /**< Transaction sorting/GAS calculation timeout */
    ETH_ERROR_STATE_UPDATE_TIMEOUT     = 4,   /**< State update operation timeout */
    ETH_ERROR_BUFFER_TOO_SMALL         = 5,   /**< Insufficient buffer size */

    /* Communication Errors (100-199) */
    ETH_ERROR_COMM_TIMEOUT             = 100, /**< Communication timeout */
    ETH_ERROR_CONNECTION_LOST          = 101, /**< Connection lost */
    ETH_ERROR_DEVICE_BUSY              = 102, /**< Device busy */
    ETH_ERROR_IO_FAILURE               = 103, /**< I/O operation failure */
    ETH_ERROR_PROTOCOL_VIOLATION       = 104, /**< Protocol violation */
    ETH_ERROR_CRC_MISMATCH             = 105, /**< CRC verification failed */

    /* Protocol Errors (200-299) */
    ETH_ERROR_INVALID_PACKET           = 200, /**< Malformed packet */
    ETH_ERROR_UNSUPPORTED_VERSION      = 201, /**< Protocol version not supported */
    ETH_ERROR_CHECKSUM_FAILURE         = 202, /**< Checksum validation failed */

    /* Hardware Errors (300-399) */
    ETH_ERROR_HW_FAILURE               = 300, /**< Hardware malfunction */
    ETH_ERROR_DEVICE_NOT_FOUND         = 301, /**< Device not detected */
    ETH_ERROR_HW_BUSY                  = 302, /**< Hardware resource busy */
    ETH_ERROR_DRIVER_FAILURE           = 303, /**< Driver malfunction */

    /* Security Errors (400-499) */
    ETH_ERROR_ACCESS_DENIED            = 400, /**< Permission denied */
    ETH_ERROR_AUTH_FAILURE             = 401, /**< Authentication failure */
    ETH_ERROR_CRYPTO_FAILURE           = 402  /**< Cryptographic operation failure */
} eth_error_t;

/**
 * @brief Enumeration for task states.
 *
 * @note Includes invalid, ready, running, blocked, suspended, terminated, and maximum state.
 */
typedef enum {
    TASK_INVALID    = 0,   /**< Invalid state */
    TASK_READY      = 1,   /**< Ready state */
    TASK_RUNNING    = 2,   /**< Running state */
    TASK_BLOCKED    = 3,   /**< Blocked (delayed) state */
    TASK_SUSPENDED  = 4,   /**< Suspended state */
    TASK_TERMINATED = 5,   /**< Terminated state */
    TASK_MAX_STATE  = 6    /**< Total number of states */
} task_state_t;

/**
 * @brief Type definition for a task entry function.
 *
 * @param param [in] Pointer to task parameters (optional)
 * @return int Returns ETH_SUCCESS on success or a defined error code on failure.
 */
typedef uint32_t (*task_func_t)(void *);

/**
 * @brief Task Control Block (TCB)
 *
 * @note Contains task entry, parameters, stack, state, priority, delay counter, stack canary,
 *       an error code, last execution time (for monitoring), the interrupt resource ID that triggers the task,
 *       a pointer to the ring buffer assigned to this task, and pointers for a doubly-linked ready list.
 */
struct tcb {
    task_func_t     entry;             /**< Task entry function */
    void           *parameter;         /**< Task parameter */
    uint8_t         stack[STACK_SIZE];   /**< Task stack */
    uint8_t        *sp;                /**< Simulated stack pointer */
    task_state_t    state;             /**< Task state */
    uint8_t         priority;          /**< Task priority (higher value = higher priority) */
    uint32_t        tick_count;        /**< Delay tick counter */
    uint32_t        secure_canary;     /**< Stack canary for safety check */
    uint32_t        error_code;        /**< Error code (ETH_SUCCESS if none) */
    uint32_t        last_exec_time;    /**< Execution time of the last run (platform-specific units) */
    uint32_t        trigger_interrupt; /**< Interrupt resource ID that triggers this task */
    ring_buffer_t  *rb;                /**< Pointer to the ring buffer assigned to this task */
    struct tcb     *next;              /**< Pointer to the next ready task (doubly-linked list) */
    struct tcb     *prev;              /**< Pointer to the previous ready task (doubly-linked list) */
};

/* -------------------- Global Variables -------------------- */
tcb_t tasks[MAX_TASKS];                     // Array of TCBs
volatile tcb_t *current_task = NULL;        // Currently running task
tcb_t *ready_list[PRIORITY_LEVELS] = {0};     // Ready list array; each priority level corresponds to a list

/* -------------------- Memory Backup and Recovery -------------------- */
/**
 * @brief Backup the current TCB array using memcpy_s.
 *
 * @note Copies the entire tasks array into backup_tasks.
 */
void backup_memory(void) {
    uint32_t ret = memcpy_s(backup_tasks, sizeof(backup_tasks), tasks, sizeof(tasks));
    assert(ret == 0);
}

/**
 * @brief Check and recover the TCB memory.
 *
 * @note Compares the tasks array with the backup; if differences are found, restores from backup.
 */
void check_and_recover_memory(void) {
    if (memcmp(tasks, backup_tasks, sizeof(tasks)) != 0) {
        uint32_t ret = memcpy_s(tasks, sizeof(tasks), backup_tasks, sizeof(backup_tasks));
        assert(ret == 0);
#ifdef DEBUG
        printf("Memory corruption detected! Restored backup.\n");
#endif
    }
}

/* -------------------- Ring Buffer Operations -------------------- */
/**
 * @brief Push a data byte into the specified ring buffer.
 *
 * @param rb [in] Pointer to the ring buffer.
 * @param byte [in] Data byte to push.
 * @return int Returns 0 on success, -1 if buffer is full.
 */
uint32_t ring_buffer_push(ring_buffer_t *rb, uint8_t byte) {
    uint32_t next_head = (rb->head + 1) % DATA_BUFFER_SIZE;
    if (next_head == rb->tail) {
         return -1; // Buffer full
    }
    rb->buffer[rb->head] = byte;
    rb->head = next_head;
    return 0;
}

/**
 * @brief Pop a data byte from the specified ring buffer.
 *
 * @param rb [in] Pointer to the ring buffer.
 * @param byte [out] Pointer to store the popped byte.
 * @return int Returns 0 on success, -1 if buffer is empty.
 */
uint32_t ring_buffer_pop(ring_buffer_t *rb, uint8_t *byte) {
    if (rb->head == rb->tail) {
         return -1; // Buffer empty
    }
    *byte = rb->buffer[rb->tail];
    rb->tail = (rb->tail + 1) % DATA_BUFFER_SIZE;
    return 0;
}

/* -------------------- Cryptographic Operations -------------------- */
#ifdef USE_SECP256
/**
 * @brief Perform ECDSA verification using libsecp256k1.
 *
 * @param msg [in] Pointer to the message data.
 * @param msg_len [in] Length of the message.
 * @param sig [in] Pointer to the 64-byte raw signature (R || S).
 * @param pub_key [in] Pointer to the 33-byte compressed public key.
 * @return int Returns ETH_SUCCESS if valid, ETH_ERROR_AUTH_FAILURE otherwise.
 */
uint32_t perform_ecdsa_verification(const uint8_t *msg, size_t msg_len,
                               const uint8_t *sig, const uint8_t *pub_key) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    
    uint8_t hash[32];
    SHA256_CTX sha_ctx;
    sha256_init(&sha_ctx);
    sha256_update(&sha_ctx, msg, msg_len);
    sha256_final(&sha_ctx, hash);

    secp256k1_ecdsa_signature signature;
    if (!secp256k1_ecdsa_signature_parse_compact(ctx, &signature, sig)) {
        secp256k1_context_destroy(ctx);
        return ETH_ERROR_AUTH_FAILURE; // Signature parsing failed
    }

    secp256k1_pubkey secp_pubkey;
    if (!secp256k1_ec_pubkey_parse(ctx, &secp_pubkey, pub_key, 33)) {
        secp256k1_context_destroy(ctx);
        return ETH_ERROR_AUTH_FAILURE; // Public key parsing failed
    }

    uint32_t verified = secp256k1_ecdsa_verify(ctx, &signature, hash, &secp_pubkey);
    secp256k1_context_destroy(ctx);
    return (verified == 1) ? ETH_SUCCESS : ETH_ERROR_AUTH_FAILURE;
}
#else
/**
 * @brief Perform ECDSA verification using micro-ecc (uECC).
 *
 * @param msg [in] Pointer to the 32-byte message hash.
 * @param sig [in] Pointer to the 64-byte signature (R || S).
 * @param pub_key [in] Pointer to the 64-byte public key.
 * @return int Returns ETH_SUCCESS if valid, ETH_ERROR_AUTH_FAILURE otherwise.
 */
uint32_t perform_ecdsa_verification(const uint8_t *msg, const uint8_t *sig, const uint8_t *pub_key) {
    uECC_Curve curve = uECC_secp256k1();
    return uECC_verify(pub_key, msg, 32, sig, curve) ? ETH_SUCCESS : ETH_ERROR_AUTH_FAILURE;
}
#endif


/**
 * @brief Perform Keccak-256 hash calculation using the minimal SHA256 library.
 *
 * @param data [in] Pointer to input data.
 * @param data_len [in] Length of input data.
 * @param hash [out] Buffer to store the 32-byte hash.
 * @param hash_len [in] Length of the hash buffer.
 * @return int Returns ETH_SUCCESS on success, or ETH_ERROR_BUFFER_TOO_SMALL if the buffer is insufficient.
 *
 * @note For demonstration, this implementation uses SHA256 as a placeholder for Keccak-256.
 *       Replace with a real Keccak-256 implementation as needed.
 */
uint32_t perform_keccak256(const uint8_t *data, size_t data_len, uint8_t *hash, size_t hash_len) {
    if (hash_len < 32) {
         return ETH_ERROR_BUFFER_TOO_SMALL;
    }
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, hash);
    return ETH_SUCCESS;
}

/* -------------------- ETH-Related Tasks -------------------- */
/**
 * @brief ETH transaction verification task.
 *
 * @param param [in] Unused parameter.
 * @return int Returns ETH_SUCCESS on success or an error code on failure.
 *
 * @note Triggered by an interrupt when a new transaction verification request arrives.
 *       Retrieves data from its assigned ring buffer, performs full ECDSA verification,
 *       and simulates sending the result. Execution time is measured.
 */
uint32_t task_eth_tx_verification(void *param) {
    (void)param;
    static uint32_t exec_ticks = 0;
    uint32_t start_time = hal_get_timestamp();
    exec_ticks++;

    if (exec_ticks > MAX_EXECUTION_TICKS) {
        return ETH_ERROR_TX_VERIFICATION_TIMEOUT;
    }

    uint8_t msg[32];  // Assume message is 32 bytes (Ethereum transaction hash)
    if (ring_buffer_pop(current_task->rb, msg) != 0) {
        return ETH_ERROR_IO_FAILURE;
    }

    uint8_t signature[64] = { /* Placeholder: R || S (64 bytes) */ };
    uint8_t public_key[64] = { /* Placeholder: Uncompressed Public Key (64 bytes) */ };

    int verify_ret = perform_ecdsa_verification(msg, signature, public_key);
    if (verify_ret != ETH_SUCCESS) {
        return verify_ret;
    }

    task_delay((tcb_t *)current_task, 2);
    systick_handler();
    uint32_t end_time = hal_get_timestamp();
    current_task->last_exec_time = end_time - start_time;
    return ETH_SUCCESS;
}

/**
 * @brief ETH block hash calculation task.
 *
 * @param param [in] Unused parameter.
 * @return int Returns ETH_SUCCESS on success or an error code on failure.
 *
 * @note Triggered by an interrupt when a new block arrives.
 *       Retrieves a data packet from its assigned ring buffer, performs Keccak-256 hash calculation,
 *       and simulates sending the hash result. Execution time is measured.
 */
uint32_t task_eth_block_hash(void *param) {
    (void)param;
    static uint32_t exec_ticks = 0;
    uint32_t start_time = hal_get_timestamp();
    exec_ticks++;
    if (exec_ticks > MAX_EXECUTION_TICKS) {
        return ETH_ERROR_BLOCK_HASH_TIMEOUT;
    }
    uint8_t packet[4] = {0};
    for (int i = 0; i < 4; i++) {
         if (ring_buffer_pop(current_task->rb, &packet[i]) != 0) {
             break;
         }
    }
    uint8_t hash[32];
    int hash_ret = perform_keccak256(packet, 4, hash, sizeof(hash));
    if (hash_ret != ETH_SUCCESS) {
         return hash_ret;
    }
    task_delay((tcb_t *)current_task, 3);
    systick_handler();
    uint32_t end_time = hal_get_timestamp();
    current_task->last_exec_time = end_time - start_time;
    return ETH_SUCCESS;
}

/**
 * @brief ETH transaction sorting and GAS calculation task.
 *
 * @param param [in] Unused parameter.
 * @return int Returns ETH_SUCCESS on success or an error code on failure.
 *
 * @note Triggered by an interrupt when new transaction data arrives.
 *       Retrieves data from its assigned ring buffer, performs dummy sorting and GAS computation,
 *       and simulates sending the computed result. Execution time is measured.
 */
uint32_t task_eth_tx_sort_gas(void *param) {
    (void)param;
    static uint32_t exec_ticks = 0;
    uint32_t start_time = hal_get_timestamp();
    exec_ticks++;
    if (exec_ticks > MAX_EXECUTION_TICKS) {
        return ETH_ERROR_TX_SORT_GAS_TIMEOUT;
    }
    uint8_t tx_data;
    if (ring_buffer_pop(current_task->rb, &tx_data) != 0) {
         return ETH_ERROR_IO_FAILURE;
    }
    tx_data ^= 0xAA; // Dummy processing
    task_delay((tcb_t *)current_task, 4);
    systick_handler();
    uint32_t end_time = hal_get_timestamp();
    current_task->last_exec_time = end_time - start_time;
    return ETH_SUCCESS;
}

/**
 * @brief ETH state update task.
 *
 * @param param [in] Unused parameter.
 * @return int Returns ETH_SUCCESS on success or an error code on failure.
 *
 * @note Triggered by an interrupt when new state data is available.
 *       Retrieves data from its assigned ring buffer, performs a dummy state update,
 *       and simulates sending the updated state. Execution time is measured.
 */
uint32_t task_eth_state_update(void *param) {
    (void)param;
    static uint32_t exec_ticks = 0;
    uint32_t start_time = hal_get_timestamp();
    exec_ticks++;
    if (exec_ticks > MAX_EXECUTION_TICKS) {
        return ETH_ERROR_STATE_UPDATE_TIMEOUT;
    }
    uint8_t state_data;
    if (ring_buffer_pop(current_task->rb, &state_data) != 0) {
         return ETH_ERROR_IO_FAILURE;
    }
    state_data = ~state_data; // Dummy state update
    task_delay((tcb_t *)current_task, 5);
    systick_handler();
    uint32_t end_time = hal_get_timestamp();
    current_task->last_exec_time = end_time - start_time;
    return ETH_SUCCESS;
}

/**
 * @brief ETH smart contract execution task.
 *
 * @param param [in] Unused parameter.
 * @return int Returns ETH_SUCCESS on success or an error code on failure.
 *
 * @note Simulates smart contract execution by retrieving contract data from its assigned ring buffer,
 *       performing a dummy state transition, and simulating sending the result.
 *       Execution time is measured.
 */
uint32_t task_eth_contract_execution(void *param) {
    (void)param;
    static uint32_t exec_ticks = 0;
    uint32_t start_time = hal_get_timestamp();
    exec_ticks++;
    if (exec_ticks > MAX_EXECUTION_TICKS) {
        return ETH_ERROR_PROTOCOL_VIOLATION;
    }
    uint8_t contract_data;
    if (ring_buffer_pop(current_task->rb, &contract_data) != 0) {
         return ETH_ERROR_IO_FAILURE;
    }
    contract_data += 5; // Dummy contract execution
    task_delay((tcb_t *)current_task, 3);
    systick_handler();
    uint32_t end_time = hal_get_timestamp();
    current_task->last_exec_time = end_time - start_time;
    return ETH_SUCCESS;
}

/**
 * @brief ETH mining reward calculation task.
 *
 * @param param [in] Unused parameter.
 * @return int Returns ETH_SUCCESS on success or an error code on failure.
 *
 * @note Simulates mining reward calculation by retrieving mining data from its assigned ring buffer,
 *       performing dummy reward computation, and simulating sending the reward.
 *       Execution time is measured.
 */
uint32_t task_eth_mining(void *param) {
    (void)param;
    static uint32_t exec_ticks = 0;
    uint32_t start_time = hal_get_timestamp();
    exec_ticks++;
    if (exec_ticks > MAX_EXECUTION_TICKS) {
        return ETH_ERROR_HW_BUSY;
    }
    uint8_t mining_data;
    if (ring_buffer_pop(current_task->rb, &mining_data) != 0) {
         return ETH_ERROR_IO_FAILURE;
    }
    mining_data = (mining_data + 10) % 256; // Dummy mining calculation
    task_delay((tcb_t *)current_task, 4);
    systick_handler();
    uint32_t end_time = hal_get_timestamp();
    current_task->last_exec_time = end_time - start_time;
    return ETH_SUCCESS;
}

/**
 * @brief ETH data encryption task.
 *
 * @param param [in] Unused parameter.
 * @return int Returns ETH_SUCCESS on success or an error code on failure.
 *
 * @note Simulates data encryption by retrieving plaintext from its assigned ring buffer,
 *       performing dummy encryption (XOR with key 0x5A), and simulating sending the encrypted data.
 *       Execution time is measured.
 */
uint32_t task_eth_data_encryption(void *param) {
    (void)param;
    static uint32_t exec_ticks = 0;
    uint32_t start_time = hal_get_timestamp();
    exec_ticks++;
    if (exec_ticks > MAX_EXECUTION_TICKS) {
        return ETH_ERROR_CRYPTO_FAILURE;
    }
    uint8_t plain_data;
    if (ring_buffer_pop(current_task->rb, &plain_data) != 0) {
         return ETH_ERROR_IO_FAILURE;
    }
    plain_data ^= 0x5A; // Dummy encryption
    task_delay((tcb_t *)current_task, 3);
    systick_handler();
    uint32_t end_time = hal_get_timestamp();
    current_task->last_exec_time = end_time - start_time;
    return ETH_SUCCESS;
}

/**
 * @brief Idle task function.
 *
 * @param param [in] Unused parameter.
 * @return int Always returns ETH_SUCCESS.
 *
 * @note The idle task runs when no other task is ready.
 */
uint32_t idle_task(void *param) {
    (void)param;
    systick_handler();
    return ETH_SUCCESS;
}

/* -------------------- Multi-Thread Support -------------------- */
#ifdef MULTI_THREAD
/**
 * @brief OS thread entry wrapper for RTOS tasks.
 *
 * @param arg [in] Pointer to the task's TCB.
 * @return void* Always returns NULL.
 *
 * @note This wrapper allows each task to run in its own OS thread.
 */
void *rtos_thread_entry(void *arg) {
    tcb_t *tcb = (tcb_t *)arg;
    while (tcb->state != TASK_TERMINATED) {
        uint32_t ret = tcb->entry(tcb->parameter);
        if (ret != ETH_SUCCESS) {
            tcb->error_code = ret;
            tcb->state = TASK_TERMINATED;
            break;
        }
        // In an interrupt-driven system, tasks are reactivated by interrupts.
    }
    return NULL;
}

/**
 * @brief Create an OS thread for an RTOS task.
 *
 * @param tcb [in] Pointer to the task's TCB.
 * @return int Returns 0 on success, or a nonzero error code on failure.
 */
uint32_t rtos_thread_create(tcb_t *tcb) {
    assert(tcb != NULL);
    return hal_create_thread(rtos_thread_entry, (void *)tcb);
}
#endif // MULTI_THREAD

/* -------------------- Scheduler and System Tick -------------------- */
/**
 * @brief Select the highest-priority ready task.
 *
 * @return tcb_t* Pointer to the selected task control block; returns NULL if no task is ready.
 */
tcb_t *select_next_task(void) {
    for (uint32_t prio = PRIORITY_LEVELS - 1; prio >= 0; prio--) {
        if (ready_list[prio] != NULL) {
            return ready_list[prio];
        }
    }
    return NULL;
}

/**
 * @brief Perform a context switch to the specified task.
 *
 * @param next [in] Pointer to the task control block to switch to.
 *
 * @note Calls the platform-specific context switch function in the HAL.
 */
void context_switch(tcb_t *next) {
    assert(next != NULL);
    hal_context_switch((void *)next);
    current_task = next;
}

/**
 * @brief System tick handler.
 *
 * @return void
 *
 * @note Decrements delay counters for blocked tasks. When a task's tick_count reaches zero,
 *       sets it to READY and adds it to the ready list. Then, schedules the highest-priority task.
 */
void systick_handler(void) {
    for (uint32_t i = 0; i < MAX_TASKS; i++) {
        if (tasks[i].state == TASK_BLOCKED && tasks[i].tick_count > 0) {
            tasks[i].tick_count--;
            if (tasks[i].tick_count == 0) {
                tasks[i].state = TASK_READY;
                add_to_ready_list(&tasks[i]);
            }
        }
    }

    // Determine the next task based on execution slot allocation
    tcb_t *next = select_next_task();
    if (next && next != current_task) {
        uint32_t allocated_cycles = get_execution_cycles(next);
        if (allocated_cycles > 0) {
            execute_task_with_slot(next, allocated_cycles);
        } else {
            remove_from_ready_list(next); // Prevent indefinite execution
        }
    }
}

/**
 * @brief Get the number of CPU cycles allocated to a task.
 *
 * @param tcb [in] Pointer to the task control block.
 * @return uint32_t The number of cycles allowed based on Gas metering.
 */
uint32_t get_execution_cycles(tcb_t *tcb) {
    return tcb->gas_limit * CPU_CYCLES_PER_GAS_UNIT;
}

/**
 * @brief Execute a task within its allocated CPU slot.
 *
 * @param tcb [in] Pointer to the task control block.
 * @param cycles [in] Maximum cycles allowed.
 */
void execute_task_with_slot(tcb_t *tcb, uint32_t cycles) {
    uint32_t start_time = hal_get_timestamp();
    uint32_t result = tcb->entry(tcb->parameter);
    uint32_t end_time = hal_get_timestamp();

    uint32_t used_cycles = end_time - start_time;
    if (used_cycles > cycles) {
        tcb->state = TASK_TERMINATED;  // Kill task if it overran its slot
    } else {
        tcb->gas_limit -= used_cycles / CPU_CYCLES_PER_GAS_UNIT;
    }
}

/* -------------------- Safety Check -------------------- */
/**
 * @brief Check the integrity of a task's stack.
 *
 * @param tcb [in] Pointer to the task control block.
 * @return bool Returns true if the stack canary is intact; false otherwise.
 */
bool check_task_security(tcb_t *tcb) {
    assert(tcb != NULL);
    return (tcb->secure_canary == STACK_CANARY);
}

/* -------------------- Interrupt Handler Abstraction -------------------- */
/**
 * @brief Generic interrupt handler callback.
 *
 * @param interrupt_id [in] Interrupt resource identifier.
 *
 * @note This handler is called by the HAL when an interrupt occurs.
 *       It pushes incoming data into the ring buffer corresponding to the interrupt,
 *       and marks the associated task as READY.
 */
void generic_interrupt_handler(uint32_t interrupt_id) {
    // Simulate receiving a data byte from hardware.
    uint8_t dummy = (uint8_t)(interrupt_id & 0xFF);
    ring_buffer_push(&interrupt_buffers[interrupt_id], dummy);
    // Find and activate the task associated with this interrupt.
    for (uint32_t i = 0; i < MAX_TASKS; i++) {
        if (tasks[i].trigger_interrupt == interrupt_id) {
            if (tasks[i].state != TASK_RUNNING) {
                tasks[i].state = TASK_READY;
                add_to_ready_list(&tasks[i]);
            }
        }
    }
}

/* -------------------- Task Management -------------------- */
/**
 * @brief Create a new task.
 *
 * @param task_id [in] Task ID (0 to MAX_TASKS-1).
 * @param entry [in] Pointer to the task's entry function.
 * @param param [in] Pointer to the task parameter.
 * @param priority [in] Task priority.
 * @param interrupt_id [in] Interrupt resource ID that triggers this task.
 *
 * @note Initializes the TCB, assigns a ring buffer for this task if interrupt_id > 0,
 *       registers the interrupt with the HAL, and adds the task to the ready list.
 */
void create_task(uint32_t task_id, task_func_t entry, void *param, uint8_t priority, uint32_t interrupt_id) {
    assert(task_id >= 0 && task_id < MAX_TASKS);
    tcb_t *tcb = &tasks[task_id];
    tcb->entry = entry;
    tcb->parameter = param;
    tcb->state = TASK_READY;
    tcb->priority = priority;
    tcb->tick_count = 0;
    tcb->secure_canary = STACK_CANARY;
    tcb->error_code = ETH_SUCCESS;
    tcb->last_exec_time = 0;
    tcb->trigger_interrupt = interrupt_id;
    tcb->sp = tcb->stack + STACK_SIZE - 1;
    tcb->next = tcb->prev = NULL;
    /* If this task is triggered by an interrupt, assign the corresponding ring buffer */
    if (interrupt_id > 0) {
        tcb->rb = &interrupt_buffers[interrupt_id];
        uint32_t reg_ret = hal_register_interrupt(interrupt_id, (void (*)(void))generic_interrupt_handler);
        assert(reg_ret == 0);
    } else {
        tcb->rb = NULL;
    }
    add_to_ready_list(tcb);
}

/**
 * @brief Delay a task by a specified number of ticks.
 *
 * @param tcb [in] Pointer to the task control block.
 * @param ticks [in] Number of ticks to delay.
 *
 * @note Removes the task from the ready list and sets its state to BLOCKED.
 */
void task_delay(tcb_t *tcb, uint32_t ticks) {
    assert(tcb != NULL);
    remove_from_ready_list(tcb);
    tcb->tick_count = ticks;
    tcb->state = TASK_BLOCKED;
}

/* -------------------- ETH-Related Tasks -------------------- */
uint32_t task_eth_tx_verification(void *param) {
    (void)param;
    static uint32_t exec_ticks = 0;
    uint32_t start_time = hal_get_timestamp();
    exec_ticks++;
    if (exec_ticks > MAX_EXECUTION_TICKS) {
        return ETH_ERROR_TX_VERIFICATION_TIMEOUT;
    }
    uint8_t msg;
    if (ring_buffer_pop(current_task->rb, &msg) != 0) {
         return ETH_ERROR_IO_FAILURE;
    }
    /* For a real implementation, obtain signature and public key from secure storage */
    uint8_t signature[70] = {0};
    uint8_t pub_key[33] = {0};
    uint32_t verify_ret = perform_ecdsa_verification(&msg, 1, signature, sizeof(signature), pub_key, sizeof(pub_key));
    if (verify_ret != ETH_SUCCESS) {
         return verify_ret;
    }
    task_delay((tcb_t *)current_task, 2);
    systick_handler();
    uint32_t end_time = hal_get_timestamp();
    current_task->last_exec_time = end_time - start_time;
    return ETH_SUCCESS;
}

uint32_t task_eth_block_hash(void *param) {
    (void)param;
    static uint32_t exec_ticks = 0;
    uint32_t start_time = hal_get_timestamp();
    exec_ticks++;
    if (exec_ticks > MAX_EXECUTION_TICKS) {
        return ETH_ERROR_BLOCK_HASH_TIMEOUT;
    }
    uint8_t packet[4] = {0};
    for (uint32_t i = 0; i < 4; i++) {
         if (ring_buffer_pop(current_task->rb, &packet[i]) != 0) {
             break;
         }
    }
    uint8_t hash[32];
    uint32_t hash_ret = perform_keccak256(packet, 4, hash, sizeof(hash));
    if (hash_ret != ETH_SUCCESS) {
         return hash_ret;
    }
    task_delay((tcb_t *)current_task, 3);
    systick_handler();
    uint32_t end_time = hal_get_timestamp();
    current_task->last_exec_time = end_time - start_time;
    return ETH_SUCCESS;
}

uint32_t task_eth_tx_sort_gas(void *param) {
    (void)param;
    static uint32_t exec_ticks = 0;
    uint32_t start_time = hal_get_timestamp();
    exec_ticks++;
    if (exec_ticks > MAX_EXECUTION_TICKS) {
        return ETH_ERROR_TX_SORT_GAS_TIMEOUT;
    }
    uint8_t tx_data;
    if (ring_buffer_pop(current_task->rb, &tx_data) != 0) {
         return ETH_ERROR_IO_FAILURE;
    }
    tx_data ^= 0xAA; // Dummy processing for sorting and GAS calculation
    task_delay((tcb_t *)current_task, 4);
    systick_handler();
    uint32_t end_time = hal_get_timestamp();
    current_task->last_exec_time = end_time - start_time;
    return ETH_SUCCESS;
}

uint32_t task_eth_state_update(void *param) {
    (void)param;
    static uint32_t exec_ticks = 0;
    uint32_t start_time = hal_get_timestamp();
    exec_ticks++;
    if (exec_ticks > MAX_EXECUTION_TICKS) {
        return ETH_ERROR_STATE_UPDATE_TIMEOUT;
    }
    uint8_t state_data;
    if (ring_buffer_pop(current_task->rb, &state_data) != 0) {
         return ETH_ERROR_IO_FAILURE;
    }
    state_data = ~state_data; // Dummy state update
    task_delay((tcb_t *)current_task, 5);
    systick_handler();
    uint32_t end_time = hal_get_timestamp();
    current_task->last_exec_time = end_time - start_time;
    return ETH_SUCCESS;
}

uint32_t task_eth_contract_execution(void *param) {
    (void)param;
    static uint32_t exec_ticks = 0;
    uint32_t start_time = hal_get_timestamp();
    exec_ticks++;
    if (exec_ticks > MAX_EXECUTION_TICKS) {
        return ETH_ERROR_PROTOCOL_VIOLATION;
    }
    uint8_t contract_data;
    if (ring_buffer_pop(current_task->rb, &contract_data) != 0) {
         return ETH_ERROR_IO_FAILURE;
    }
    contract_data += 5; // Dummy smart contract execution
    task_delay((tcb_t *)current_task, 3);
    systick_handler();
    uint32_t end_time = hal_get_timestamp();
    current_task->last_exec_time = end_time - start_time;
    return ETH_SUCCESS;
}

uint32_t task_eth_mining(void *param) {
    (void)param;
    static uint32_t exec_ticks = 0;
    uint32_t start_time = hal_get_timestamp();
    exec_ticks++;
    if (exec_ticks > MAX_EXECUTION_TICKS) {
        return ETH_ERROR_HW_BUSY;
    }
    uint8_t mining_data;
    if (ring_buffer_pop(current_task->rb, &mining_data) != 0) {
         return ETH_ERROR_IO_FAILURE;
    }
    mining_data = (mining_data + 10) % 256; // Dummy mining reward calculation
    task_delay((tcb_t *)current_task, 4);
    systick_handler();
    uint32_t end_time = hal_get_timestamp();
    current_task->last_exec_time = end_time - start_time;
    return ETH_SUCCESS;
}

uint32_t task_eth_data_encryption(void *param) {
    (void)param;
    static uint32_t exec_ticks = 0;
    uint32_t start_time = hal_get_timestamp();
    exec_ticks++;
    if (exec_ticks > MAX_EXECUTION_TICKS) {
        return ETH_ERROR_CRYPTO_FAILURE;
    }
    uint8_t plain_data;
    if (ring_buffer_pop(current_task->rb, &plain_data) != 0) {
         return ETH_ERROR_IO_FAILURE;
    }
    plain_data ^= 0x5A; // Dummy data encryption
    task_delay((tcb_t *)current_task, 3);
    systick_handler();
    uint32_t end_time = hal_get_timestamp();
    current_task->last_exec_time = end_time - start_time;
    return ETH_SUCCESS;
}

uint32_t idle_task(void *param) {
    (void)param;
    systick_handler();
    return ETH_SUCCESS;
}

/* -------------------- Multi-Thread Support -------------------- */
#ifdef MULTI_THREAD
void *rtos_thread_entry(void *arg) {
    tcb_t *tcb = (tcb_t *)arg;
    while (tcb->state != TASK_TERMINATED) {
        uint32_t ret = tcb->entry(tcb->parameter);
        if (ret != ETH_SUCCESS) {
            tcb->error_code = ret;
            tcb->state = TASK_TERMINATED;
            break;
        }
        // In an interrupt-driven system, tasks are reactivated by interrupts.
    }
    return NULL;
}

uint32_t rtos_thread_create(tcb_t *tcb) {
    assert(tcb != NULL);
    return hal_create_thread(rtos_thread_entry, (void *)tcb);
}
#endif

/* -------------------- Scheduler and System Tick -------------------- */
tcb_t *select_next_task(void) {
    for (uint32_t prio = PRIORITY_LEVELS - 1; prio >= 0; prio--) {
        if (ready_list[prio] != NULL) {
            return ready_list[prio];
        }
    }
    return NULL;
}

void context_switch(tcb_t *next) {
    assert(next != NULL);
    hal_context_switch((void *)next);
    current_task = next;
}

void systick_handler(void) {
    for (uint32_t i = 0; i < MAX_TASKS; i++) {
        if (tasks[i].state == TASK_BLOCKED && tasks[i].tick_count > 0) {
            tasks[i].tick_count--;
            if (tasks[i].tick_count == 0) {
                tasks[i].state = TASK_READY;
                add_to_ready_list(&tasks[i]);
            }
        }
    }
    tcb_t *next = select_next_task();
    if (next && next != current_task) {
        context_switch(next);
    }
}

/* -------------------- Safety Check -------------------- */
bool check_task_security(tcb_t *tcb) {
    assert(tcb != NULL);
    return (tcb->secure_canary == STACK_CANARY);
}

/* -------------------- Interrupt Handler Abstraction -------------------- */
void generic_interrupt_handler(uint32_t interrupt_id) {
    uint8_t dummy = (uint8_t)(interrupt_id & 0xFF);
    ring_buffer_push(&interrupt_buffers[interrupt_id], dummy);
    for (uint32_t i = 0; i < MAX_TASKS; i++) {
        if (tasks[i].trigger_interrupt == interrupt_id) {
            if (tasks[i].state != TASK_RUNNING) {
                tasks[i].state = TASK_READY;
                add_to_ready_list(&tasks[i]);
            }
        }
    }
}

/* -------------------- Task Management -------------------- */
void create_task(uint32_t task_id, task_func_t entry, void *param, uint8_t priority, uint32_t interrupt_id) {
    assert(task_id >= 0 && task_id < MAX_TASKS);
    tcb_t *tcb = &tasks[task_id];
    tcb->entry = entry;
    tcb->parameter = param;
    tcb->state = TASK_READY;
    tcb->priority = priority;
    tcb->tick_count = 0;
    tcb->secure_canary = STACK_CANARY;
    tcb->error_code = ETH_SUCCESS;
    tcb->last_exec_time = 0;
    tcb->trigger_interrupt = interrupt_id;
    tcb->sp = tcb->stack + STACK_SIZE - 1;
    tcb->next = tcb->prev = NULL;
    if (interrupt_id > 0) {
        tcb->rb = &interrupt_buffers[interrupt_id];
        uint32_t reg_ret = hal_register_interrupt(interrupt_id, (void (*)(void))generic_interrupt_handler);
        assert(reg_ret == 0);
    } else {
        tcb->rb = NULL;
    }
    add_to_ready_list(tcb);
}

void task_delay(tcb_t *tcb, uint32_t ticks) {
    assert(tcb != NULL);
    remove_from_ready_list(tcb);
    tcb->tick_count = ticks;
    tcb->state = TASK_BLOCKED;
}

/* -------------------- Kernel Initialization and Start -------------------- */
void kernel_init(void) {
    hal_init();
    hal_lock_memory();
    for (int i = 0; i < PRIORITY_LEVELS; i++) {
        ready_list[i] = NULL;
    }
    backup_memory();
}

void kernel_start(void) {
#ifdef MULTI_THREAD
    for (uint32_t i = 0; i < MAX_TASKS; i++) {
        if (tasks[i].state == TASK_READY) {
            uint32_t ret = rtos_thread_create(&tasks[i]);
            assert(ret == 0);
        }
    }
    while (1) {
        check_and_recover_memory();
    }
#else
    hal_start_timer();
    current_task = select_next_task();
    assert(current_task != NULL);
    while (1) {
        uint32_t ret = current_task->entry(current_task->parameter);
        if (ret != ETH_SUCCESS) {
            current_task->error_code = ret;
            current_task->state = TASK_TERMINATED;
            remove_from_ready_list((tcb_t *)current_task);
        }
        current_task = select_next_task();
        if (current_task == NULL) {
            break;
        }
        check_and_recover_memory();
    }
#endif
}

/* -------------------- Main Function -------------------- */
uint32_t main(void) {
    kernel_init();
    /* Create Ethereum-related tasks with defined priorities and interrupt IDs:
       - Task 0: Transaction verification triggered by interrupt 10.
       - Task 1: Block hash calculation triggered by interrupt 11.
       - Task 2: Transaction sorting/GAS calculation triggered by interrupt 12.
       - Task 3: State update triggered by interrupt 13.
       - Task 4: Smart contract execution triggered by interrupt 14.
       - Task 5: Mining reward calculation triggered by interrupt 15.
       - Task 6: Data encryption triggered by interrupt 16.
       - Task 7: Idle task (no interrupt trigger, set to 0). */
    create_task(0, task_eth_tx_verification, NULL, PRIORITY_HIGH, 10);
    create_task(1, task_eth_block_hash,     NULL, PRIORITY_MID, 11);
    create_task(2, task_eth_tx_sort_gas,      NULL, PRIORITY_LOW, 12);
    create_task(3, task_eth_state_update,     NULL, PRIORITY_LOW, 13);
    create_task(4, task_eth_contract_execution, NULL, PRIORITY_MID, 14);
    create_task(5, task_eth_mining,         NULL, PRIORITY_LOW, 15);
    create_task(6, task_eth_data_encryption,  NULL, PRIORITY_LOW, 16);
    create_task(7, idle_task,               NULL, IDLE_TASK_PRIORITY, 0);
    
    kernel_start();
    return 0;
}
