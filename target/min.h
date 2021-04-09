// MIN Protocol v2.0.
//
// MIN is a lightweight reliable protocol for exchanging information from a microcontroller (MCU) to a host.
// It is designed to run on an 8-bit MCU but also scale up to more powerful devices. A typical use case is to
// send data from a UART on a small MCU over a UART-USB converter plugged into a PC host. A Python implementation
// of host code is provided (or this code could be compiled for a PC).
//
// MIN supports frames of 0-255 bytes (with a lower limit selectable at compile time to reduce RAM). MIN frames
// have identifier values between 0 and 63.
//
// An optional transport layer T-MIN can be compiled in. This provides sliding window reliable transmission of frames.
//
// Compile options:
//
// -  Define NO_TRANSPORT_PROTOCOL to remove the code and other overheads of dealing with transport frames. Any
//    transport frames sent from the other side are dropped.
//
// -  Define MIN_MAX_PAYLOAD if the size of the frames is to be limited. This is particularly useful with the transport
//    protocol where a deep FIFO is wanted but not for large frames.
//
// The API is as follows:
//
// -  min_init_context()
//    A MIN context is a structure allocated by the programmer that stores details of the protocol. This permits
//    the code to be reentrant and multiple serial ports to be used. The port parameter is used in a callback to
//    allow the programmer's serial port drivers to place bytes in the right port. In a typical scenario there will
//    be just one context.
//
// -  min_send_frame()
//    This sends a non-transport frame and will be dropped if the line is noisy.        
//
// -  min_queue_frame()
//    This queues a transport frame which will will be retransmitted until the other side receives it correctly.
//
// -  min_rx_feed()
//    This passes in received bytes to the context associated with the source. Note that if the transport protocol
//    is included then this must be called regularly to operate the transport state machine even if there are no
//    incoming bytes.
//
// There are several callbacks: these must be provided by the programmer and are called by the library:
//
// -  min_tx_space()
//    The programmer's serial drivers must return the number of bytes of space available in the sending buffer.
//    This helps cut down on the number of lost frames (and hence improve throughput) if a doomed attempt to transmit a
//    frame can be avoided.
//
// -  min_tx_byte()
//    The programmer's drivers must send a byte on the given port. The implementation of the serial port drivers
//    is in the domain of the programmer: they might be interrupt-based, polled, etc.
//
// -  min_application_handler()
//    This is the callback that provides a MIN frame received on a given port to the application. The programmer
//    should then deal with the frame as part of the application.
//
// -  min_time_ms()
//    This is called to obtain current time in milliseconds. This is used by the MIN transport protocol to drive
//    timeouts and retransmits.

#ifndef MIN_H
#define MIN_H

#include <stdint.h>
#include <stdbool.h>

#define NO_TRANSPORT_PROTOCOL

#ifdef ASSERTION_CHECKING
#include <assert.h>
#endif

#ifndef NO_TRANSPORT_PROTOCOL
#define TRANSPORT_PROTOCOL
#endif

#ifndef MIN_MAX_PAYLOAD
#define MIN_MAX_PAYLOAD (250U)
#endif

// Powers of two for FIFO management. Default is 16 frames in the FIFO, total of 1024 bytes for frame data
#ifndef TRANSPORT_FIFO_SIZE_FRAMES_BITS
#define TRANSPORT_FIFO_SIZE_FRAMES_BITS (4U)
#endif
#ifndef TRANSPORT_FIFO_SIZE_FRAME_DATA_BITS
#define TRANSPORT_FIFO_SIZE_FRAME_DATA_BITS (10U)
#endif

#define TRANSPORT_FIFO_MAX_FRAMES (1U << TRANSPORT_FIFO_SIZE_FRAMES_BITS)
#define TRANSPORT_FIFO_MAX_FRAME_DATA (1U << TRANSPORT_FIFO_SIZE_FRAME_DATA_BITS)

#if (MIN_MAX_PAYLOAD > 255)
#error "MIN frame payloads can be no bigger than 255 bytes"
#endif

// Indices into the frames FIFO are uint8_t and so can't have more than 256 frames in a FIFO
#if (TRANSPORT_FIFO_MAX_FRAMES > 256)
#error "Transport FIFO frames cannot exceed 256"
#endif

// Using a 16-bit offset into the frame data FIFO so it has to be addressable within 64Kbytes
#if (TRANSPORT_FIFO_MAX_FRAME_DATA > 65536)
#error "Transport FIFO data allocated cannot exceed 64Kbytes"
#endif

#define MIN_DEFAULT_CONFIG()    {   \
                                    .get_ms = systime_get_ms,   \
                                    .last_rx_time = 0x00,   \
                                    .rx_callback = (void*)0,   \
                                    .signal = (void*)0,   \
                                    .timeout_callback = (void*)0,   \
                                    .timeout_not_seen_rx = 100,   \
                                    .tx_byte = (void*)0,   \
                                    .tx_frame = (void*)0,   \
                                    .tx_space = (void*)0,   \
                                    .use_dma_frame = 0,   \
                                    .use_timeout_method = 0,   \
                                }

struct crc32_context
{
    uint32_t crc;
};

#ifdef TRANSPORT_PROTOCOL

struct transport_frame
{
    uint32_t last_sent_time_ms; // When frame was last sent (used for re-send timeouts)
    uint16_t payload_offset;    // Where in the ring buffer the payload is
    uint8_t payload_len;        // How big the payload is
    uint8_t min_id;             // ID of frame
    uint8_t seq;                // Sequence number of frame
};

struct transport_fifo
{
    struct transport_frame frames[TRANSPORT_FIFO_MAX_FRAMES];
    uint32_t last_sent_ack_time_ms;
    uint32_t last_received_anything_ms;
    uint32_t last_received_frame_ms;
    uint32_t dropped_frames; // Diagnostic counters
    uint32_t spurious_acks;
    uint32_t sequence_mismatch_drop;
    uint32_t resets_received;
    uint16_t n_ring_buffer_bytes;     // Number of bytes used in the payload ring buffer
    uint16_t n_ring_buffer_bytes_max; // Largest number of bytes ever used
    uint16_t ring_buffer_tail_offset; // Tail of the payload ring buffer
    uint8_t n_frames;                 // Number of frames in the FIFO
    uint8_t n_frames_max;             // Larger number of frames in the FIFO
    uint8_t head_idx;                 // Where frames are taken from in the FIFO
    uint8_t tail_idx;                 // Where new frames are added
    uint8_t sn_min;                   // Sequence numbers for transport protocol
    uint8_t sn_max;
    uint8_t rn;
};
#endif

typedef struct
{
    uint8_t id;
    uint8_t len;
    uint8_t *payload;
} min_msg_t;

typedef enum
{
    MIN_TX_BEGIN,
    MIN_TX_FULL,
    MIN_TX_END
} min_tx_signal_t;

typedef bool (*min_tx_byte_cb_t)(void *ctx, uint8_t data);
typedef void (*min_rx_frame_cb_t)(void *ctx, min_msg_t *frame);
typedef void (*min_rx_timeout_cb_t)(void *ctx);
typedef void (*min_tx_dma_cb_t)(void *ctx, uint8_t *msg, uint8_t len);
typedef uint32_t (*min_tx_fifo_space_avaliable_cb_t)(void *ctx);
typedef void (*min_frame_signal_cb_t)(void *ctx, min_tx_signal_t signal);
typedef uint32_t (*min_get_ms_cb_t)(void);
typedef struct
{
    min_rx_frame_cb_t rx_callback;
    min_rx_timeout_cb_t timeout_callback;
    min_tx_byte_cb_t tx_byte;
    min_tx_dma_cb_t tx_frame; // For DMA enable
    min_tx_fifo_space_avaliable_cb_t tx_space;
    min_frame_signal_cb_t signal;
    min_get_ms_cb_t get_ms;
    bool use_dma_frame;
    bool use_timeout_method;
    uint32_t timeout_not_seen_rx;
    uint32_t last_rx_time;
} min_frame_cfg_t;

typedef struct
{
#ifdef TRANSPORT_PROTOCOL
    struct transport_fifo transport_fifo; // T-MIN queue of outgoing frames
#endif
    min_frame_cfg_t *cb;
    uint8_t *rx_frame_payload_buf;    // Payload received so far
    uint8_t *tx_frame_payload_buf;    // Payload tx
    uint32_t rx_frame_checksum;       // Checksum received over the wire
    struct crc32_context rx_checksum; // Calculated checksum for receiving frame
    struct crc32_context tx_checksum; // Calculated checksum for sending frame
    uint8_t rx_header_bytes_seen;     // Countdown of header bytes to reset state
    uint8_t rx_frame_state;           // State of receiver
    uint8_t rx_frame_payload_bytes;   // Length of payload received so far
    uint8_t tx_frame_payload_bytes;   // Length of payload received so far
    uint8_t rx_frame_id_control;      // ID and control bit of frame being received
    uint8_t rx_frame_seq;             // Sequence number of frame being received
    uint8_t rx_frame_length;          // Length of frame
    uint8_t rx_control;               // Control byte
    uint8_t tx_header_byte_countdown; // Count out the header bytes
    uint8_t port;                     // Number of the port associated with the context
} min_context_t;

#ifdef TRANSPORT_PROTOCOL
// Queue a MIN frame in the transport queue
bool min_queue_frame(min_context_t *self, uint8_t min_id, uint8_t *payload, uint8_t payload_len);

// Determine if MIN has space to queue a transport frame
bool min_queue_has_space_for_frame(min_context_t *self, uint8_t payload_len);
#endif

// Send a non-transport frame MIN frame
void min_send_frame(min_context_t *self, min_msg_t *msg);

// Must be regularly called, with the received bytes since the last call.
// NB: if the transport protocol is being used then even if there are no bytes
// this call must still be made in order to drive the state machine for retransmits.
void min_rx_feed(min_context_t *self, uint8_t *buf, uint32_t buf_len);

// Reset the state machine and (optionally) tell the other side that we have done so
void min_transport_reset(min_context_t *self, bool inform_other_side);

// CALLBACK. Handle incoming MIN frame
// void min_application_handler(min_context_t * self, min_msg_t * msg);

#ifdef TRANSPORT_PROTOCOL
// CALLBACK. Must return current time in milliseconds.
// Typically a tick timer interrupt will increment a 32-bit variable every 1ms (e.g. SysTick on Cortex M ARM devices).
uint32_t min_time_ms(void);
#endif

// // CALLBACK. Send a byte on the given line.
// void min_tx_byte(struct min_context * self);

// Initialize a MIN context ready for receiving bytes from a serial link
// (Can have multiple MIN contexts)
void min_init_context(min_context_t *self);

#ifdef MIN_DEBUG_PRINTING
// Debug print
void min_debug_print(const char *msg, ...);
#else
#define min_debug_print(...)
#endif

/**
 * @brief       Estimate frame output size, suitable for DMA
 * @retval      Frame output size 
 */
uint32_t min_estimate_frame_output_size(min_msg_t *input_msg);

// Test only
/**
 * @brief       Build raw frame output
 * @param[in]   input_msg Inout message
 * @param[out]  output Output buffer hold data
 * @param[out]  len Output buffer len
 */
void min_build_raw_frame_output(min_msg_t *input_msg, uint8_t *output, uint32_t *len);

/**
 * @brief       Reset frame when timeout no received UART interrupt
 */
void min_reset_buffer_when_timeout(min_context_t *self);

#endif //MIN_H
