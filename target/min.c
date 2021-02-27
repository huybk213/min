// Copyright (c) 2014-2017 JK Energy Ltd.
//
// Use authorized under the MIT license.

#include "min.h"

#define TRANSPORT_FIFO_SIZE_FRAMES_MASK             ((uint8_t)((1U << TRANSPORT_FIFO_SIZE_FRAMES_BITS) - 1U))
#define TRANSPORT_FIFO_SIZE_FRAME_DATA_MASK         ((uint16_t)((1U << TRANSPORT_FIFO_SIZE_FRAME_DATA_BITS) - 1U))

#define MIN_GET_ID(id_control)   (id_control & (uint8_t)0x3FU)

// Number of bytes needed for a frame with a given payload length, excluding stuff bytes
// 3 header bytes, ID/control byte, length byte, seq byte, 4 byte CRC, EOF byte
#define NUMBER_OF_BYTE_NEED_FOR_A_FRAME_EX_STUFF            (11U)
#define ON_WIRE_SIZE(p)                             ((p) + NUMBER_OF_BYTE_NEED_FOR_A_FRAME_EX_STUFF)

// Special protocol bytes
enum {
    HEADER_BYTE = 0xAAU,
    STUFF_BYTE = 0x55U,
    EOF_BYTE = 0x55U,
};

// Receiving state machine
enum {
    SEARCHING_FOR_SOF,
    RECEIVING_ID_CONTROL,
    RECEIVING_SEQ,
    RECEIVING_LENGTH,
    RECEIVING_PAYLOAD,
    RECEIVING_CHECKSUM_3,
    RECEIVING_CHECKSUM_2,
    RECEIVING_CHECKSUM_1,
    RECEIVING_CHECKSUM_0,
    RECEIVING_EOF,
};

#ifdef TRANSPORT_PROTOCOL

#ifndef TRANSPORT_ACK_RETRANSMIT_TIMEOUT_MS
#define TRANSPORT_ACK_RETRANSMIT_TIMEOUT_MS         (25U)
#endif
#ifndef TRANSPORT_FRAME_RETRANSMIT_TIMEOUT_MS
#define TRANSPORT_FRAME_RETRANSMIT_TIMEOUT_MS       (50U) // Should be long enough for a whole window to be transmitted plus an ACK / NACK to get back
#endif
#ifndef TRANSPORT_MAX_WINDOW_SIZE
#define TRANSPORT_MAX_WINDOW_SIZE                   (16U)
#endif
#ifndef TRANSPORT_IDLE_TIMEOUT_MS
#define TRANSPORT_IDLE_TIMEOUT_MS                   (1000U)
#endif

enum {
    // Top bit must be set: these are for the transport protocol to use
    // 0x7f and 0x7e are reserved MIN identifiers.
    ACK = 0xFFU,
    RESET = 0xfeU,
};

// Where the payload data of the frame FIFO is stored
uint8_t payloads_ring_buffer[TRANSPORT_FIFO_MAX_FRAME_DATA];

static uint32_t now;
static void send_reset(min_context_t * self);
#endif

static void crc32_init_context(struct crc32_context *context)
{
    context->crc = 0xFFFFFFFFU;
}

static void crc32_step(struct crc32_context *context, uint8_t byte)
{
    context->crc ^= byte;
    for(uint32_t j = 0; j < 8; j++) {
        uint32_t mask = (uint32_t) -(context->crc & 1U);
        context->crc = (context->crc >> 1) ^ (0xEDB88320U & mask);
    }
}

static uint32_t crc32_finalize(struct crc32_context *context)
{
    return ~context->crc;
}

static void min_tx_byte(min_context_t * self, uint8_t byte)
{
    if (self->cb && self->cb->use_dma_frame == 0)
    {
        self->cb->tx_byte(self, byte);
    }
    else
    {
        self->tx_frame_payload_buf[self->tx_frame_payload_bytes++] = byte;
        if (self->cb && self->tx_frame_payload_bytes == MIN_MAX_PAYLOAD)
        {
            self->cb->tx_frame(self, self->tx_frame_payload_buf, MIN_MAX_PAYLOAD);
            self->tx_frame_payload_bytes = 0;
        }
    }
}

static void stuffed_tx_byte(min_context_t * self, uint8_t byte)
{
    // Transmit the byte
    min_tx_byte(self, byte);
    crc32_step(&self->tx_checksum, byte);

    // See if an additional stuff byte is needed
    if (byte == HEADER_BYTE) {
        if (--self->tx_header_byte_countdown == 0) {
            min_tx_byte(self, STUFF_BYTE);        // Stuff byte
            self->tx_header_byte_countdown = 2U;
        }
    }
    else {
        self->tx_header_byte_countdown = 2U;
    }
}

static void on_wire_bytes(min_context_t * self, uint8_t id_control, uint8_t seq, uint8_t *payload_base, uint16_t payload_offset, uint16_t payload_mask, uint8_t payload_len)
{
    uint8_t n, i;
    uint32_t checksum;

    self->tx_header_byte_countdown = 2U;
    crc32_init_context(&self->tx_checksum);

   if (self->cb && self->cb->signal)
        self->cb->signal(self, MIN_TX_BEGIN);

    // Header is 3 bytes; because unstuffed will reset receiver immediately
    min_tx_byte(self, HEADER_BYTE);
    min_tx_byte(self, HEADER_BYTE);
    min_tx_byte(self, HEADER_BYTE);

    stuffed_tx_byte(self, id_control);
    if (id_control & 0x80U) {
        // Send the sequence number if it is a transport frame
        stuffed_tx_byte(self, seq);
    }

    stuffed_tx_byte(self, payload_len);

    for(i = 0, n = payload_len; n > 0; n--, i++) {
        stuffed_tx_byte(self, payload_base[payload_offset]);
        payload_offset++;
        payload_offset &= payload_mask;
    }

    checksum = crc32_finalize(&self->tx_checksum);

    // Network order is big-endian. A decent C compiler will spot that this
    // is extracting bytes and will use efficient instructions.
    stuffed_tx_byte(self, (uint8_t)((checksum >> 24) & 0xFFU));
    stuffed_tx_byte(self, (uint8_t)((checksum >> 16) & 0xFFU));
    stuffed_tx_byte(self, (uint8_t)((checksum >> 8) & 0xFFU));
    stuffed_tx_byte(self, (uint8_t)((checksum >> 0) & 0xFFU));

    // Ensure end-of-frame doesn't contain 0xaa and confuse search for start-of-frame
    min_tx_byte(self, EOF_BYTE);

    if (self->cb && self->cb->signal)
        self->cb->signal(self, MIN_TX_END);

    if (self->cb && self->cb->use_dma_frame){
        self->tx_frame_payload_bytes = 0;
    }
}

// test only
static void stuffed_tx_output(uint8_t* output, uint32_t *size, uint32_t *crc, uint8_t *tx_header_byte_countdown, uint8_t byte)
{
    // Transmit the byte
    uint32_t tmp_size = *size;
    uint32_t tmp_crc = *crc;
    uint8_t tmp_header_cnt = *tx_header_byte_countdown;
    output[tmp_size++] = byte;

    tmp_crc ^= byte;
    for (uint32_t j = 0; j < 8; j++) {
        uint32_t mask = (uint32_t) -(tmp_crc & 1U);
        tmp_crc= (tmp_crc >> 1) ^ (0xEDB88320U & mask);
    }

    // See if an additional stuff byte is needed
    if (byte == HEADER_BYTE) {
        if (--tmp_header_cnt == 0) {
            output[tmp_size++] = STUFF_BYTE;        // Stuff byte
            tmp_header_cnt = 2U;
        }
    }
    else {
        tmp_header_cnt = 2U;
    }

    *tx_header_byte_countdown = tmp_header_cnt;
    *crc = tmp_crc;
    *size = tmp_size;
}

static void on_wire_output_buffer(uint8_t id_control, 
                                    uint8_t seq, 
                                    uint8_t *payload_base, 
                                    uint16_t payload_offset, 
                                    uint16_t payload_mask, 
                                    uint8_t payload_len,
                                    uint8_t *output,
                                    uint32_t *size)
{
    uint8_t n, i;
    uint32_t checksum;
    uint8_t tx_header_byte_countdown = 2U;
    uint32_t init_crc = 0xFFFFFFFFU;
    *size = 0;
    uint32_t tmp_size = 0;

    // Header is 3 bytes; because unstuffed will reset receiver immediately
    output[tmp_size++] = HEADER_BYTE;
    output[tmp_size++] = HEADER_BYTE;
    output[tmp_size++] = HEADER_BYTE;

    stuffed_tx_output(output, &tmp_size, &init_crc, &tx_header_byte_countdown, id_control);
    if (id_control & 0x80U) {
        // Send the sequence number if it is a transport frame
        stuffed_tx_output(output, &tmp_size, &init_crc, &tx_header_byte_countdown, seq);
    }

    stuffed_tx_output(output, &tmp_size, &init_crc, &tx_header_byte_countdown, payload_len);

    for(i = 0, n = payload_len; n > 0; n--, i++) {
        stuffed_tx_output(output, &tmp_size, &init_crc, &tx_header_byte_countdown, payload_base[payload_offset]);
        payload_offset++;
        payload_offset &= payload_mask;
    }

    checksum = ~init_crc;

    // Network order is big-endian. A decent C compiler will spot that this
    // is extracting bytes and will use efficient instructions.
    stuffed_tx_output(output, &tmp_size, &init_crc, &tx_header_byte_countdown, (uint8_t)((checksum >> 24) & 0xFFU));
    stuffed_tx_output(output, &tmp_size, &init_crc, &tx_header_byte_countdown, (uint8_t)((checksum >> 16) & 0xFFU));
    stuffed_tx_output(output, &tmp_size, &init_crc, &tx_header_byte_countdown, (uint8_t)((checksum >> 8) & 0xFFU));
    stuffed_tx_output(output, &tmp_size, &init_crc, &tx_header_byte_countdown, (uint8_t)((checksum >> 0) & 0xFFU));

    // Ensure end-of-frame doesn't contain 0xaa and confuse search for start-of-frame
    output[tmp_size++] = EOF_BYTE;
    *size = tmp_size;
}
#ifdef TRANSPORT_PROTOCOL

// Pops frame from front of queue, reclaims its ring buffer space
static void transport_fifo_pop(min_context_t * self)
{
#ifdef ASSERTION_CHECKING
    assert(self->transport_fifo.n_frames != 0);
#endif
    struct transport_frame *frame = &self->transport_fifo.frames[self->transport_fifo.head_idx];
    min_debug_print("Popping frame id=%d seq=%d\n", frame->min_id, frame->seq);

#ifdef ASSERTION_CHECKING
    assert(self->transport_fifo.n_ring_buffer_bytes >= frame->payload_len);
#endif

    self->transport_fifo.n_frames--;
    self->transport_fifo.head_idx++;
    self->transport_fifo.head_idx &= TRANSPORT_FIFO_SIZE_FRAMES_MASK;
    self->transport_fifo.n_ring_buffer_bytes -= frame->payload_len;
}

// Claim a buffer slot from the FIFO. Returns 0 if there is no space.
static struct transport_frame *transport_fifo_push(min_context_t * self, uint16_t data_size)
{
    // A frame is only queued if there aren't too many frames in the FIFO and there is space in the
    // data ring buffer.
    struct transport_frame *ret = 0;
    if (self->transport_fifo.n_frames < TRANSPORT_FIFO_MAX_FRAMES) {
        // Is there space in the ring buffer for the frame payload?
        if (self->transport_fifo.n_ring_buffer_bytes <= TRANSPORT_FIFO_MAX_FRAME_DATA - data_size) {
            self->transport_fifo.n_frames++;
            if (self->transport_fifo.n_frames > self->transport_fifo.n_frames_max) {
                // High-water mark of FIFO (for diagnostic purposes)
                self->transport_fifo.n_frames_max = self->transport_fifo.n_frames;
            }
            // Create FIFO entry
            ret = &(self->transport_fifo.frames[self->transport_fifo.tail_idx]);
            ret->payload_offset = self->transport_fifo.ring_buffer_tail_offset;

            // Claim ring buffer space
            self->transport_fifo.n_ring_buffer_bytes += data_size;
            if (self->transport_fifo.n_ring_buffer_bytes > self->transport_fifo.n_ring_buffer_bytes_max) {
                // High-water mark of ring buffer usage (for diagnostic purposes)
                self->transport_fifo.n_ring_buffer_bytes_max = self->transport_fifo.n_ring_buffer_bytes;
            }
            self->transport_fifo.ring_buffer_tail_offset += data_size;
            self->transport_fifo.ring_buffer_tail_offset &= TRANSPORT_FIFO_SIZE_FRAME_DATA_MASK;

            // Claim FIFO space
            self->transport_fifo.tail_idx++;
            self->transport_fifo.tail_idx &= TRANSPORT_FIFO_SIZE_FRAMES_MASK;
        }
        else {
            min_debug_print("No FIFO payload space: data_size=%d, n_ring_buffer_bytes=%d\n", data_size, self->transport_fifo.n_ring_buffer_bytes);
        }
    }
    else {
        min_debug_print("No FIFO frame slots\n");
    }
    return ret;
}

// Return the nth frame in the FIFO
static struct transport_frame *transport_fifo_get(min_context_t * self, uint8_t n)
{
    uint8_t idx = self->transport_fifo.head_idx;
    return &self->transport_fifo.frames[(idx + n) & TRANSPORT_FIFO_SIZE_FRAMES_MASK];
}

// Sends the given frame to the serial line
static void transport_fifo_send(min_context_t * self, struct transport_frame *frame)
{
    min_debug_print("transport_fifo_send: min_id=%d, seq=%d, payload_len=%d\n", frame->min_id, frame->seq, frame->payload_len);
    on_wire_bytes(self, frame->min_id | (uint8_t)0x80U, frame->seq, payloads_ring_buffer, frame->payload_offset, TRANSPORT_FIFO_SIZE_FRAME_DATA_MASK, frame->payload_len);
    frame->last_sent_time_ms = now;
}

// We don't queue an ACK frame - we send it straight away (if there's space to do so)
static void send_ack(min_context_t * self)
{
    // In the embedded end we don't reassemble out-of-order frames and so never ask for retransmits. Payload is
    // always the same as the sequence number.
    min_debug_print("send ACK: seq=%d\n", self->transport_fifo.rn);
    if (ON_WIRE_SIZE(0) <= min_tx_space(self)) {
        on_wire_bytes(self, ACK, self->transport_fifo.rn, &self->transport_fifo.rn, 0, 0xFFU, 1U);
        self->transport_fifo.last_sent_ack_time_ms = now;
    }
}

// We don't queue an RESET frame - we send it straight away (if there's space to do so)
static void send_reset(min_context_t * self)
{
    min_debug_print("send RESET\n");
    if (ON_WIRE_SIZE(0) <= min_tx_space(self)) {
        on_wire_bytes(self, RESET, 0, 0, 0, 0, 0);
    }
}

static void transport_fifo_reset(min_context_t * self)
{
    // Clear down the transmission FIFO queue
    self->transport_fifo.n_frames = 0;
    self->transport_fifo.head_idx = 0;
    self->transport_fifo.tail_idx = 0;
    self->transport_fifo.n_ring_buffer_bytes = 0;
    self->transport_fifo.ring_buffer_tail_offset = 0;
    self->transport_fifo.sn_max = 0;
    self->transport_fifo.sn_min = 0;
    self->transport_fifo.rn = 0;

    // Reset the timers
    self->transport_fifo.last_received_anything_ms = now;
    self->transport_fifo.last_sent_ack_time_ms = now;
    self->transport_fifo.last_received_frame_ms = 0;
}

void min_transport_reset(min_context_t * self, bool inform_other_side)
{
    if (inform_other_side) {
        // Tell the other end we have gone away
        send_reset(self);
    }

    // Throw our frames away
    transport_fifo_reset(self);
}

// Queues a MIN ID / payload frame into the outgoing FIFO
// API call.
// Returns true if the frame was queued OK.
bool min_queue_frame(min_context_t * self, uint8_t min_id, uint8_t *payload, uint8_t payload_len)
{
    struct transport_frame *frame = transport_fifo_push(self, payload_len); // Claim a FIFO slot, reserve space for payload

    // We are just queueing here: the poll() function puts the frame into the window and on to the wire
    if (frame != 0) {
        // Copy frame details into frame slot, copy payload into ring buffer
        frame->min_id = min_id & (uint8_t)0x3FU;
        frame->payload_len = payload_len;

        uint16_t payload_offset = frame->payload_offset;
        for(uint32_t i = 0; i < payload_len; i++) {
            payloads_ring_buffer[payload_offset] = payload[i];
            payload_offset++;
            payload_offset &= TRANSPORT_FIFO_SIZE_FRAME_DATA_MASK;
        }
        min_debug_print("Queued ID=%d, len=%d\n", min_id, payload_len);
        return true;
    }
    else {
        self->transport_fifo.dropped_frames++;
        return false;
    }
}

bool min_queue_has_space_for_frame(min_context_t * self, uint8_t payload_len) {
    return self->transport_fifo.n_frames < TRANSPORT_FIFO_MAX_FRAMES &&
           self->transport_fifo.n_ring_buffer_bytes <= TRANSPORT_FIFO_MAX_FRAME_DATA - payload_len;
}

// Finds the frame in the window that was sent least recently
static struct transport_frame *find_retransmit_frame(min_context_t * self)
{
    uint8_t window_size = self->transport_fifo.sn_max - self->transport_fifo.sn_min;

#ifdef ASSERTION_CHECKS
    assert(window_size > 0);
    assert(window_size <= self->transport_fifo.nframes);
#endif

    // Start with the head of the queue and call this the oldest
    struct transport_frame *oldest_frame = &self->transport_fifo.frames[self->transport_fifo.head_idx];
    uint32_t oldest_elapsed_time = now - oldest_frame->last_sent_time_ms;

    uint8_t idx = self->transport_fifo.head_idx;
    for(uint8_t i = 0; i < window_size; i++) {
        uint32_t elapsed = now - self->transport_fifo.frames[idx].last_sent_time_ms;
        if (elapsed > oldest_elapsed_time) { // Strictly older only; otherwise the earlier frame is deemed the older
            oldest_elapsed_time = elapsed;
            oldest_frame = &self->transport_fifo.frames[idx];
        }
        idx++;
        idx &= TRANSPORT_FIFO_SIZE_FRAMES_MASK;
    }

    return oldest_frame;
}
#endif // TRANSPORT_PROTOCOL

// This runs the receiving half of the transport protocol, acknowledging frames received, discarding
// duplicates received, and handling RESET requests.
static void valid_frame_received(min_context_t * self)
{
    uint8_t id_control = self->rx_frame_id_control;
    uint8_t *payload = self->rx_frame_payload_buf;
    uint8_t payload_len = self->rx_control;

#ifdef TRANSPORT_PROTOCOL
    uint8_t seq = self->rx_frame_seq;
    uint8_t num_acked;
    uint8_t num_nacked;
    uint8_t num_in_window;

    // When we receive anything we know the other end is still active and won't shut down
    self->transport_fifo.last_received_anything_ms = now;

    switch(id_control) {
        case ACK:
            // If we get an ACK then we remove all the acknowledged frames with seq < rn
            // The payload byte specifies the number of NACKed frames: how many we want retransmitted because
            // they have gone missing.
            // But we need to make sure we don't accidentally ACK too many because of a stale ACK from an old session
            num_acked = seq - self->transport_fifo.sn_min;
            num_nacked = payload[0] - seq;
            num_in_window = self->transport_fifo.sn_max - self->transport_fifo.sn_min;

            if (num_acked <= num_in_window) {
                self->transport_fifo.sn_min = seq;
#ifdef ASSERTION_CHECKING
                assert(self->transport_fifo.n_frames >= num_in_window);
                assert(num_in_window <= TRANSPORT_MAX_WINDOW_SIZE);
                assert(num_nacked <= TRANSPORT_MAX_WINDOW_SIZE);
#endif
                // Now pop off all the frames up to (but not including) rn
                // The ACK contains Rn; all frames before Rn are ACKed and can be removed from the window
                min_debug_print("Received ACK seq=%d, num_acked=%d, num_nacked=%d\n", seq, num_acked, num_nacked);
                for(uint8_t i = 0; i < num_acked; i++) {
                    transport_fifo_pop(self);
                }
                uint8_t idx = self->transport_fifo.head_idx;
                // Now retransmit the number of frames that were requested
                for(uint8_t i = 0; i < num_nacked; i++) {
                    struct transport_frame *retransmit_frame = &self->transport_fifo.frames[idx];
                    transport_fifo_send(self, retransmit_frame);
                    idx++;
                    idx &= TRANSPORT_FIFO_SIZE_FRAMES_MASK;
                }
            }
            else {
                min_debug_print("Received spurious ACK seq=%d\n", seq);
                self->transport_fifo.spurious_acks++;
            }
            break;
        case RESET:
            // If we get a RESET demand then we reset the transport protocol (empty the FIFO, reset the
            // sequence numbers, etc.)
            // We don't send anything, we just do it. The other end can send frames to see if this end is
            // alive (pings, etc.) or just wait to get application frames.
            self->transport_fifo.resets_received++;
            transport_fifo_reset(self);
            break;
        default:
            if (id_control & 0x80U) {
                // Incoming application frames

                // Reset the activity time (an idle connection will be stalled)
                self->transport_fifo.last_received_frame_ms = now;

                if (seq == self->transport_fifo.rn) {
                    // Accept this frame as matching the sequence number we were looking for

                    // Now looking for the next one in the sequence
                    self->transport_fifo.rn++;

                    // Always send an ACK back for the frame we received
                    // ACKs are short (should be about 9 microseconds to send on the wire) and
                    // this will cut the latency down.
                    // We also periodically send an ACK in case the ACK was lost, and in any case
                    // frames are re-sent.
                    send_ack(self);

                    // Now ready to pass this up to the application handlers

                    // Pass frame up to application handler to deal with
                    min_debug_print("Incoming app frame seq=%d, id=%d, payload len=%d\n", seq, MIN_GET_ID(id_control), payload_len);
                    min_msg_t msg;
                    msg.id = MIN_GET_ID(id_control);
                    msg.payload = payload;
                    msg.len = payload_len;
                    if (self->cb && self->cb->rx_callback)
                        self->cb->rx_callback(self, &msg);
                } else {
                    // Discard this frame because we aren't looking for it: it's either a dupe because it was
                    // retransmitted when our ACK didn't get through in time, or else it's further on in the
                    // sequence and others got dropped.
                    self->transport_fifo.sequence_mismatch_drop++;
                }
            }
            else {
                // Not a transport frame
                min_msg_t msg;
                msg.id = MIN_GET_ID(id_control);
                msg.payload = payload;
                msg.len = payload_len;
                if (self->cb && self->cb->rx_callback)
                    self->cb->rx_callback(self, &msg);
                
            }
            break;
    }
#else // TRANSPORT_PROTOCOL
    min_msg_t msg;
    msg.id = MIN_GET_ID(id_control);
    msg.payload = payload;
    msg.len = payload_len;
    if (self->cb && self->cb->rx_callback)
        self->cb->rx_callback(self, &msg);
#endif // TRANSPORT_PROTOCOL
}

static void rx_byte(min_context_t * self, uint8_t byte)
{
    // Regardless of state, three header bytes means "start of frame" and
    // should reset the frame buffer and be ready to receive frame data
    //
    // Two in a row in over the frame means to expect a stuff byte.
    uint32_t crc;

    if (self->rx_header_bytes_seen == 2) {
        self->rx_header_bytes_seen = 0;
        if (byte == HEADER_BYTE) {
            self->rx_frame_state = RECEIVING_ID_CONTROL;
            return;
        }
        if (byte == STUFF_BYTE) {
            /* Discard this byte; carry on receiving on the next character */
            return;
        }
        else {
            /* Something has gone wrong, give up on this frame and look for header again */
            self->rx_frame_state = SEARCHING_FOR_SOF;
            return;
        }
    }

    if (byte == HEADER_BYTE) {
        self->rx_header_bytes_seen++;
    }
    else {
        self->rx_header_bytes_seen = 0;
    }

    switch(self->rx_frame_state) {
        case SEARCHING_FOR_SOF:
            break;
        case RECEIVING_ID_CONTROL:
            self->rx_frame_id_control = byte;
            self->rx_frame_payload_bytes = 0;
            crc32_init_context(&self->rx_checksum);
            crc32_step(&self->rx_checksum, byte);
            if (byte & 0x80U) {
#ifdef TRANSPORT_PROTOCOL
                self->rx_frame_state = RECEIVING_SEQ;
#else
                // If there is no transport support compiled in then all transport frames are ignored
                self->rx_frame_state = SEARCHING_FOR_SOF;
#endif // TRANSPORT_PROTOCOL
            }
            else {
                self->rx_frame_seq = 0;
                self->rx_frame_state = RECEIVING_LENGTH;
            }
            break;
        case RECEIVING_SEQ:
            self->rx_frame_seq = byte;
            crc32_step(&self->rx_checksum, byte);
            self->rx_frame_state = RECEIVING_LENGTH;
            break;
        case RECEIVING_LENGTH:
            self->rx_frame_length = byte;
            self->rx_control = byte;
            crc32_step(&self->rx_checksum, byte);
            if (self->rx_frame_length > 0) {
                // Can reduce the RAM size by compiling limits to frame sizes
                if (self->rx_frame_length <= MIN_MAX_PAYLOAD) {
                    self->rx_frame_state = RECEIVING_PAYLOAD;
                }
                else {
                    // Frame dropped because it's longer than any frame we can buffer
                    self->rx_frame_state = SEARCHING_FOR_SOF;
                }
            }
            else {
                self->rx_frame_state = RECEIVING_CHECKSUM_3;
            }
            break;
        case RECEIVING_PAYLOAD:
            self->rx_frame_payload_buf[self->rx_frame_payload_bytes++] = byte;
            crc32_step(&self->rx_checksum, byte);
            if (--self->rx_frame_length == 0) {
                self->rx_frame_state = RECEIVING_CHECKSUM_3;
            }
            break;
        case RECEIVING_CHECKSUM_3:
            self->rx_frame_checksum = ((uint32_t)byte) << 24;
            self->rx_frame_state = RECEIVING_CHECKSUM_2;
            break;
        case RECEIVING_CHECKSUM_2:
            self->rx_frame_checksum |= ((uint32_t)byte) << 16;
            self->rx_frame_state = RECEIVING_CHECKSUM_1;
            break;
        case RECEIVING_CHECKSUM_1:
            self->rx_frame_checksum |= ((uint32_t)byte) << 8;
            self->rx_frame_state = RECEIVING_CHECKSUM_0;
            break;
        case RECEIVING_CHECKSUM_0:
            self->rx_frame_checksum |= byte;
            crc = crc32_finalize(&self->rx_checksum);
            if (self->rx_frame_checksum != crc) {
                // Frame fails the checksum and so is dropped
                self->rx_frame_state = SEARCHING_FOR_SOF;
            }
            else {
                // Checksum passes, go on to check for the end-of-frame marker
                self->rx_frame_state = RECEIVING_EOF;
            }
            break;
        case RECEIVING_EOF:
            if (byte == EOF_BYTE) {
                // Frame received OK, pass up data to handler
                valid_frame_received(self);
            }
            // else discard
            // Look for next frame */
            self->rx_frame_state = SEARCHING_FOR_SOF;
            break;
        default:
            // Should never get here but in case we do then reset to a safe state
            self->rx_frame_state = SEARCHING_FOR_SOF;
            break;
    }
}

// API call: sends received bytes into a MIN context and runs the transport timeouts
void min_rx_feed(min_context_t * self, uint8_t *buf, uint32_t buf_len)
{
    if (!self || !buf || buf_len == 0)
        return;

    if (self->cb && self->cb->get_ms && self->cb->use_timeout_method){
        self->cb->last_rx_time = self->cb->get_ms();
    }

    for(uint32_t i = 0; i < buf_len; i++) {
        rx_byte(self, buf[i]);
    }

#ifdef TRANSPORT_PROTOCOL
    uint8_t window_size;

    now = min_time_ms();

    bool remote_connected = (now - self->transport_fifo.last_received_anything_ms < TRANSPORT_IDLE_TIMEOUT_MS);
    bool remote_active = (now - self->transport_fifo.last_received_frame_ms < TRANSPORT_IDLE_TIMEOUT_MS);

    // This sends one new frame or resends one old frame
    window_size = self->transport_fifo.sn_max - self->transport_fifo.sn_min; // Window size
    if ((window_size < TRANSPORT_MAX_WINDOW_SIZE) && (self->transport_fifo.n_frames > window_size)) {
        // There are new frames we can send; but don't even bother if there's no buffer space for them
        struct transport_frame *frame = transport_fifo_get(self, window_size);
        if (ON_WIRE_SIZE(frame->payload_len) <= min_tx_space(self)) {
            frame->seq = self->transport_fifo.sn_max;
            transport_fifo_send(self, frame);

            // Move window on
            self->transport_fifo.sn_max++;
        }
    }
    else {
        // Sender cannot send new frames so resend old ones (if there's anyone there)
        if ((window_size > 0) && remote_connected) {
            // There are unacknowledged frames. Can re-send an old frame. Pick the least recently sent one.
            struct transport_frame *oldest_frame = find_retransmit_frame(self);
            if (now - oldest_frame->last_sent_time_ms >= TRANSPORT_FRAME_RETRANSMIT_TIMEOUT_MS) {
                // Resending oldest frame if there's a chance there's enough space to send it
                if (ON_WIRE_SIZE(oldest_frame->payload_len) <= min_tx_space(self)) {
                    transport_fifo_send(self, oldest_frame);
                }
            }
        }
    }

#ifndef DISABLE_TRANSPORT_ACK_RETRANSMIT
    // Periodically transmit the ACK with the rn value, unless the line has gone idle
    if (now - self->transport_fifo.last_sent_ack_time_ms > TRANSPORT_ACK_RETRANSMIT_TIMEOUT_MS) {
        if (remote_active) {
            send_ack(self);
        }
    }
#endif // DISABLE_TRANSPORT_ACK_RETRANSMIT
#endif // TRANSPORT_PROTOCOL
}

void min_init_context(min_context_t * self)
{
    if (!self)
        return;

    // Initialize context
    self->rx_header_bytes_seen = 0;
    self->rx_frame_state = SEARCHING_FOR_SOF;

#ifdef TRANSPORT_PROTOCOL
    // Counters for diagnosis purposes
    self->transport_fifo.spurious_acks = 0;
    self->transport_fifo.sequence_mismatch_drop = 0;
    self->transport_fifo.dropped_frames = 0;
    self->transport_fifo.resets_received = 0;
    self->transport_fifo.n_ring_buffer_bytes_max = 0;
    self->transport_fifo.n_frames_max = 0;
    transport_fifo_reset(self);
#endif // TRANSPORT_PROTOCOL
}



uint32_t min_tx_space(min_context_t * self)
{
    if (self->cb && self->cb->tx_space)
        return self->cb->tx_space(self);
    return 255;
}

// Sends an application MIN frame on the wire (do not put into the transport queue)
void min_send_frame(min_context_t * self, min_msg_t * msg)
{
    if (!msg || msg->len > MIN_MAX_PAYLOAD)
        return;
    
    if ((ON_WIRE_SIZE(msg->len) <= min_tx_space(self))) {
        on_wire_bytes(self, MIN_GET_ID(msg->id), 0, msg->payload, 0, 0xFFFFU, msg->len);
    }
}

void min_build_raw_frame_output(min_msg_t *input_msg, uint8_t *output, uint32_t *len)
{
    if (!input_msg || input_msg->len > MIN_MAX_PAYLOAD)
        return;

    *len = 0;

    on_wire_output_buffer(MIN_GET_ID(input_msg->id), 0, input_msg->payload, 0, 0xFFFFU, input_msg->len, output, len);
}

void min_reset_buffer_when_timeout(min_context_t *self)
{
    if (self->cb && self->cb->use_timeout_method && self->cb->get_ms)
    {
        uint32_t now = self->cb->get_ms();
        uint32_t diff;
        if (now < self->cb->last_rx_time)
        {
            diff = (0xFFFFFFFF - self->cb->last_rx_time) + now;
        }
        else
        {
            diff = now - self->cb->last_rx_time;
        }

        if (diff >= self->cb->timeout_not_seen_rx)
        {
            self->cb->last_rx_time = now;
            if (self->cb->timeout_callback && self->rx_frame_state != SEARCHING_FOR_SOF)
                self->cb->timeout_callback(self);

            self->rx_frame_state = SEARCHING_FOR_SOF;
        }
    }
}
#if 0 // test

#define SERIAL_PAYLOAD_SZ   (MIN_MAX_PAYLOAD+200)
typedef struct
{
    uint8_t buffer[SERIAL_PAYLOAD_SZ];
    uint16_t index;
} fake_serial_buffer_t;

uint8_t min_rx_buffer[MIN_MAX_PAYLOAD];
uint8_t min_tx_buffer[MIN_MAX_PAYLOAD];

fake_serial_buffer_t fake_serial_buffer;

void on_min_rx_frame(void* ctx, min_msg_t* frame)
{
    min_context_t* min_ctx = (min_context_t*)ctx;
    DebugPrint("On frame size %d, id %d, len %d, data %s, port %d\r\n", 
                frame->len,
                frame->len,
                frame->payload,
                min_ctx->port);
}

void serial_write_byte(void* ctx, uint8_t data)
{
    fake_serial_buffer.buffer[fake_serial_buffer.index++] = data;
}

void serial_write_frame(void* ctx, uint8_t* data, uint8_t len)
{
    DebugPrint("Transmit frame size %d\r\n", len);;
    while (len--)
    {
        serial_write_byte(ctx, *data);
        data++;
    }
}

void serial_signal(void* ctx, min_tx_signal_t signal)
{
    min_context_t * min_ctx = (struct min_context*) ctx;
    if (signal == MIN_TX_BEGIN)
    {
        DebugPrint("Transmit frame begin\r\n");
    }
    else
    {
        DebugPrint("Transmit frame end\r\n");
        min_rx_feed(min_ctx, min_ctx->tx_frame_payload_buf, min_ctx->tx_frame_payload_bytes);
    }
}

uint32_t serial_tx_space(void* ctx)
{
    return SERIAL_PAYLOAD_SZ - fake_serial_buffer.index;
}

struct min_context ctx;

int test()
{
    fake_serial_buffer.index = 0;

    min_frame_cb_t cb;

    cb.rx_callback = on_min_rx_frame;
    cb.tx_byte = serial_write_byte;
    cb.tx_frame = serial_write_frame;
    cb.use_dma_frame = true;
    cb.signal = serial_signal;
    cb.tx_space = serial_tx_space;
    ctx.cb = &cb;
    ctx.rx_frame_payload_buf = min_rx_buffer;
    ctx.tx_frame_payload_buf = min_tx_buffer;

    min_init_context(&ctx);
    min_msg_t min_msg;
    min_msg.id = 0x30;
    min_msg.payload = (uint8_t*)"123";
    min_msg.len = 3;
    min_send_frame(&ctx, &min_msg);
    
    return 1;
}


#endif


