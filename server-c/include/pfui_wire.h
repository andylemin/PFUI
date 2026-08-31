/*
 * PFUI wire framing. See ../../protocol/PROTOCOL.md for the normative spec and
 * ../../protocol/vectors/framing.tsv for the shared conformance vectors.
 *
 * This is the framing layer only: it hands back the payload as opaque bytes and
 * takes no view on JSON or lz4.
 */

#ifndef PFUI_WIRE_H
#define PFUI_WIRE_H

#include <stddef.h>
#include <stdint.h>

#define PFUI_HEADER_LEN 4u
#define PFUI_MAX_MESSAGE (1u << 20) /* 1 MiB, must match the Python side */

typedef enum {
	PFUI_OK = 0,
	PFUI_SHORT,	/* no complete header yet; peer closed or more to come */
	PFUI_BAD_LENGTH,/* declared length is zero or above PFUI_MAX_MESSAGE */
	PFUI_TRUNCATED,	/* header is complete but the payload is not */
	PFUI_NOSPACE	/* caller's buffer cannot hold the frame */
} pfui_status;

/*
 * Read the declared payload length from a 4-byte big-endian header. Rejects the
 * length before a caller has any reason to allocate for it.
 */
pfui_status pfui_header_decode(const uint8_t *buf, size_t len, uint32_t *out_len);

/*
 * Point *payload at the payload inside a complete frame. No copy is made, so
 * *payload remains valid only as long as buf does.
 */
pfui_status pfui_frame_decode(const uint8_t *buf, size_t len,
    const uint8_t **payload, uint32_t *payload_len);

/*
 * Write header + payload into out. Returns the total bytes written via *written.
 */
pfui_status pfui_frame_encode(uint8_t *out, size_t out_cap, const uint8_t *payload,
    uint32_t payload_len, size_t *written);

const char *pfui_status_str(pfui_status status);

#endif /* PFUI_WIRE_H */
