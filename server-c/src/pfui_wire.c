#include "pfui_wire.h"

#include <string.h>

pfui_status
pfui_header_decode(const uint8_t *buf, size_t len, uint32_t *out_len)
{
	uint32_t declared;

	if (buf == NULL || out_len == NULL)
		return PFUI_SHORT;
	if (len < PFUI_HEADER_LEN)
		return PFUI_SHORT;

	declared = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
	    ((uint32_t)buf[2] << 8) | (uint32_t)buf[3];

	/* Checked before the caller reads or allocates the payload */
	if (declared == 0 || declared > PFUI_MAX_MESSAGE)
		return PFUI_BAD_LENGTH;

	*out_len = declared;
	return PFUI_OK;
}

pfui_status
pfui_frame_decode(const uint8_t *buf, size_t len, const uint8_t **payload,
    uint32_t *payload_len)
{
	uint32_t declared;
	pfui_status status;

	if (payload == NULL || payload_len == NULL)
		return PFUI_SHORT;

	status = pfui_header_decode(buf, len, &declared);
	if (status != PFUI_OK)
		return status;

	if (len - PFUI_HEADER_LEN < declared)
		return PFUI_TRUNCATED;

	*payload = buf + PFUI_HEADER_LEN;
	*payload_len = declared;
	return PFUI_OK;
}

pfui_status
pfui_frame_encode(uint8_t *out, size_t out_cap, const uint8_t *payload,
    uint32_t payload_len, size_t *written)
{
	if (out == NULL || payload == NULL || written == NULL)
		return PFUI_NOSPACE;
	if (payload_len == 0 || payload_len > PFUI_MAX_MESSAGE)
		return PFUI_BAD_LENGTH;
	if (out_cap < (size_t)payload_len + PFUI_HEADER_LEN)
		return PFUI_NOSPACE;

	out[0] = (uint8_t)(payload_len >> 24);
	out[1] = (uint8_t)(payload_len >> 16);
	out[2] = (uint8_t)(payload_len >> 8);
	out[3] = (uint8_t)(payload_len);
	memcpy(out + PFUI_HEADER_LEN, payload, payload_len);

	*written = (size_t)payload_len + PFUI_HEADER_LEN;
	return PFUI_OK;
}

const char *
pfui_status_str(pfui_status status)
{
	switch (status) {
	case PFUI_OK:
		return "ok";
	case PFUI_SHORT:
		return "short";
	case PFUI_BAD_LENGTH:
		return "length";
	case PFUI_TRUNCATED:
		return "truncated";
	case PFUI_NOSPACE:
		return "nospace";
	}
	return "unknown";
}
