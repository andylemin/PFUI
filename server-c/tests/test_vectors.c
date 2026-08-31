/*
 * Runs the shared framing vectors from ../../protocol/vectors/framing.tsv.
 *
 * The Python implementation runs the same file, so a divergence between the two
 * fails here or in protocol/python/tests/test_vectors.py, not in production.
 */

#include "pfui_wire.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_HEX (2 * (PFUI_MAX_MESSAGE + PFUI_HEADER_LEN) + 1)

static int failures;
static int checks;

static size_t
unhex(const char *hex, uint8_t *out, size_t out_cap)
{
	size_t len = strlen(hex), i;

	if (strcmp(hex, "-") == 0 || len % 2 != 0 || len / 2 > out_cap)
		return 0;
	for (i = 0; i < len / 2; i++) {
		unsigned int byte;
		if (sscanf(hex + 2 * i, "%2x", &byte) != 1)
			return 0;
		out[i] = (uint8_t)byte;
	}
	return len / 2;
}

static void
check(const char *name, int condition, const char *detail)
{
	checks++;
	if (!condition) {
		failures++;
		fprintf(stderr, "FAIL %s: %s\n", name, detail);
	}
}

static void
run_vector(const char *name, const char *frame_hex, const char *expect,
    const char *payload_hex)
{
	static uint8_t frame[PFUI_MAX_MESSAGE + PFUI_HEADER_LEN];
	static uint8_t want[PFUI_MAX_MESSAGE];
	const uint8_t *payload = NULL;
	uint32_t payload_len = 0;
	size_t frame_len, want_len;
	pfui_status status;

	frame_len = strcmp(frame_hex, "-") == 0 ? 0 : unhex(frame_hex, frame, sizeof(frame));
	status = pfui_frame_decode(frame, frame_len, &payload, &payload_len);

	if (strcmp(expect, "ok") == 0) {
		check(name, status == PFUI_OK, pfui_status_str(status));
		if (status != PFUI_OK)
			return;
		want_len = unhex(payload_hex, want, sizeof(want));
		check(name, payload_len == want_len, "payload length mismatch");
		check(name, payload_len == want_len &&
		    memcmp(payload, want, want_len) == 0, "payload bytes mismatch");

		/* Re-encoding the payload must reproduce the frame byte for byte */
		{
			static uint8_t round[PFUI_MAX_MESSAGE + PFUI_HEADER_LEN];
			size_t written = 0;
			status = pfui_frame_encode(round, sizeof(round), payload,
			    payload_len, &written);
			check(name, status == PFUI_OK, "re-encode failed");
			check(name, written == frame_len &&
			    memcmp(round, frame, frame_len) == 0, "round trip differs");
		}
	} else {
		check(name, strcmp(pfui_status_str(status), expect) == 0,
		    pfui_status_str(status));
	}
}

int
main(int argc, char **argv)
{
	const char *path = argc > 1 ? argv[1] : "../protocol/vectors/framing.tsv";
	char line[MAX_HEX + 256];
	FILE *fp;

	fp = fopen(path, "r");
	if (fp == NULL) {
		fprintf(stderr, "cannot open vectors: %s\n", path);
		return 2;
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		char *name, *frame_hex, *expect, *payload_hex, *newline;

		if (line[0] == '#' || line[0] == '\n')
			continue;
		newline = strchr(line, '\n');
		if (newline != NULL)
			*newline = '\0';

		name = strtok(line, "\t");
		frame_hex = strtok(NULL, "\t");
		expect = strtok(NULL, "\t");
		payload_hex = strtok(NULL, "\t");
		if (name == NULL || frame_hex == NULL || expect == NULL ||
		    payload_hex == NULL) {
			fprintf(stderr, "malformed vector line\n");
			failures++;
			continue;
		}
		if (frame_hex[0] == '\0')
			frame_hex = "-";
		run_vector(name, frame_hex, expect, payload_hex);
	}
	fclose(fp);

	printf("%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
