//! Payload conformance against ../protocol/vectors/messages.json.
//!
//! byte_exact frame_hex values are the Python encoder's output (json.dumps
//! spacing), so the assertion here is decode-side: our decoder must read the
//! Python daemon's exact bytes. Compressed vectors are round-trip only, per
//! PROTOCOL.md. The pylz4 fixture is a python-lz4-produced payload checked in
//! as bytes, proving lz4_flex reads the other implementation's frames.

use std::path::PathBuf;

use pfui_firewall::wire::{decode, encode, read_frame, MAX_MESSAGE};

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("server-rust/ sits in the repo root")
        .join("protocol/vectors")
}

fn message_vectors() -> serde_json::Value {
    let text = std::fs::read_to_string(vectors_dir().join("messages.json"))
        .expect("messages.json readable");
    serde_json::from_str(&text).expect("messages.json parses")
}

#[test]
fn vectors_agree_on_max_message() {
    assert_eq!(
        message_vectors()["max_message"].as_u64().unwrap(),
        MAX_MESSAGE as u64
    );
}

#[test]
fn message_vectors_decode_and_round_trip() {
    let doc = message_vectors();
    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert!(!vectors.is_empty());
    for vector in vectors {
        let name = vector["name"].as_str().unwrap();
        let msg = &vector["message"];
        let compress = vector["compress"].as_bool().unwrap();

        if vector["byte_exact"].as_bool() == Some(true) {
            // The exact bytes the Python encoder puts on the wire must decode
            // to the same message here
            let frame = hex::decode(vector["frame_hex"].as_str().unwrap()).unwrap();
            let mut reader = frame.as_slice();
            let decoded = read_frame(&mut reader, 512, compress)
                .unwrap_or_else(|e| panic!("{name}: {e}"))
                .unwrap_or_else(|| panic!("{name}: unexpected short frame"));
            assert_eq!(&decoded, msg, "{name}: decode of Python frame");
        }

        // Round-trip through our own encoder, in small chunks like recv()
        let blob = encode(msg, compress).unwrap_or_else(|e| panic!("{name}: {e}"));
        let mut reader = blob.as_slice();
        let decoded = read_frame(&mut reader, 64, compress)
            .unwrap_or_else(|e| panic!("{name}: {e}"))
            .unwrap_or_else(|| panic!("{name}: unexpected short frame"));
        assert_eq!(&decoded, msg, "{name}: round trip");
    }
}

#[test]
fn python_lz4_frame_decodes() {
    // Payload produced by python-lz4 (the client's compressor) for the
    // rr_single_a message; generated once and checked in, so a lz4_flex
    // regression against the other implementation's output fails here
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pylz4_rr_single_a.hex");
    let payload = hex::decode(
        std::fs::read_to_string(&fixture)
            .expect("fixture readable")
            .trim(),
    )
    .expect("fixture is hex");
    let decoded = decode(&payload, true).expect("python-lz4 payload decodes");
    let expected: serde_json::Value = serde_json::json!({
        "kind": "rr",
        "qname": "example.com.",
        "AF4": [{"ip": "8.8.8.8", "ttl": 3600}],
        "AF6": []
    });
    assert_eq!(decoded, expected);
}
