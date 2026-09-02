//! Framing conformance against ../protocol/vectors/framing.tsv — the same
//! rows server-c and protocol/python run, so the implementations cannot
//! drift apart unnoticed. This layer is about bytes, not JSON: several ok
//! payloads are deliberately not valid JSON.

use std::path::PathBuf;

use pfui_firewall::wire::{read_frame_raw, ReadError, WireError};

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("server-rust/ sits in the repo root")
        .join("protocol/vectors")
}

struct Row {
    name: String,
    frame: Vec<u8>,
    expect: String,
    payload_hex: String,
}

fn framing_rows() -> Vec<Row> {
    let text =
        std::fs::read_to_string(vectors_dir().join("framing.tsv")).expect("framing.tsv readable");
    let mut rows = Vec::new();
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Tab-separated, never empty: "-" stands for empty or not applicable
        let cols: Vec<&str> = line.split('\t').collect();
        assert_eq!(cols.len(), 4, "malformed vector row: {line}");
        rows.push(Row {
            name: cols[0].to_string(),
            frame: if cols[1] == "-" {
                Vec::new()
            } else {
                hex::decode(cols[1]).expect("frame_hex")
            },
            expect: cols[2].to_string(),
            payload_hex: cols[3].to_string(),
        });
    }
    assert!(!rows.is_empty(), "no vectors parsed");
    rows
}

#[test]
fn framing_vectors() {
    for row in framing_rows() {
        // chunk of 3 forces every read across slice boundaries, the way a
        // small SOCKET_BUFFER delivers a frame
        for chunk in [3usize, 512] {
            let mut reader = row.frame.as_slice();
            let result = read_frame_raw(&mut reader, chunk);
            match row.expect.as_str() {
                "ok" => {
                    let payload = result
                        .unwrap_or_else(|e| panic!("{}: unexpected {e}", row.name))
                        .unwrap_or_else(|| panic!("{}: unexpected short", row.name));
                    assert_eq!(hex::encode(payload), row.payload_hex, "{}", row.name);
                }
                // No complete header arrived, so there is no message; not an error
                "short" => match result {
                    Ok(None) => {}
                    other => panic!("{}: expected short, got {other:?}", row.name),
                },
                "length" => match result {
                    Err(ReadError::Wire(WireError::BadLength(_))) => {}
                    other => panic!("{}: expected BadLength, got {other:?}", row.name),
                },
                "truncated" => match result {
                    Err(ReadError::Wire(WireError::Truncated { .. })) => {}
                    other => panic!("{}: expected Truncated, got {other:?}", row.name),
                },
                other => panic!("{}: unknown expect value {other}", row.name),
            }
        }
    }
}
