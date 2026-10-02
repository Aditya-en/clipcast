use clipcast::tcp::*;
use clipcast::proto::*;
fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
#[test]
fn print_vectors() {
    let key: [u8;32] = (0u8..32).collect::<Vec<_>>().try_into().unwrap();
    let client_device_id: [u8;16] = (0x10u8..0x20).collect::<Vec<_>>().try_into().unwrap();
    let transfer_id: [u8;16] = (0xa0u8..0xb0).collect::<Vec<_>>().try_into().unwrap();
    let client_nonce: [u8;32] = (0xc0u8..0xe0).collect::<Vec<_>>().try_into().unwrap();
    let payload = b"Hello, TCP!";
    let sha = sha256(payload);
    let announce = AnnouncePayload { inner_content_type: INNER_TEXT, transfer_id, total_len: payload.len() as u64, sha256: sha, tcp_port: 47475 };
    println!("ANNOUNCE_PAYLOAD={}", hex(&encode_announce(&announce)));
    let h = RequestHeader { client_device_id, transfer_id, client_nonce };
    let header_bytes = encode_request_header(&h);
    println!("HEADER={}", hex(&header_bytes));
    let sk = derive_session_key(&key, &client_nonce, &transfer_id).unwrap();
    println!("SESSION_KEY={}", hex(&sk));
    println!("HANDSHAKE_TAG={}", hex(&seal_handshake(&sk, &header_bytes)));
    let ct = seal_frame(&sk, &header_bytes, DIR_SERVER_TO_CLIENT, 0, FLAG_FINAL, payload);
    let mut frame = (ct.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&ct);
    println!("FRAME0_FINAL={}", hex(&frame));
    let ct1 = seal_frame(&sk, &header_bytes, DIR_SERVER_TO_CLIENT, 1, FLAG_FINAL, b"");
    let mut frame1 = (ct1.len() as u32).to_be_bytes().to_vec();
    frame1.extend_from_slice(&ct1);
    println!("FRAME1_EMPTY_FINAL={}", hex(&frame1));
    println!("SHA={}", hex(&sha));
}
