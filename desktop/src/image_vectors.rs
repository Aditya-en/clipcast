//! Cross-implementation test vectors for image sync.
//!
//! The canonical values live in `docs/test-vectors-image.md`; this module
//! rebuilds every blob from the documented fixed inputs and asserts
//! byte-exact equality, so any wire-format drift breaks the build. The
//! Android client implements the same vectors from the same document.

#[cfg(test)]
mod tests {
    use crate::{crypto, proto, tcp};

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The deterministic 1x1 PNG from the vectors document (69 bytes).
    fn test_image() -> Vec<u8> {
        unhex(
            "89504e470d0a1a0a0000000d4948445200000001000000010802000000907753de0000000c4944415408d763f8cfc00000000300010005fed40000000049454e44ae426082",
        )
    }

    fn key() -> [u8; 32] {
        std::array::from_fn(|i| i as u8)
    }

    struct VectorInputs {
        device_id: [u8; 16],
        udp_nonce: [u8; 12],
        transfer_id: [u8; 16],
        tcp_client_id: [u8; 16],
        tcp_client_nonce: [u8; 32],
    }

    fn inputs() -> VectorInputs {
        VectorInputs {
            device_id: std::array::from_fn(|i| 0x20 + i as u8),
            udp_nonce: std::array::from_fn(|i| 0xe0 + i as u8),
            transfer_id: std::array::from_fn(|i| 0xb0 + i as u8),
            tcp_client_id: std::array::from_fn(|i| 0x30 + i as u8),
            tcp_client_nonce: std::array::from_fn(|i| 0xd0 + i as u8),
        }
    }

    const SHA_HEX: &str = "167a2b4b202a5c05e6fb5ac9f45b52d7bc5c5f8a0f94679362fd8a86912ee397";
    const ANNOUNCE_HEX: &str = "02b0b1b2b3b4b5b6b7b8b9babbbcbdbebf0000000000000045167a2b4b202a5c05e6fb5ac9f45b52d7bc5c5f8a0f94679362fd8a86912ee397b97309696d6167652f706e67";
    const BODY_HEX: &str = "000000003ade68b10000018bcfe56800800000004502b0b1b2b3b4b5b6b7b8b9babbbcbdbebf0000000000000045167a2b4b202a5c05e6fb5ac9f45b52d7bc5c5f8a0f94679362fd8a86912ee397b97309696d6167652f706e67";
    const HEADER_HEX: &str = "43434c500101202122232425262728292a2b2c2d2e2fe0e1e2e3e4e5e6e7e8e9eaeb";
    const DATAGRAM_HEX: &str = "43434c500101202122232425262728292a2b2c2d2e2fe0e1e2e3e4e5e6e7e8e9eaeb34c2c983cf1ee29ac0037fc591f9908345a53be7bb867da92e32dec8ba869033e9595d4fc71af86031cea5b03b1f15fb4f19f06d41e6fd6b99704dfca0603671abb8e643ad67538b64042af5a96af97411cd8a5b9b52c7c208b1318b2f099155055c7ab27e12c9bb2a59";
    const REQ_HEX: &str = "43434c540101303132333435363738393a3b3c3d3e3fb0b1b2b3b4b5b6b7b8b9babbbcbdbebfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef";
    const SKEY_HEX: &str = "bbc21c6ef3429aee544715ec07e690b5aa507e443d6491a431b260a8b68b25a4";
    const TAG_HEX: &str = "8d44bb79dc2471ab93c9b0745a6cc9da";
    const FRAME_HEX: &str = "000000565db649ebbc31786690ba9dc1eb582893d667c4f8859b069f707e41a4b770bea27eefb9b96a9e7cb0ca8275eab6e5fe99a5287365e2c0594edf3d80a073217af6984184dcb2ae9096d4032c0b08c3971e012d77b3be6b";

    #[test]
    fn image_vectors_match_documented_hex() {
        let img = test_image();
        assert_eq!(img.len(), 69);
        let v = inputs();
        let (device_id, nonce, transfer_id, client_id, client_nonce) = (
            v.device_id,
            v.udp_nonce,
            v.transfer_id,
            v.tcp_client_id,
            v.tcp_client_nonce,
        );

        // 1. Image hash.
        assert_eq!(hex(&tcp::sha256(&img)), SHA_HEX);

        // 2. Image announce payload, then decode round-trip.
        let payload = proto::encode_image_announce(&proto::ImageAnnouncePayload {
            transfer_id,
            total_len: img.len() as u64,
            sha256: tcp::sha256(&img),
            tcp_port: 47475,
            mime_type: "image/png".to_string(),
        });
        assert_eq!(hex(&payload), ANNOUNCE_HEX);
        let decoded = proto::decode_image_announce(&unhex(ANNOUNCE_HEX)).unwrap();
        assert_eq!(decoded.mime_type, "image/png");
        assert_eq!(decoded.total_len, 69);
        assert_eq!(decoded.tcp_port, 47475);

        // 3. Body plaintext and header.
        let body = proto::Body {
            lamport: 987654321,
            timestamp_ms: 1700000000000,
            content_type: proto::CONTENT_ANNOUNCE,
            payload: unhex(ANNOUNCE_HEX),
        };
        assert_eq!(hex(&proto::encode_body(&body)), BODY_HEX);
        let header = proto::Header {
            version: 1,
            msg_type: proto::MSG_CLIP_UPDATE,
            device_id,
            nonce,
        };
        assert_eq!(hex(&proto::encode_header(&header)), HEADER_HEX);

        // 4. Sealed datagram, then open + parse (the receiver path).
        let datagram = crypto::seal(&key(), &header, &body);
        assert_eq!(hex(&datagram), DATAGRAM_HEX);
        let (opened_header, opened_body) = crypto::open(&key(), &unhex(DATAGRAM_HEX)).unwrap();
        assert_eq!(opened_header.device_id, device_id);
        assert_eq!(opened_body.content_type, proto::CONTENT_ANNOUNCE);
        assert_eq!(hex(&opened_body.payload), ANNOUNCE_HEX);

        // 5. TCP request header + session key + handshake tag.
        let req = tcp::RequestHeader {
            client_device_id: client_id,
            transfer_id,
            client_nonce,
        };
        let req_bytes = tcp::encode_request_header(&req);
        assert_eq!(hex(&req_bytes), REQ_HEX);
        let skey = tcp::derive_session_key(&key(), &client_nonce, &transfer_id).unwrap();
        assert_eq!(hex(&skey), SKEY_HEX);
        assert_eq!(hex(&tcp::seal_handshake(&skey, &req_bytes)), TAG_HEX);
        tcp::verify_handshake(&skey, &req_bytes, &unhex(TAG_HEX)).unwrap();

        // 6. Image data frame: open, check FINAL + bytes + hash (receiver path).
        let frame = unhex(FRAME_HEX);
        let len = u32::from_be_bytes(frame[0..4].try_into().unwrap()) as usize;
        assert_eq!(len, frame.len() - 4);
        let (flags, data) =
            tcp::open_frame(&skey, &req_bytes, tcp::DIR_SERVER_TO_CLIENT, 0, &frame[4..]).unwrap();
        assert_eq!(flags, tcp::FLAG_FINAL);
        assert_eq!(data, img);
        tcp::verify_content(
            &data,
            img.len() as u64,
            &tcp::sha256(&img),
            proto::INNER_IMAGE,
        )
        .unwrap();
        // And the locally sealed frame matches the documented bytes.
        let ct = tcp::seal_frame(
            &skey,
            &req_bytes,
            tcp::DIR_SERVER_TO_CLIENT,
            0,
            tcp::FLAG_FINAL,
            &img,
        );
        let mut local = (ct.len() as u32).to_be_bytes().to_vec();
        local.extend_from_slice(&ct);
        assert_eq!(hex(&local), FRAME_HEX);
    }
}
