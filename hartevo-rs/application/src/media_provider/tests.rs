use super::*;

#[test]
fn media_connection_and_download_reject_credential_leaks_and_origin_changes() {
    for base in [
        "http://example.com",
        "https://secret@example.com",
        "https://example.com?token=x",
        "https://example.com/#x",
    ] {
        assert!(MediaConnection::new(base, "TEST_MEDIA_KEY").is_err());
    }
    for key in ["", "1KEY", "secret-key", "A\nB"] {
        assert!(MediaConnection::new("https://example.com", key).is_err());
    }
    let connection = MediaConnection::new("https://example.com/v1/", "TEST_MEDIA_KEY").unwrap();
    assert_eq!(
        connection.digest(),
        MediaConnection::new("https://example.com", "TEST_MEDIA_KEY")
            .unwrap()
            .digest()
    );
    assert_ne!(
        connection.digest(),
        MediaConnection::new("https://example.com", "OTHER_MEDIA_KEY")
            .unwrap()
            .digest()
    );
    assert!(!format!("{connection:?}").contains("example.com"));
    let transport = NativeMediaTransport { connection };
    assert_eq!(
        transport.asset_url("/media/asset.mp4").unwrap().as_str(),
        "https://example.com/media/asset.mp4"
    );
    assert!(
        transport
            .asset_url("https://example.com/media/asset.mp4?signature=opaque")
            .is_ok()
    );
    for asset in [
        "http://example.com/a",
        "//attacker.example/a",
        "https://example.com.attacker.example/a",
        "https://example.com:444/a",
        "https://user@example.com/a",
        "data:video/mp4,abc",
        "https://example.com/a#x",
    ] {
        assert!(transport.asset_url(asset).is_err());
    }
}

#[test]
fn media_image_checks_decode_bytes_and_requested_dimensions() {
    let image = image::DynamicImage::ImageRgb8(image::RgbImage::new(1024, 1024));
    let mut output = Cursor::new(Vec::new());
    image.write_to(&mut output, ImageFormat::Png).unwrap();
    let bytes = output.into_inner();
    let metadata = inspect_media(&bytes, MediaKind::Image).unwrap();
    assert!(metadata.meets_requested_format(MediaKind::Image));
    assert!(metadata.validate_bytes(&bytes).is_ok());
    assert!(metadata.validate_bytes(&bytes[..bytes.len() - 1]).is_err());
    assert!(inspect_media(&bytes[..24], MediaKind::Image).is_err());
    assert!(inspect_media(b"<svg><script>bad</script></svg>", MediaKind::Image).is_err());
    assert!(inspect_media(&bytes, MediaKind::Video).is_err());
}

fn atom(kind: [u8; 4], body: &[u8]) -> Vec<u8> {
    let mut bytes = u32::try_from(body.len() + 8)
        .unwrap()
        .to_be_bytes()
        .to_vec();
    bytes.extend(kind);
    bytes.extend(body);
    bytes
}

// Container fixtures verify parsing only; they deliberately contain no codec
// frames. Actual playback is verified separately in the native desktop window.
fn mp4(duration: u32, audio_first: bool) -> Vec<u8> {
    let mut mvhd = vec![0; 20];
    mvhd[12..16].copy_from_slice(&1000u32.to_be_bytes());
    mvhd[16..20].copy_from_slice(&duration.to_be_bytes());
    let mut tkhd = vec![0; 84];
    tkhd[76..80].copy_from_slice(&(480u32 << 16).to_be_bytes());
    tkhd[80..84].copy_from_slice(&(480u32 << 16).to_be_bytes());
    let mut hdlr = vec![0; 12];
    hdlr[8..12].copy_from_slice(b"vide");
    let mut track = atom(*b"tkhd", &tkhd);
    track.extend(atom(*b"mdia", &atom(*b"hdlr", &hdlr)));
    let mut movie = atom(*b"mvhd", &mvhd);
    if audio_first {
        hdlr[8..12].copy_from_slice(b"soun");
        movie.extend(atom(*b"trak", &atom(*b"mdia", &atom(*b"hdlr", &hdlr))));
    }
    movie.extend(atom(*b"trak", &track));
    let mut file = atom(*b"ftyp", b"isom");
    file.extend(atom(*b"mdat", &[1]));
    file.extend(atom(*b"moov", &movie));
    file
}

#[test]
fn media_video_reads_video_track_after_audio_and_checks_duration_and_bounds() {
    let bytes = mp4(3042, true);
    let metadata = inspect_media(&bytes, MediaKind::Video).unwrap();
    assert_eq!(
        (metadata.width, metadata.height, metadata.duration_millis),
        (480, 480, Some(3042))
    );
    assert!(metadata.meets_requested_format(MediaKind::Video));
    assert!(
        !inspect_media(&mp4(6000, false), MediaKind::Video)
            .unwrap()
            .meets_requested_format(MediaKind::Video)
    );
    assert!(inspect_media(&bytes[..bytes.len() - 1], MediaKind::Video).is_err());
    let mut malformed = bytes;
    malformed[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(inspect_media(&malformed, MediaKind::Video).is_err());
    assert!(mp4_boxes(&atom(*b"free", &[]).repeat(4097)).is_none());
}
