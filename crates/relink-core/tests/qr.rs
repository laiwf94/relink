//! The QR encoder against a second, independent implementation (Nayuki's
//! qrcodegen), module for module, at every version, level and mask; and the
//! SVG and PNG writers read back into modules.

use proptest::prelude::*;
use qrcodegen::{Mask, QrCodeEcc, QrSegment, Version};
use relink_core::qr::{self, EcLevel, QrCode, Render, Rgb};

fn reference(data: &[u8], ec: EcLevel, mask: Option<u8>) -> qrcodegen::QrCode {
    let ecc = match ec {
        EcLevel::Low => QrCodeEcc::Low,
        EcLevel::Medium => QrCodeEcc::Medium,
        EcLevel::Quartile => QrCodeEcc::Quartile,
        EcLevel::High => QrCodeEcc::High,
    };
    qrcodegen::QrCode::encode_segments_advanced(
        &[QrSegment::make_bytes(data)],
        ecc,
        Version::new(1),
        Version::new(40),
        mask.map(Mask::new),
        false,
    )
    .expect("fits")
}

fn assert_same(data: &[u8], ec: EcLevel, mask: Option<u8>) {
    let ours = match mask {
        Some(m) => QrCode::encode_with_mask(data, ec, m),
        None => QrCode::encode(data, ec),
    }
    .expect("fits");
    let theirs = reference(data, ec, mask);
    let ctx = format!("{} bytes at {ec}, mask {mask:?}", data.len());
    assert_eq!(ours.version(), theirs.version().value(), "version, {ctx}");
    assert_eq!(ours.mask(), theirs.mask().value(), "mask, {ctx}");
    assert_eq!(ours.size(), theirs.size() as usize, "{ctx}");
    for y in 0..ours.size() {
        for x in 0..ours.size() {
            assert_eq!(
                ours.is_dark(x, y),
                theirs.get_module(x as i32, y as i32),
                "module ({x}, {y}), {ctx}"
            );
        }
    }
}

/// Reproducible bytes that are not all alike.
fn bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut s = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s >> 24) as u8
        })
        .collect()
}

#[test]
fn every_version_and_level_matches_the_reference() {
    for ec in EcLevel::ALL {
        for v in qr::MIN_VERSION..=qr::MAX_VERSION {
            let full = qr::byte_capacity(v, ec);
            let least = if v == 1 {
                0
            } else {
                qr::byte_capacity(v - 1, ec) + 1
            };
            for len in [least, full] {
                let data = bytes(len, v as u64 * 4 + ec as u64);
                assert_same(&data, ec, None);
                let q = QrCode::encode(&data, ec).unwrap();
                assert_eq!(q.version(), v);
                assert_eq!(q.size(), qr::side(v));
            }
        }
    }
}

#[test]
fn every_mask_matches_the_reference() {
    for ec in EcLevel::ALL {
        for v in [1, 2, 6, 7, 14, 32, 40] {
            let data = bytes(qr::byte_capacity(v, ec), v as u64);
            for mask in 0..8 {
                assert_same(&data, ec, Some(mask));
            }
        }
    }
}

#[test]
fn links_match_the_reference() {
    for url in [
        "https://rl.example/a",
        "https://rl.example/Xy7_q-2",
        "https://go.example.com/spring-sale?utm_source=poster&utm_medium=print",
        "HTTPS://RL.EXAMPLE/ABC",
        "https://例え.テスト/ünïcode",
    ] {
        for ec in EcLevel::ALL {
            assert_same(url.as_bytes(), ec, None);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn random_data_matches_the_reference(
        data in prop::collection::vec(any::<u8>(), 0..400),
        level in 0usize..4,
    ) {
        assert_same(&data, EcLevel::ALL[level], None);
    }
}

/// A pinned symbol, so a change in output shows here even without the
/// reference. Version 2-M, mask 2 (checked against qrcodegen above).
#[test]
fn known_symbol() {
    let q = QrCode::encode(b"https://rl.example/Xy7_q-2", EcLevel::Medium).unwrap();
    let expected = "\
#######....##...#.#######
#.....#....#..##..#.....#
#.###.#.#####.###.#.###.#
#.###.#.###..#....#.###.#
#.###.#.#....#..#.#.###.#
#.....#.##...###..#.....#
#######.#.#.#.#.#.#######
........#.#.#.##.........
#.#####..#.#..###.#####..
###..#.#.#.####.#..#...#.
.###..#...###..###..##.##
..#....#.##.#..##.#.....#
#.#.###.##..###...###.###
##..##....#.###.#..#.#.#.
#....#####..#..###.###.##
#..###..#####.##...##...#
#.#.####..#..#.######.#..
........##.##.###...##...
#######..#...##.#.#.#.###
#.....#.##....#.#...##...
#.###.#.#.###.#######.#..
#.###.#.#.######.##.#####
#.###.#.#....####....##.#
#.....#.....#.#.######..#
#######.##...##..########
";
    let drawn: String = (0..q.size())
        .map(|y| {
            let mut row: String = (0..q.size())
                .map(|x| if q.is_dark(x, y) { '#' } else { '.' })
                .collect();
            row.push('\n');
            row
        })
        .collect();
    assert_eq!((q.version(), q.mask()), (2, 2), "{drawn}");
    assert_eq!(drawn, expected);
    assert!(format!("{q:?}").ends_with(expected));
}

// PNG, read back with code that shares nothing with the writer.

fn crc32_bitwise(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in bytes {
        crc ^= b as u32;
        for _ in 0..8 {
            let low = crc & 1;
            crc >>= 1;
            if low == 1 {
                crc ^= 0xEDB8_8320;
            }
        }
    }
    !crc
}

fn adler32_plain(bytes: &[u8]) -> u32 {
    let (mut a, mut b) = (1u64, 0u64);
    for &x in bytes {
        a = (a + x as u64) % 65_521;
        b = (b + a) % 65_521;
    }
    ((b << 16) | a) as u32
}

struct Png {
    width: usize,
    palette: Vec<[u8; 3]>,
    /// One palette index per pixel, row-major.
    pixels: Vec<u8>,
}

fn read_png(png: &[u8]) -> Png {
    assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
    let mut at = 8;
    let mut chunks = Vec::new();
    while at < png.len() {
        let len = u32::from_be_bytes(png[at..at + 4].try_into().unwrap()) as usize;
        let kind = &png[at + 4..at + 8];
        let data = &png[at + 8..at + 8 + len];
        let crc = u32::from_be_bytes(png[at + 8 + len..at + 12 + len].try_into().unwrap());
        assert_eq!(
            crc,
            crc32_bitwise(&png[at + 4..at + 8 + len]),
            "CRC of {kind:?}"
        );
        chunks.push((kind.to_vec(), data.to_vec()));
        at += 12 + len;
    }
    assert_eq!(at, png.len());
    let kinds: Vec<&[u8]> = chunks.iter().map(|(k, _)| k.as_slice()).collect();
    assert_eq!(kinds, [&b"IHDR"[..], b"PLTE", b"IDAT", b"IEND"]);
    let ihdr = &chunks[0].1;
    let width = u32::from_be_bytes(ihdr[0..4].try_into().unwrap()) as usize;
    let height = u32::from_be_bytes(ihdr[4..8].try_into().unwrap()) as usize;
    assert_eq!(width, height);
    assert_eq!(&ihdr[8..], &[1, 3, 0, 0, 0]);
    let palette = chunks[1].1.chunks(3).map(|c| [c[0], c[1], c[2]]).collect();

    // zlib: header, stored blocks only, Adler-32.
    let z = &chunks[2].1;
    assert_eq!((z[0] as u32 * 256 + z[1] as u32) % 31, 0);
    assert_eq!(z[0] & 0x0F, 8);
    let mut raw = Vec::new();
    let mut i = 2;
    loop {
        let header = z[i];
        assert_eq!(header & 0b110, 0, "stored blocks only");
        let len = u16::from_le_bytes([z[i + 1], z[i + 2]]);
        let nlen = u16::from_le_bytes([z[i + 3], z[i + 4]]);
        assert_eq!(len, !nlen);
        raw.extend_from_slice(&z[i + 5..i + 5 + len as usize]);
        i += 5 + len as usize;
        if header & 1 == 1 {
            break;
        }
    }
    assert_eq!(
        u32::from_be_bytes(z[i..i + 4].try_into().unwrap()),
        adler32_plain(&raw)
    );
    assert_eq!(i + 4, z.len());

    let stride = 1 + width.div_ceil(8);
    assert_eq!(raw.len(), stride * height);
    let mut pixels = Vec::with_capacity(width * height);
    for row in raw.chunks(stride) {
        assert_eq!(row[0], 0, "filter type 0");
        for x in 0..width {
            pixels.push((row[1 + x / 8] >> (7 - x % 8)) & 1);
        }
        // Padding bits after the last pixel are zero.
        for x in width..(stride - 1) * 8 {
            assert_eq!((row[1 + x / 8] >> (7 - x % 8)) & 1, 0);
        }
    }
    Png {
        width,
        palette,
        pixels,
    }
}

fn check_png(q: &QrCode, render: Render) {
    let png = read_png(&q.to_png(&render).unwrap());
    let b = render.border as usize;
    let s = render.scale as usize;
    assert_eq!(png.width, (q.size() + 2 * b) * s);
    let Rgb(lr, lg, lb) = render.light;
    let Rgb(dr, dg, db) = render.dark;
    assert_eq!(png.palette, [[lr, lg, lb], [dr, dg, db]]);
    for py in 0..png.width {
        for px in 0..png.width {
            let (mx, my) = (px / s, py / s);
            let dark = mx >= b && my >= b && q.is_dark(mx - b, my - b);
            assert_eq!(
                png.pixels[py * png.width + px],
                dark as u8,
                "pixel ({px}, {py})"
            );
        }
    }
}

#[test]
fn png_reads_back_as_the_symbol() {
    let small = QrCode::encode(b"https://rl.example/a", EcLevel::Medium).unwrap();
    for (border, scale) in [(0, 1), (4, 1), (4, 3), (1, 7), (4, 8), (16, 32)] {
        check_png(
            &small,
            Render {
                border,
                scale,
                ..Render::default()
            },
        );
    }
    let colours = Render {
        dark: "#1a2b3c".parse().unwrap(),
        light: "#fed".parse().unwrap(),
        ..Render::default()
    };
    check_png(&small, colours);

    // Version 40 at the largest scale: about 5.6 MB in 86 stored blocks.
    let big = QrCode::encode(&bytes(2953, 1), EcLevel::Low).unwrap();
    assert_eq!(big.version(), 40);
    let largest = Render {
        border: qr::MAX_BORDER,
        scale: qr::MAX_SCALE,
        ..Render::default()
    };
    check_png(&big, largest);
    let len = big.to_png(&largest).unwrap().len();
    assert!(len < 6_000_000, "{len}");
}

// SVG, read back from its path.

fn read_svg(svg: &str) -> (usize, Vec<bool>, String, String) {
    let attr = |name: &str, from: &str| -> String {
        let start = from.find(&format!("{name}=\"")).unwrap() + name.len() + 2;
        from[start..start + from[start..].find('"').unwrap()].to_string()
    };
    let view = attr("viewBox", svg);
    let n: usize = view.rsplit(' ').next().unwrap().parse().unwrap();
    assert_eq!(view, format!("0 0 {n} {n}"));
    let rect = &svg[svg.find("<rect").unwrap()..];
    let light = attr("fill", rect);
    let path = &svg[svg.find("<path").unwrap()..];
    let dark = attr("fill", path);
    let d = attr("d", path);
    let mut grid = vec![false; n * n];
    for cmd in d.split('z').filter(|c| !c.is_empty()) {
        let rest = cmd.strip_prefix('M').unwrap();
        let (xy, rest) = rest.split_once('h').unwrap();
        let (x, y) = xy.split_once(',').unwrap();
        let (run, back) = rest.split_once("v1h-").unwrap();
        assert_eq!(run, back);
        let (x, y, run): (usize, usize, usize) =
            (x.parse().unwrap(), y.parse().unwrap(), run.parse().unwrap());
        assert!(run > 0);
        for i in x..x + run {
            assert!(!grid[y * n + i], "overlap at ({i}, {y})");
            grid[y * n + i] = true;
        }
    }
    (n, grid, light, dark)
}

#[test]
fn svg_reads_back_as_the_symbol() {
    for (data, ec) in [
        (&b"https://rl.example/a"[..], EcLevel::Low),
        (&bytes(500, 9)[..], EcLevel::High),
    ] {
        let q = QrCode::encode(data, ec).unwrap();
        for border in [0, 4, 16] {
            let render = Render {
                border,
                scale: 5,
                dark: Rgb(0x11, 0x22, 0x33),
                light: Rgb(0xff, 0xee, 0xdd),
            };
            let svg = q.to_svg(&render).unwrap();
            assert!(svg.starts_with("<svg xmlns=\"http://www.w3.org/2000/svg\""));
            let b = border as usize;
            let (n, grid, light, dark) = read_svg(&svg);
            assert_eq!(n, q.size() + 2 * b);
            assert!(svg.contains(&format!("width=\"{}\" height=\"{}\"", n * 5, n * 5)));
            assert_eq!((light.as_str(), dark.as_str()), ("#ffeedd", "#112233"));
            for y in 0..n {
                for x in 0..n {
                    let dark = x >= b && y >= b && q.is_dark(x - b, y - b);
                    assert_eq!(grid[y * n + x], dark, "({x}, {y})");
                }
            }
        }
    }
}
