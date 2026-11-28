//! QR codes (ISO/IEC 18004:2015) for links, written as SVG or PNG.
//!
//! The encoder covers what a short link needs and nothing else: one segment
//! in byte mode, versions 1 to 40, the four error-correction levels, and the
//! eight data masks scored by the standard's four penalty rules. There are
//! no numeric, alphanumeric or kanji segments, no ECI and no structured
//! append: a URL is bytes, and byte mode reads the same in every scanner.
//!
//! The smallest version that holds the data at the requested level is used,
//! and the level is never raised behind the caller's back, so the same input
//! always gives the same symbol. Of the eight masks, the one with the lowest
//! penalty wins, ties going to the lower mask number.
//!
//! Both writers draw a quiet zone (four modules by default, as the standard
//! asks) in the light colour. The SVG is one `<path>` with one rectangle per
//! horizontal run of dark modules. The PNG is a 1-bit palette image whose
//! pixels are stored without compression (deflate's stored blocks): a QR
//! image is small, the PNG needs no deflate implementation, and every
//! decoder reads stored blocks. Nothing here allocates more than the symbol
//! and the output.

use std::fmt;
use std::str::FromStr;

/// Smallest and largest versions. Version `v` is `17 + 4v` modules a side.
pub const MIN_VERSION: u8 = 1;
pub const MAX_VERSION: u8 = 40;

/// Quiet zone the writers draw unless told otherwise, in modules.
pub const DEFAULT_BORDER: u8 = 4;
/// Largest quiet zone the writers accept, in modules.
pub const MAX_BORDER: u8 = 16;
/// PNG pixels per module unless told otherwise.
pub const DEFAULT_SCALE: u8 = 8;
/// Largest PNG pixels per module. Version 40 with the largest border is
/// then 6,688 pixels a side and about 5.6 MB of PNG.
pub const MAX_SCALE: u8 = 32;

/// How much of the symbol can be lost and still read back.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EcLevel {
    /// About 7% of codewords recoverable.
    Low,
    /// About 15%.
    Medium,
    /// About 25%.
    Quartile,
    /// About 30%.
    High,
}

impl EcLevel {
    pub const ALL: [EcLevel; 4] = [
        EcLevel::Low,
        EcLevel::Medium,
        EcLevel::Quartile,
        EcLevel::High,
    ];

    fn index(self) -> usize {
        self as usize
    }

    /// The two bits the format information carries for this level
    /// (table 12 of the standard): L is 01, M 00, Q 11 and H 10.
    fn format_bits(self) -> u32 {
        match self {
            EcLevel::Low => 1,
            EcLevel::Medium => 0,
            EcLevel::Quartile => 3,
            EcLevel::High => 2,
        }
    }

    /// The level's letter: `L`, `M`, `Q` or `H`.
    pub fn letter(self) -> char {
        match self {
            EcLevel::Low => 'L',
            EcLevel::Medium => 'M',
            EcLevel::Quartile => 'Q',
            EcLevel::High => 'H',
        }
    }
}

impl fmt::Display for EcLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.letter())
    }
}

impl FromStr for EcLevel {
    type Err = QrError;

    /// `L`, `M`, `Q` or `H`, either case.
    fn from_str(s: &str) -> Result<Self, QrError> {
        match s {
            "L" | "l" => Ok(EcLevel::Low),
            "M" | "m" => Ok(EcLevel::Medium),
            "Q" | "q" => Ok(EcLevel::Quartile),
            "H" | "h" => Ok(EcLevel::High),
            _ => Err(QrError::BadLevel),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QrError {
    /// The data does not fit in version 40 at this level; `max` bytes would.
    TooLong { len: usize, max: usize },
    /// Not one of `L`, `M`, `Q` or `H`.
    BadLevel,
    /// A mask number other than 0 to 7.
    BadMask,
    /// A border over [`MAX_BORDER`] or a scale of 0 or over [`MAX_SCALE`].
    BadRender,
    /// A colour other than `#rgb` or `#rrggbb`.
    BadColor,
}

impl fmt::Display for QrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QrError::TooLong { len, max } => write!(
                f,
                "{len} bytes do not fit in a QR code at this error-correction level (at most {max})"
            ),
            QrError::BadLevel => f.write_str("error-correction level must be L, M, Q or H"),
            QrError::BadMask => f.write_str("mask must be 0 to 7"),
            QrError::BadRender => write!(
                f,
                "border must be 0 to {MAX_BORDER} modules and scale 1 to {MAX_SCALE} pixels"
            ),
            QrError::BadColor => f.write_str("colour must be #rgb or #rrggbb"),
        }
    }
}

impl std::error::Error for QrError {}

// Tables 9 of the standard, indexed by level (L, M, Q, H) and version; the
// entry for version 0 is unused.

/// Error-correction codewords in each block.
const ECC_PER_BLOCK: [[u8; 41]; 4] = [
    [
        0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28,
        30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
    ],
    [
        0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28,
        28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    ],
    [
        0, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30,
        30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
    ],
    [
        0, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24,
        30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
    ],
];

/// Error-correction blocks the codewords are split into.
const BLOCKS: [[u8; 41]; 4] = [
    [
        0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13,
        14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25,
    ],
    [
        0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21,
        23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49,
    ],
    [
        0, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29,
        34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68,
    ],
    [
        0, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32,
        35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81,
    ],
];

/// Modules a side of a version.
pub fn side(version: u8) -> usize {
    17 + 4 * version as usize
}

/// Modules left for data and error correction once the function patterns
/// and the format and version information are drawn.
fn raw_data_modules(version: u8) -> usize {
    let v = version as usize;
    let mut n = (16 * v + 128) * v + 64;
    if v >= 2 {
        let align = v / 7 + 2;
        n -= (25 * align - 10) * align - 55;
        if v >= 7 {
            n -= 36;
        }
    }
    n
}

/// Data codewords a version holds at a level.
fn data_codewords(version: u8, ec: EcLevel) -> usize {
    let v = version as usize;
    raw_data_modules(version) / 8
        - ECC_PER_BLOCK[ec.index()][v] as usize * BLOCKS[ec.index()][v] as usize
}

/// Bits of the byte-mode character count: 8 up to version 9, then 16.
fn count_bits(version: u8) -> usize {
    if version <= 9 { 8 } else { 16 }
}

/// Most bytes of data a version holds at a level in one byte-mode segment.
pub fn byte_capacity(version: u8, ec: EcLevel) -> usize {
    let bits = data_codewords(version, ec) * 8 - 4 - count_bits(version);
    (bits / 8).min((1 << count_bits(version)) - 1)
}

// GF(256) with the standard's polynomial x^8 + x^4 + x^3 + x^2 + 1.

const GF: ([u8; 256], [u8; 256]) = {
    let mut exp = [0u8; 256];
    let mut log = [0u8; 256];
    let mut x: u16 = 1;
    let mut i = 0;
    while i < 255 {
        exp[i] = x as u8;
        log[x as usize] = i as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= 0x11D;
        }
        i += 1;
    }
    exp[255] = exp[0];
    (exp, log)
};

fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let (exp, log) = &GF;
    exp[(log[a as usize] as usize + log[b as usize] as usize) % 255]
}

/// The generator polynomial (x - α^0)(x - α^1)...(x - α^(n-1)), highest
/// power first and without its leading 1.
fn rs_generator(n: usize) -> Vec<u8> {
    let mut g = vec![0u8; n];
    g[n - 1] = 1;
    let mut root = 1u8;
    for _ in 0..n {
        // Multiply by (x - root): shift up one power and add root times g.
        for j in 0..n {
            g[j] = gf_mul(g[j], root);
            if j + 1 < n {
                g[j] ^= g[j + 1];
            }
        }
        root = gf_mul(root, 2);
    }
    g
}

/// The remainder of data(x) * x^n divided by the generator: the block's
/// error-correction codewords.
fn rs_remainder(data: &[u8], generator: &[u8]) -> Vec<u8> {
    let mut rem = vec![0u8; generator.len()];
    for &b in data {
        let factor = b ^ rem[0];
        rem.rotate_left(1);
        let last = rem.len() - 1;
        rem[last] = 0;
        for (r, &g) in rem.iter_mut().zip(generator) {
            *r ^= gf_mul(g, factor);
        }
    }
    rem
}

/// A bit string written most significant bit first.
struct Bits {
    bytes: Vec<u8>,
    len: usize,
}

impl Bits {
    fn with_capacity(bytes: usize) -> Self {
        Bits {
            bytes: Vec::with_capacity(bytes),
            len: 0,
        }
    }

    fn push(&mut self, value: u32, n: usize) {
        for i in (0..n).rev() {
            if self.len.is_multiple_of(8) {
                self.bytes.push(0);
            }
            if (value >> i) & 1 == 1 {
                *self.bytes.last_mut().expect("pushed above") |= 0x80 >> (self.len % 8);
            }
            self.len += 1;
        }
    }
}

/// An encoded symbol: a square of dark and light modules.
#[derive(Clone, PartialEq, Eq)]
pub struct QrCode {
    version: u8,
    ec: EcLevel,
    mask: u8,
    size: usize,
    /// Row-major, `true` for dark.
    modules: Vec<bool>,
}

impl fmt::Debug for QrCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "QrCode {{ version: {}, ec: {}, mask: {} }}",
            self.version, self.ec, self.mask
        )?;
        for y in 0..self.size {
            for x in 0..self.size {
                f.write_str(if self.is_dark(x, y) { "#" } else { "." })?;
            }
            f.write_str("\n")?;
        }
        Ok(())
    }
}

impl QrCode {
    /// Encodes `data` in byte mode at level `ec`, in the smallest version
    /// that holds it, with the mask of lowest penalty.
    pub fn encode(data: &[u8], ec: EcLevel) -> Result<QrCode, QrError> {
        Self::build(data, ec, None)
    }

    /// As [`QrCode::encode`] with a chosen mask, 0 to 7.
    pub fn encode_with_mask(data: &[u8], ec: EcLevel, mask: u8) -> Result<QrCode, QrError> {
        if mask > 7 {
            return Err(QrError::BadMask);
        }
        Self::build(data, ec, Some(mask))
    }

    fn build(data: &[u8], ec: EcLevel, mask: Option<u8>) -> Result<QrCode, QrError> {
        let version = (MIN_VERSION..=MAX_VERSION)
            .find(|&v| data.len() <= byte_capacity(v, ec))
            .ok_or(QrError::TooLong {
                len: data.len(),
                max: byte_capacity(MAX_VERSION, ec),
            })?;
        let codewords = Self::codewords(data, version, ec);

        let size = side(version);
        let mut base = Matrix {
            size,
            modules: vec![false; size * size],
            function: vec![false; size * size],
        };
        base.draw_function_patterns(version);
        base.draw_codewords(&codewords);

        let (mask, modules) = match mask {
            Some(m) => (m, base.masked(m, ec)),
            None => {
                let mut best: Option<(u32, u8, Vec<bool>)> = None;
                for m in 0..8 {
                    let candidate = base.masked(m, ec);
                    let score = penalty(&candidate, size);
                    if best.as_ref().is_none_or(|(s, _, _)| score < *s) {
                        best = Some((score, m, candidate));
                    }
                }
                let (_, m, modules) = best.expect("eight masks were scored");
                (m, modules)
            }
        };
        Ok(QrCode {
            version,
            ec,
            mask,
            size,
            modules,
        })
    }

    /// The segment, terminator and padding, split into blocks, each block
    /// followed by its error correction, then interleaved (clause 7.6).
    fn codewords(data: &[u8], version: u8, ec: EcLevel) -> Vec<u8> {
        let capacity = data_codewords(version, ec);
        let mut bits = Bits::with_capacity(capacity);
        bits.push(0b0100, 4);
        bits.push(data.len() as u32, count_bits(version));
        for &b in data {
            bits.push(b as u32, 8);
        }
        let terminator = (capacity * 8 - bits.len).min(4);
        bits.push(0, terminator);
        bits.push(0, (8 - bits.len % 8) % 8);
        let mut padded = bits.bytes;
        for pad in [0xEC, 0x11].into_iter().cycle() {
            if padded.len() >= capacity {
                break;
            }
            padded.push(pad);
        }

        let v = version as usize;
        let blocks = BLOCKS[ec.index()][v] as usize;
        let ecc_len = ECC_PER_BLOCK[ec.index()][v] as usize;
        let raw = raw_data_modules(version) / 8;
        // The first `short` blocks hold one data codeword fewer than the rest.
        let short = blocks - raw % blocks;
        let short_data = raw / blocks - ecc_len;
        let generator = rs_generator(ecc_len);

        let mut split = Vec::with_capacity(blocks);
        let mut eccs = Vec::with_capacity(blocks);
        let mut at = 0;
        for i in 0..blocks {
            let n = short_data + usize::from(i >= short);
            let block = &padded[at..at + n];
            at += n;
            eccs.push(rs_remainder(block, &generator));
            split.push(block);
        }

        let mut out = Vec::with_capacity(raw);
        for i in 0..=short_data {
            for block in &split {
                if let Some(&b) = block.get(i) {
                    out.push(b);
                }
            }
        }
        for i in 0..ecc_len {
            for ecc in &eccs {
                out.push(ecc[i]);
            }
        }
        debug_assert_eq!(out.len(), raw);
        out
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn ec_level(&self) -> EcLevel {
        self.ec
    }

    pub fn mask(&self) -> u8 {
        self.mask
    }

    /// Modules a side, without a quiet zone.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Whether the module in column `x`, row `y` is dark. Outside the
    /// symbol, everything is light.
    pub fn is_dark(&self, x: usize, y: usize) -> bool {
        x < self.size && y < self.size && self.modules[y * self.size + x]
    }

    /// The symbol as SVG, one module per user unit, with `render.scale`
    /// pixels per module as its width and height.
    pub fn to_svg(&self, render: &Render) -> Result<String, QrError> {
        render.check()?;
        let b = render.border as usize;
        let n = self.size + 2 * b;
        let px = n * render.scale as usize;
        let mut out = String::with_capacity(256 + self.size * self.size);
        use fmt::Write;
        let _ = write!(
            out,
            "<svg xmlns=\"http://www.w3.org/2000/svg\" version=\"1.1\" \
             width=\"{px}\" height=\"{px}\" viewBox=\"0 0 {n} {n}\" \
             shape-rendering=\"crispEdges\">\
             <rect width=\"{n}\" height=\"{n}\" fill=\"{}\"/><path fill=\"{}\" d=\"",
            render.light, render.dark
        );
        for y in 0..self.size {
            let mut x = 0;
            while x < self.size {
                if !self.is_dark(x, y) {
                    x += 1;
                    continue;
                }
                let start = x;
                while x < self.size && self.is_dark(x, y) {
                    x += 1;
                }
                let run = x - start;
                let _ = write!(out, "M{},{}h{run}v1h-{run}z", start + b, y + b);
            }
        }
        out.push_str("\"/></svg>\n");
        Ok(out)
    }

    /// The symbol as a 1-bit palette PNG with `render.scale` pixels per
    /// module, its pixels in stored (uncompressed) deflate blocks.
    pub fn to_png(&self, render: &Render) -> Result<Vec<u8>, QrError> {
        render.check()?;
        let border = render.border as usize;
        let scale = render.scale as usize;
        let width = (self.size + 2 * border) * scale;
        let row_bytes = width.div_ceil(8);
        let raw_len = (1 + row_bytes) * width;
        let blocks = raw_len.div_ceil(STORED_MAX).max(1);
        let idat_len = 2 + raw_len + 5 * blocks + 4;
        let mut png = Vec::with_capacity(8 + 25 + 18 + 12 + idat_len + 12);
        png.extend_from_slice(b"\x89PNG\r\n\x1a\n");

        let mut ihdr = [0u8; 13];
        ihdr[0..4].copy_from_slice(&(width as u32).to_be_bytes());
        ihdr[4..8].copy_from_slice(&(width as u32).to_be_bytes());
        // Bit depth 1, colour type 3 (palette), deflate, no filter set
        // choice beyond the standard one, no interlace.
        ihdr[8..13].copy_from_slice(&[1, 3, 0, 0, 0]);
        chunk(&mut png, b"IHDR", &ihdr);

        let Rgb(lr, lg, lb) = render.light;
        let Rgb(dr, dg, db) = render.dark;
        // Index 0 is light, so the zero bits of a fresh row are the quiet zone.
        chunk(&mut png, b"PLTE", &[lr, lg, lb, dr, dg, db]);

        let start = begin_chunk(&mut png, idat_len, b"IDAT");
        let mut z = Stored::new(&mut png, raw_len);
        let mut row = vec![0u8; 1 + row_bytes];
        for y in 0..self.size + 2 * border {
            // Filter type 0, then one bit per pixel, most significant first.
            row.fill(0);
            if y >= border && y < border + self.size {
                for x in 0..self.size {
                    if self.is_dark(x, y - border) {
                        let first = (x + border) * scale;
                        for p in first..first + scale {
                            row[1 + p / 8] |= 0x80 >> (p % 8);
                        }
                    }
                }
            }
            for _ in 0..scale {
                z.write(&row);
            }
        }
        z.finish();
        end_chunk(&mut png, start);
        chunk(&mut png, b"IEND", &[]);
        Ok(png)
    }
}

/// How the writers draw a symbol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Render {
    /// Quiet zone in modules, 0 to [`MAX_BORDER`]. Scanners want 4.
    pub border: u8,
    /// Pixels per module, 1 to [`MAX_SCALE`]: the PNG's resolution and the
    /// SVG's nominal width and height.
    pub scale: u8,
    pub dark: Rgb,
    pub light: Rgb,
}

impl Default for Render {
    fn default() -> Self {
        Render {
            border: DEFAULT_BORDER,
            scale: DEFAULT_SCALE,
            dark: Rgb(0, 0, 0),
            light: Rgb(255, 255, 255),
        }
    }
}

impl Render {
    fn check(&self) -> Result<(), QrError> {
        if self.border > MAX_BORDER || self.scale == 0 || self.scale > MAX_SCALE {
            return Err(QrError::BadRender);
        }
        Ok(())
    }
}

/// A colour, written `#rrggbb`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rgb(pub u8, pub u8, pub u8);

impl fmt::Display for Rgb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{:02x}{:02x}{:02x}", self.0, self.1, self.2)
    }
}

impl FromStr for Rgb {
    type Err = QrError;

    /// `#rgb` or `#rrggbb`, hex digits of either case.
    fn from_str(s: &str) -> Result<Self, QrError> {
        let hex = s.strip_prefix('#').ok_or(QrError::BadColor)?;
        if !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(QrError::BadColor);
        }
        let digit = |i: usize| u8::from_str_radix(&hex[i..i + 1], 16).expect("hex checked");
        match hex.len() {
            3 => Ok(Rgb(digit(0) * 17, digit(1) * 17, digit(2) * 17)),
            6 => Ok(Rgb(
                digit(0) * 16 + digit(1),
                digit(2) * 16 + digit(3),
                digit(4) * 16 + digit(5),
            )),
            _ => Err(QrError::BadColor),
        }
    }
}

/// The symbol being drawn, and which of its modules are function patterns.
struct Matrix {
    size: usize,
    modules: Vec<bool>,
    function: Vec<bool>,
}

impl Matrix {
    fn set_function(&mut self, x: usize, y: usize, dark: bool) {
        let i = y * self.size + x;
        self.modules[i] = dark;
        self.function[i] = true;
    }

    /// Finder, separator, timing and alignment patterns, the version
    /// information, and the format information's place (its bits depend on
    /// the mask, so they are drawn per mask in [`Matrix::masked`]).
    fn draw_function_patterns(&mut self, version: u8) {
        let n = self.size;
        for i in 0..n {
            self.set_function(6, i, i % 2 == 0);
            self.set_function(i, 6, i % 2 == 0);
        }
        for (cx, cy) in [(3, 3), (n - 4, 3), (3, n - 4)] {
            self.draw_finder(cx, cy);
        }
        let centres = alignment_centres(version);
        let last = centres.len().saturating_sub(1);
        for (i, &cy) in centres.iter().enumerate() {
            for (j, &cx) in centres.iter().enumerate() {
                // The three corners that would overlap a finder are skipped.
                let corner = (i == 0 && j == 0) || (i == 0 && j == last) || (i == last && j == 0);
                if !corner {
                    for dy in 0..5usize {
                        for dx in 0..5usize {
                            let ring = dx.abs_diff(2).max(dy.abs_diff(2));
                            self.set_function(cx + dx - 2, cy + dy - 2, ring != 1);
                        }
                    }
                }
            }
        }
        draw_format(self, 0);
        if version >= 7 {
            let bits = version_bits(version);
            for i in 0..18 {
                let dark = (bits >> i) & 1 == 1;
                let a = n - 11 + i % 3;
                let b = i / 3;
                self.set_function(a, b, dark);
                self.set_function(b, a, dark);
            }
        }
    }

    /// A finder centred on (cx, cy) with its light separator, clipped to
    /// the symbol.
    fn draw_finder(&mut self, cx: usize, cy: usize) {
        for dy in -4i32..=4 {
            for dx in -4i32..=4 {
                let x = cx as i32 + dx;
                let y = cy as i32 + dy;
                if (0..self.size as i32).contains(&x) && (0..self.size as i32).contains(&y) {
                    let ring = dx.abs().max(dy.abs());
                    self.set_function(x as usize, y as usize, ring != 2 && ring != 4);
                }
            }
        }
    }

    /// Places codewords in two-module columns from the bottom right,
    /// upwards then downwards, skipping function modules and the vertical
    /// timing pattern (clause 7.7.3). Remainder bits are left light.
    fn draw_codewords(&mut self, codewords: &[u8]) {
        let n = self.size;
        let total = codewords.len() * 8;
        let mut i = 0;
        let mut right = n - 1;
        loop {
            if right == 6 {
                right = 5;
            }
            let upward = (right + 1) & 2 == 0;
            for vert in 0..n {
                let y = if upward { n - 1 - vert } else { vert };
                for x in [right, right - 1] {
                    let at = y * n + x;
                    if !self.function[at] && i < total {
                        self.modules[at] = (codewords[i / 8] >> (7 - i % 8)) & 1 == 1;
                        i += 1;
                    }
                }
            }
            if right < 2 {
                break;
            }
            right -= 2;
        }
        debug_assert_eq!(i, total);
    }

    /// Flips every data module for which `flips(x, y)` holds: the data
    /// masks of table 10, with i the row (y) and j the column (x).
    fn apply(&self, modules: &mut [bool], flips: impl Fn(usize, usize) -> bool) {
        let n = self.size;
        for (y, (row, function)) in modules
            .chunks_exact_mut(n)
            .zip(self.function.chunks_exact(n))
            .enumerate()
        {
            for (x, (m, &f)) in row.iter_mut().zip(function).enumerate() {
                *m ^= !f && flips(x, y);
            }
        }
    }

    /// A copy with data mask `mask` applied and its format bits drawn.
    fn masked(&self, mask: u8, ec: EcLevel) -> Vec<bool> {
        let n = self.size;
        let mut out = Matrix {
            size: n,
            modules: self.modules.clone(),
            function: Vec::new(),
        };
        // One loop per mask, so the condition is not chosen per module.
        match mask {
            0 => self.apply(&mut out.modules, |x, y| (x + y) % 2 == 0),
            1 => self.apply(&mut out.modules, |_, y| y % 2 == 0),
            2 => self.apply(&mut out.modules, |x, _| x % 3 == 0),
            3 => self.apply(&mut out.modules, |x, y| (x + y) % 3 == 0),
            4 => self.apply(&mut out.modules, |x, y| (x / 3 + y / 2) % 2 == 0),
            5 => self.apply(&mut out.modules, |x, y| x * y % 2 + x * y % 3 == 0),
            6 => self.apply(&mut out.modules, |x, y| (x * y % 2 + x * y % 3) % 2 == 0),
            7 => self.apply(&mut out.modules, |x, y| ((x + y) % 2 + x * y % 3) % 2 == 0),
            _ => unreachable!("masks are 0 to 7"),
        }
        draw_format(&mut out, format_bits(ec, mask));
        out.modules
    }
}

/// The 15 format bits: level and mask, a BCH(15,5) code, and the XOR mask
/// 101010000010010 (clause 7.9).
fn format_bits(ec: EcLevel, mask: u8) -> u32 {
    let data = ec.format_bits() << 3 | mask as u32;
    let mut rem = data;
    for _ in 0..10 {
        rem = (rem << 1) ^ ((rem >> 9) * 0x537);
    }
    ((data << 10) | (rem & 0x3FF)) ^ 0x5412
}

/// The 18 version bits: the version and a BCH(18,6) code (clause 7.10).
fn version_bits(version: u8) -> u32 {
    let v = version as u32;
    let mut rem = v;
    for _ in 0..12 {
        rem = (rem << 1) ^ ((rem >> 11) * 0x1F25);
    }
    (v << 12) | (rem & 0xFFF)
}

/// Both copies of the format information, and the dark module beside the
/// bottom-left finder.
fn draw_format(m: &mut Matrix, bits: u32) {
    let n = m.size;
    let bit = |i: usize| (bits >> i) & 1 == 1;
    let mut set = |x: usize, y: usize, dark: bool| {
        let i = y * n + x;
        m.modules[i] = dark;
        if !m.function.is_empty() {
            m.function[i] = true;
        }
    };
    // Around the top-left finder.
    for i in 0..6 {
        set(8, i, bit(i));
    }
    set(8, 7, bit(6));
    set(8, 8, bit(7));
    set(7, 8, bit(8));
    for i in 9..15 {
        set(14 - i, 8, bit(i));
    }
    // Split between the other two finders.
    for i in 0..8 {
        set(n - 1 - i, 8, bit(i));
    }
    for i in 8..15 {
        set(8, n - 15 + i, bit(i));
    }
    set(8, n - 8, true);
}

/// Row and column centres of the alignment patterns (annex E).
fn alignment_centres(version: u8) -> Vec<usize> {
    if version == 1 {
        return Vec::new();
    }
    let v = version as usize;
    let count = v / 7 + 2;
    let step = if v == 32 {
        26
    } else {
        (v * 4 + count * 2 + 1) / (count * 2 - 2) * 2
    };
    let mut centres = vec![6; count];
    let last = side(version) - 7;
    for (k, c) in centres.iter_mut().skip(1).rev().enumerate() {
        *c = last - k * step;
    }
    centres
}

const N1: u32 = 3;
const N2: u32 = 3;
const N3: u32 = 40;
const N4: u32 = 10;

/// The penalty of a masked symbol (clause 7.8.3): runs of five or more of a
/// colour in a row or column, 2×2 blocks of a colour, 1:1:3:1:1 finder-like
/// patterns with four light modules on a side (the quiet zone counts as
/// light), and the distance of the dark share from half.
fn penalty(modules: &[bool], n: usize) -> u32 {
    let mut score = 0;
    let mut columns = vec![false; n * n];
    for y in 0..n {
        for x in 0..n {
            columns[x * n + y] = modules[y * n + x];
        }
    }
    for line in modules.chunks_exact(n).chain(columns.chunks_exact(n)) {
        score += line_penalty(line);
    }
    for (row, below) in modules.chunks_exact(n).zip(modules[n..].chunks_exact(n)) {
        for x in 0..n - 1 {
            // Without short-circuits: on data modules, branches mispredict.
            let c = row[x];
            let same = (c == row[x + 1]) & (c == below[x]) & (c == below[x + 1]);
            score += N2 * same as u32;
        }
    }
    let total = n * n;
    let dark = modules.iter().filter(|&&d| d).count();
    // The smallest k with |dark/total - 1/2| <= (k + 1) / 20.
    let k = ((dark * 20).abs_diff(total * 10))
        .div_ceil(total)
        .saturating_sub(1);
    score + k as u32 * N4
}

/// Rules 1 and 3 along one row or column.
fn line_penalty(line: &[bool]) -> u32 {
    let mut score = 0;
    let mut runs = Runs::new(line.len());
    let mut colour = false;
    let mut len = 0;
    for &module in line {
        if module == colour {
            len += 1;
            if len == 5 {
                score += N1;
            } else if len > 5 {
                score += 1;
            }
        } else {
            runs.push(len);
            if !colour {
                score += runs.finder_like() * N3;
            }
            colour = module;
            len = 1;
        }
    }
    score + runs.terminate(colour, len) * N3
}

/// The last seven run lengths of a row or column, newest first, starting
/// with a light run so that runs alternate light, dark, light...
struct Runs {
    n: usize,
    history: [usize; 7],
}

impl Runs {
    fn new(n: usize) -> Self {
        Runs { n, history: [0; 7] }
    }

    fn push(&mut self, mut len: usize) {
        if self.history[0] == 0 {
            // The first run is light and continues into the quiet zone.
            len += self.n;
        }
        self.history.copy_within(0..6, 1);
        self.history[0] = len;
    }

    /// Finder-like patterns ending at the newest light run: dark, light,
    /// three dark, light, dark, with four light modules before or after.
    fn finder_like(&self) -> u32 {
        let h = &self.history;
        let m = h[1];
        let core = m > 0 && h[2] == m && h[3] == m * 3 && h[4] == m && h[5] == m;
        u32::from(core && h[0] >= m * 4 && h[6] >= m)
            + u32::from(core && h[6] >= m * 4 && h[0] >= m)
    }

    /// Closes the row or column with the quiet zone after it.
    fn terminate(&mut self, colour: bool, mut len: usize) -> u32 {
        if colour {
            self.push(len);
            len = 0;
        }
        len += self.n;
        self.push(len);
        self.finder_like()
    }
}

// PNG plumbing.

/// Largest stored deflate block.
const STORED_MAX: usize = 65_535;

const CRC_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 == 1 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

/// CRC-32 as PNG and zlib's gzip cousin use it.
fn crc32(bytes: &[u8]) -> u32 {
    !bytes.iter().fold(!0u32, |c, &b| {
        CRC_TABLE[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8)
    })
}

fn chunk(png: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    let start = begin_chunk(png, data.len(), kind);
    png.extend_from_slice(data);
    end_chunk(png, start);
}

/// Writes a chunk's length and type; returns where the CRC starts.
fn begin_chunk(png: &mut Vec<u8>, len: usize, kind: &[u8; 4]) -> usize {
    png.extend_from_slice(&(len as u32).to_be_bytes());
    let start = png.len();
    png.extend_from_slice(kind);
    start
}

fn end_chunk(png: &mut Vec<u8>, start: usize) {
    let crc = crc32(&png[start..]);
    png.extend_from_slice(&crc.to_be_bytes());
}

/// A zlib stream of stored deflate blocks, written straight into the PNG.
struct Stored<'a> {
    out: &'a mut Vec<u8>,
    /// Bytes still to come, including those of the current block.
    left: usize,
    /// Bytes still to come in the current block.
    block_left: usize,
    a: u32,
    b: u32,
}

impl<'a> Stored<'a> {
    fn new(out: &'a mut Vec<u8>, total: usize) -> Self {
        // CMF 0x78: deflate, 32 KiB window. FLG 0x01: no dictionary, the
        // fastest level, and a check value making CMF·256 + FLG a multiple of 31.
        out.extend_from_slice(&[0x78, 0x01]);
        let mut z = Stored {
            out,
            left: total,
            block_left: 0,
            a: 1,
            b: 0,
        };
        if total == 0 {
            z.block_header(0);
        }
        z
    }

    fn block_header(&mut self, len: usize) {
        let last = u8::from(self.left == len);
        let len16 = len as u16;
        self.out.push(last);
        self.out.extend_from_slice(&len16.to_le_bytes());
        self.out.extend_from_slice(&(!len16).to_le_bytes());
        self.block_left = len;
    }

    fn write(&mut self, mut bytes: &[u8]) {
        // Adler-32, reduced often enough that the sums cannot overflow.
        for chunk in bytes.chunks(5552) {
            for &byte in chunk {
                self.a += byte as u32;
                self.b += self.a;
            }
            self.a %= 65_521;
            self.b %= 65_521;
        }
        while !bytes.is_empty() {
            if self.block_left == 0 {
                self.block_header(self.left.min(STORED_MAX));
            }
            let n = bytes.len().min(self.block_left);
            self.out.extend_from_slice(&bytes[..n]);
            bytes = &bytes[n..];
            self.block_left -= n;
            self.left -= n;
        }
    }

    fn finish(self) {
        debug_assert_eq!(self.left, 0);
        let adler = (self.b << 16) | self.a;
        self.out.extend_from_slice(&adler.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_tables() {
        // Byte-mode capacities from table 7 of the standard.
        let cases = [
            (1, [17, 14, 11, 7]),
            (2, [32, 26, 20, 14]),
            (7, [154, 122, 86, 64]),
            (10, [271, 213, 151, 119]),
            (40, [2953, 2331, 1663, 1273]),
        ];
        for (v, caps) in cases {
            for (ec, cap) in EcLevel::ALL.into_iter().zip(caps) {
                assert_eq!(byte_capacity(v, ec), cap, "version {v} {ec}");
            }
        }
        // Data codewords from table 9.
        for (ec, n) in EcLevel::ALL.into_iter().zip([1468, 1128, 808, 628]) {
            assert_eq!(data_codewords(27, ec), n, "version 27 {ec}");
        }
        for v in MIN_VERSION..=MAX_VERSION {
            // Data and error-correction codewords fill the symbol at every level.
            let raw = raw_data_modules(v) / 8;
            for ec in EcLevel::ALL {
                let blocks = BLOCKS[ec.index()][v as usize] as usize;
                let ecc = ECC_PER_BLOCK[ec.index()][v as usize] as usize;
                assert!(data_codewords(v, ec) + blocks * ecc == raw);
                assert!(raw / blocks > ecc);
            }
            // Remainder bits are 0, 3, 4 or 7.
            assert!([0, 3, 4, 7].contains(&(raw_data_modules(v) % 8)), "{v}");
        }
        assert_eq!(raw_data_modules(1), 208);
        assert_eq!(raw_data_modules(40), 29_648);
        assert_eq!(alignment_centres(2), [6, 18]);
        assert_eq!(alignment_centres(7), [6, 22, 38]);
        assert_eq!(alignment_centres(32), [6, 34, 60, 86, 112, 138]);
        assert_eq!(alignment_centres(40), [6, 30, 58, 86, 114, 142, 170]);
    }

    #[test]
    fn format_and_version_codes() {
        // Annex C: M with mask 5 is 100000011001110; table D.1, version 7.
        assert_eq!(format_bits(EcLevel::Medium, 5), 0b100000011001110);
        assert_eq!(format_bits(EcLevel::Low, 0), 0b111011111000100);
        assert_eq!(format_bits(EcLevel::High, 1), 0b001001110111110);
        assert_eq!(format_bits(EcLevel::Quartile, 6), 0b010111011011010);
        assert_eq!(version_bits(7), 0b000111110010010100);
        assert_eq!(version_bits(40), 0b101000110001101001);
    }

    #[test]
    fn reed_solomon() {
        // Annex I: version 1-M "01234567", 16 data codewords and 10 of ECC.
        let data = [
            0x10, 0x20, 0x0C, 0x56, 0x61, 0x80, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11,
            0xEC, 0x11,
        ];
        assert_eq!(
            rs_remainder(&data, &rs_generator(10)),
            [0xA5, 0x24, 0xD4, 0xC1, 0xED, 0x36, 0xC7, 0x87, 0x2C, 0x55]
        );
        assert_eq!(gf_mul(0, 7), 0);
        assert_eq!(gf_mul(2, 0x80), 0x1D);
    }

    #[test]
    fn checks_and_errors() {
        assert_eq!(crc32(b"IEND"), 0xAE42_6082);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(
            QrCode::encode(&[b'a'; 2954], EcLevel::Low),
            Err(QrError::TooLong {
                len: 2954,
                max: 2953
            })
        );
        assert!(QrCode::encode(&[b'a'; 2953], EcLevel::Low).is_ok());
        assert_eq!(
            QrCode::encode_with_mask(b"x", EcLevel::Low, 8),
            Err(QrError::BadMask)
        );
        let q = QrCode::encode(b"", EcLevel::High).unwrap();
        assert_eq!(
            (q.version(), q.size(), q.ec_level()),
            (1, 21, EcLevel::High)
        );
        assert!(!q.is_dark(21, 0) && !q.is_dark(0, 21) && q.is_dark(0, 0));
        for bad in [
            Render {
                border: MAX_BORDER + 1,
                ..Render::default()
            },
            Render {
                scale: 0,
                ..Render::default()
            },
            Render {
                scale: MAX_SCALE + 1,
                ..Render::default()
            },
        ] {
            assert_eq!(q.to_svg(&bad), Err(QrError::BadRender));
            assert_eq!(q.to_png(&bad), Err(QrError::BadRender));
        }
        for e in [
            QrError::TooLong { len: 3, max: 2 },
            QrError::BadLevel,
            QrError::BadMask,
            QrError::BadRender,
            QrError::BadColor,
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn levels_and_colours() {
        for ec in EcLevel::ALL {
            assert_eq!(ec.to_string().parse::<EcLevel>(), Ok(ec));
            assert_eq!(
                ec.letter()
                    .to_ascii_lowercase()
                    .to_string()
                    .parse::<EcLevel>(),
                Ok(ec)
            );
        }
        assert_eq!("X".parse::<EcLevel>(), Err(QrError::BadLevel));
        assert_eq!("#0aF".parse::<Rgb>(), Ok(Rgb(0, 0xAA, 0xFF)));
        assert_eq!("#12ab9C".parse::<Rgb>(), Ok(Rgb(0x12, 0xAB, 0x9C)));
        assert_eq!(Rgb(0x12, 0xAB, 0x9C).to_string(), "#12ab9c");
        for bad in [
            "123456", "#12345", "#12345g", "#+1+2+3", "#", "#1234567", "#éa",
        ] {
            assert_eq!(bad.parse::<Rgb>(), Err(QrError::BadColor), "{bad}");
        }
    }

    #[test]
    fn stored_blocks_split_at_65535() {
        let mut out = Vec::new();
        let mut z = Stored::new(&mut out, 70_000);
        z.write(&[7u8; 60_000]);
        z.write(&[9u8; 10_000]);
        z.finish();
        assert_eq!(out.len(), 2 + 5 + 65_535 + 5 + 4_465 + 4);
        assert_eq!(&out[2..7], &[0, 0xFF, 0xFF, 0, 0]);
        assert_eq!(&out[7 + 65_535..7 + 65_540], &[1, 0x71, 0x11, 0x8E, 0xEE]);

        let mut out = Vec::new();
        Stored::new(&mut out, 0).finish();
        assert_eq!(out, [0x78, 0x01, 1, 0, 0, 0xFF, 0xFF, 0, 0, 0, 1]);
    }
}
