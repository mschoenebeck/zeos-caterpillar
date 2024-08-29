//! # Example
//!
//! ```
//! use blake2s7r::{blake2s7r, Params};
//!
//! let expected = "b763fe1b196c46e129acf0a6e723420232f5804062db91dd0f51a9b65f2d59bf";
//! let hash = blake2s7r(b"foo");
//! assert_eq!(expected, &hash.to_hex());
//!
//! let hash = Params::new()
//!     .hash_length(16)
//!     .key(b"Squeamish Ossifrage")
//!     .personal(b"Shaftoe")
//!     .to_state()
//!     .update(b"foo")
//!     .update(b"bar")
//!     .update(b"baz")
//!     .finalize();
//! assert_eq!("ee7e3facc558f9f37ac71ce1784cabc1", &hash.to_hex());
//! ```

use arrayref::{array_refs, mut_array_refs, array_ref};
use core::cmp;
use core::fmt;
use core::mem::size_of;

pub(crate) const DEGREE: usize = 8;

// Variants other than Portable are unreachable in no_std, unless CPU features
// are explicitly enabled for the build with e.g. RUSTFLAGS="-C target-feature=avx2".
// This might change in the future if is_x86_feature_detected moves into libcore.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Platform {
    Portable,
}

#[derive(Clone, Copy, Debug)]
pub struct Implementation(Platform);

impl Implementation {
    pub fn detect() -> Self {
        Self::portable()
    }

    pub fn portable() -> Self {
        Implementation(Platform::Portable)
    }

    pub fn degree(&self) -> usize {
        match self.0 {
            Platform::Portable => 1,
        }
    }

    pub fn compress1_loop(
        &self,
        input: &[u8],
        words: &mut [Word; 8],
        count: Count,
        last_node: LastNode,
        finalize: Finalize,
        stride: Stride,
    ) {
        match self.0 {
            Platform::Portable => {
                compress1_loop(input, words, count, last_node, finalize, stride);
            }
        }
    }

}

// Finalize could just be a bool, but this is easier to read at callsites.
#[derive(Clone, Copy, Debug)]
pub enum Finalize {
    Yes,
    No,
}

impl Finalize {
    pub fn yes(&self) -> bool {
        match self {
            Finalize::Yes => true,
            Finalize::No => false,
        }
    }
}

// Like Finalize, this is easier to read at callsites.
#[derive(Clone, Copy, Debug)]
pub enum LastNode {
    Yes,
    No,
}

impl LastNode {
    pub fn yes(&self) -> bool {
        match self {
            LastNode::Yes => true,
            LastNode::No => false,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Stride {
    Serial,   // BLAKE2b/BLAKE2s
    Parallel, // BLAKE2bp/BLAKE2sp
}

impl Stride {
    pub fn padded_blockbytes(&self) -> usize {
        match self {
            Stride::Serial => BLOCKBYTES,
            Stride::Parallel => DEGREE * BLOCKBYTES,
        }
    }
}

pub(crate) fn count_low(count: Count) -> Word {
    count as Word
}

pub(crate) fn count_high(count: Count) -> Word {
    (count >> 8 * size_of::<Word>()) as Word
}

pub(crate) fn flag_word(flag: bool) -> Word {
    if flag {
        !0
    } else {
        0
    }
}

// Pull a array reference at the given offset straight from the input, if
// there's a full block of input available. If there's only a partial block,
// copy it into the provided buffer, and return an array reference that. Along
// with the array, return the number of bytes of real input, and whether the
// input can be finalized (i.e. whether there aren't any more bytes after this
// block). Note that this is written so that the optimizer can elide bounds
// checks, see: https://godbolt.org/z/0hH2bC
pub fn final_block<'a>(
    input: &'a [u8],
    offset: usize,
    buffer: &'a mut [u8; BLOCKBYTES],
    stride: Stride,
) -> (&'a [u8; BLOCKBYTES], usize, bool) {
    let capped_offset = cmp::min(offset, input.len());
    let offset_slice = &input[capped_offset..];
    if offset_slice.len() >= BLOCKBYTES {
        let block = array_ref!(offset_slice, 0, BLOCKBYTES);
        let should_finalize = offset_slice.len() <= stride.padded_blockbytes();
        (block, BLOCKBYTES, should_finalize)
    } else {
        // Copy the final block to the front of the block buffer. The rest of
        // the buffer is assumed to be initialized to zero.
        buffer[..offset_slice.len()].copy_from_slice(offset_slice);
        (buffer, offset_slice.len(), true)
    }
}

pub fn input_debug_asserts(input: &[u8], finalize: Finalize) {
    // If we're not finalizing, the input must not be empty, and it must be an
    // even multiple of the block size.
    if !finalize.yes() {
        debug_assert!(!input.is_empty());
        debug_assert_eq!(0, input.len() % BLOCKBYTES);
    }
}

type Word = u32;
type Count = u64;

/// The max hash length.
pub const OUTBYTES: usize = 8 * size_of::<Word>();
/// The max key length.
pub const KEYBYTES: usize = 8 * size_of::<Word>();
/// The max salt length.
pub const SALTBYTES: usize = 2 * size_of::<Word>();
/// The max personalization length.
pub const PERSONALBYTES: usize = 2 * size_of::<Word>();
/// The number input bytes passed to each call to the compression function. Small benchmarks need
/// to use an even multiple of `BLOCKBYTES`, or else their apparent throughput will be low.
pub const BLOCKBYTES: usize = 16 * size_of::<Word>();

const IV: [Word; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const SIGMA: [[u8; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// Compute the BLAKE2s hash of a slice of bytes all at once, using default
/// parameters.
///
/// # Example
///
/// ```
/// use blake2s7r::blake2s7r;
/// let expected = "b763fe1b196c46e129acf0a6e723420232f5804062db91dd0f51a9b65f2d59bf";
/// let hash = blake2s7r(b"foo");
/// assert_eq!(expected, &hash.to_hex());
/// ```
pub fn blake2s7r(input: &[u8]) -> Hash {
    Params::new().hash(input)
}

/// A parameter builder that exposes all the non-default BLAKE2 features.
///
/// Apart from `hash_length`, which controls the length of the final `Hash`,
/// all of these parameters are just associated data that gets mixed with the
/// input. For more details, see [the BLAKE2 spec](https://blake2.net/blake2.pdf).
///
/// Several of the parameters have a valid range defined in the spec and
/// documented below. Trying to set an invalid parameter will panic.
///
/// # Example
///
/// ```
/// use blake2s7r::Params;
/// // Create a Params object with a secret key and a non-default length.
/// let mut params = Params::new();
/// params.key(b"my secret key");
/// params.hash_length(16);
///
/// // Use those params to hash an input all at once.
/// let hash = params.hash(b"my input");
///
/// // Or use those params to build an incremental State.
/// let mut state = params.to_state();
/// ```
#[derive(Clone)]
pub struct Params {
    hash_length: u8,
    key_length: u8,
    key_block: [u8; BLOCKBYTES],
    salt: [u8; SALTBYTES],
    personal: [u8; PERSONALBYTES],
    fanout: u8,
    max_depth: u8,
    max_leaf_length: u32,
    node_offset: u64,
    node_depth: u8,
    inner_hash_length: u8,
    last_node: LastNode,
    implementation: Implementation,
}

impl Params {
    /// Equivalent to `Params::default()`.
    #[inline]
    pub fn new() -> Self {
        Self {
            hash_length: OUTBYTES as u8,
            key_length: 0,
            key_block: [0; BLOCKBYTES],
            salt: [0; SALTBYTES],
            personal: [0; PERSONALBYTES],
            // NOTE: fanout and max_depth don't default to zero!
            fanout: 1,
            max_depth: 1,
            max_leaf_length: 0,
            node_offset: 0,
            node_depth: 0,
            inner_hash_length: 0,
            last_node: LastNode::No,
            implementation: Implementation::detect(),
        }
    }

    #[inline(always)]
    fn to_words(&self) -> [Word; 8] {
        let (salt_left, salt_right) = array_refs!(&self.salt, SALTBYTES / 2, SALTBYTES / 2);
        let (personal_left, personal_right) =
            array_refs!(&self.personal, PERSONALBYTES / 2, PERSONALBYTES / 2);
        [
            IV[0]
                ^ self.hash_length as u32
                ^ (self.key_length as u32) << 8
                ^ (self.fanout as u32) << 16
                ^ (self.max_depth as u32) << 24,
            IV[1] ^ self.max_leaf_length,
            IV[2] ^ self.node_offset as u32,
            IV[3]
                ^ (self.node_offset >> 32) as u32
                ^ (self.node_depth as u32) << 16
                ^ (self.inner_hash_length as u32) << 24,
            IV[4] ^ Word::from_le_bytes(*salt_left),
            IV[5] ^ Word::from_le_bytes(*salt_right),
            IV[6] ^ Word::from_le_bytes(*personal_left),
            IV[7] ^ Word::from_le_bytes(*personal_right),
        ]
    }

    /// Hash an input all at once with these parameters.
    #[inline]
    pub fn hash(&self, input: &[u8]) -> Hash {
        // If there's a key, just fall back to using the State.
        if self.key_length > 0 {
            return self.to_state().update(input).finalize();
        }
        let mut words = self.to_words();
        self.implementation.compress1_loop(
            input,
            &mut words,
            0,
            self.last_node,
            Finalize::Yes,
            Stride::Serial,
        );
        Hash {
            bytes: state_words_to_bytes(&words),
            len: self.hash_length,
        }
    }

    /// Construct a `State` object based on these parameters, for hashing input
    /// incrementally.
    pub fn to_state(&self) -> State {
        State::with_params(self)
    }

    /// Set the length of the final hash in bytes, from 1 to `OUTBYTES` (32). Apart from
    /// controlling the length of the final `Hash`, this is also associated data, and changing it
    /// will result in a totally different hash.
    #[inline]
    pub fn hash_length(&mut self, length: usize) -> &mut Self {
        assert!(
            1 <= length && length <= OUTBYTES,
            "Bad hash length: {}",
            length
        );
        self.hash_length = length as u8;
        self
    }

    /// Use a secret key, so that BLAKE2 acts as a MAC. The maximum key length is `KEYBYTES` (32).
    /// An empty key is equivalent to having no key at all.
    #[inline]
    pub fn key(&mut self, key: &[u8]) -> &mut Self {
        assert!(key.len() <= KEYBYTES, "Bad key length: {}", key.len());
        self.key_length = key.len() as u8;
        self.key_block = [0; BLOCKBYTES];
        self.key_block[..key.len()].copy_from_slice(key);
        self
    }

    /// At most `SALTBYTES` (8). Shorter salts are padded with null bytes. An empty salt is
    /// equivalent to having no salt at all.
    #[inline]
    pub fn salt(&mut self, salt: &[u8]) -> &mut Self {
        assert!(salt.len() <= SALTBYTES, "Bad salt length: {}", salt.len());
        self.salt = [0; SALTBYTES];
        self.salt[..salt.len()].copy_from_slice(salt);
        self
    }

    /// At most `PERSONALBYTES` (8). Shorter personalizations are padded with null bytes. An empty
    /// personalization is equivalent to having no personalization at all.
    #[inline]
    pub fn personal(&mut self, personalization: &[u8]) -> &mut Self {
        assert!(
            personalization.len() <= PERSONALBYTES,
            "Bad personalization length: {}",
            personalization.len()
        );
        self.personal = [0; PERSONALBYTES];
        self.personal[..personalization.len()].copy_from_slice(personalization);
        self
    }

    /// From 0 (meaning unlimited) to 255. The default is 1 (meaning sequential).
    #[inline]
    pub fn fanout(&mut self, fanout: u8) -> &mut Self {
        self.fanout = fanout;
        self
    }

    /// From 0 (meaning BLAKE2X B2 hashes), through 1 (the default, meaning sequential) to 255 (meaning unlimited).
    #[inline]
    pub fn max_depth(&mut self, depth: u8) -> &mut Self {
        self.max_depth = depth;
        self
    }

    /// From 0 (the default, meaning unlimited or sequential) to `2^32 - 1`.
    #[inline]
    pub fn max_leaf_length(&mut self, length: u32) -> &mut Self {
        self.max_leaf_length = length;
        self
    }

    /// From 0 (the default, meaning first, leftmost, leaf, or sequential) to `2^48 - 1`.
    #[inline]
    pub fn node_offset(&mut self, offset: u64) -> &mut Self {
        assert!(offset < (1 << 48), "Bad node offset: {}", offset);
        self.node_offset = offset;
        self
    }

    /// From 0 (the default, meaning leaf or sequential) to 255.
    #[inline]
    pub fn node_depth(&mut self, depth: u8) -> &mut Self {
        self.node_depth = depth;
        self
    }

    /// From 0 (the default, meaning sequential) to `OUTBYTES` (32).
    #[inline]
    pub fn inner_hash_length(&mut self, length: usize) -> &mut Self {
        assert!(length <= OUTBYTES, "Bad inner hash length: {}", length);
        self.inner_hash_length = length as u8;
        self
    }

    /// Indicates the rightmost node in a row. This can also be changed on the
    /// `State` object, potentially after hashing has begun. See
    /// [`State::set_last_node`].
    ///
    /// [`State::set_last_node`]: struct.State.html#method.set_last_node
    #[inline]
    pub fn last_node(&mut self, last_node: bool) -> &mut Self {
        self.last_node = if last_node {
            LastNode::Yes
        } else {
            LastNode::No
        };
        self
    }
}

impl Default for Params {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Params {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Params {{ hash_length: {}, key_length: {}, salt: {:?}, personal: {:?}, fanout: {}, \
             max_depth: {}, max_leaf_length: {}, node_offset: {}, node_depth: {}, \
             inner_hash_length: {}, last_node: {} }}",
            self.hash_length,
            // NB: Don't print the key itself. Debug shouldn't leak secrets.
            self.key_length,
            &self.salt,
            &self.personal,
            self.fanout,
            self.max_depth,
            self.max_leaf_length,
            self.node_offset,
            self.node_depth,
            self.inner_hash_length,
            self.last_node.yes(),
        )
    }
}

/// An incremental hasher for BLAKE2s.
///
/// To construct a `State` with non-default parameters, see `Params::to_state`.
///
/// # Example
///
/// ```
/// use blake2s7r::{State, blake2s7r};
///
/// let mut state = State::new();
///
/// state.update(b"foo");
/// assert_eq!(blake2s7r(b"foo"), state.finalize());
///
/// state.update(b"bar");
/// assert_eq!(blake2s7r(b"foobar"), state.finalize());
/// ```
#[derive(Clone)]
pub struct State {
    words: [Word; 8],
    count: Count,
    buf: [u8; BLOCKBYTES],
    buflen: u8,
    last_node: LastNode,
    hash_length: u8,
    implementation: Implementation,
    is_keyed: bool,
}

impl State {
    /// Equivalent to `State::default()` or `Params::default().to_state()`.
    pub fn new() -> Self {
        Self::with_params(&Params::default())
    }

    fn with_params(params: &Params) -> Self {
        let mut state = Self {
            words: params.to_words(),
            count: 0,
            buf: [0; BLOCKBYTES],
            buflen: 0,
            last_node: params.last_node,
            hash_length: params.hash_length,
            implementation: params.implementation,
            is_keyed: params.key_length > 0,
        };
        if state.is_keyed {
            state.buf = params.key_block;
            state.buflen = state.buf.len() as u8;
        }
        state
    }

    fn fill_buf(&mut self, input: &mut &[u8]) {
        let take = cmp::min(BLOCKBYTES - self.buflen as usize, input.len());
        self.buf[self.buflen as usize..self.buflen as usize + take].copy_from_slice(&input[..take]);
        self.buflen += take as u8;
        *input = &input[take..];
    }

    // If the state already has some input in its buffer, try to fill the buffer and perform a
    // compression. However, only do the compression if there's more input coming, otherwise it
    // will give the wrong hash it the caller finalizes immediately after.
    fn compress_buffer_if_possible(&mut self, input: &mut &[u8]) {
        if self.buflen > 0 {
            self.fill_buf(input);
            if !input.is_empty() {
                self.implementation.compress1_loop(
                    &self.buf,
                    &mut self.words,
                    self.count,
                    self.last_node,
                    Finalize::No,
                    Stride::Serial,
                );
                self.count = self.count.wrapping_add(BLOCKBYTES as Count);
                self.buflen = 0;
            }
        }
    }

    /// Add input to the hash. You can call `update` any number of times.
    pub fn update(&mut self, mut input: &[u8]) -> &mut Self {
        // If we have a partial buffer, try to complete it.
        self.compress_buffer_if_possible(&mut input);
        // While there's more than a block of input left (which also means we cleared the buffer
        // above), compress blocks directly without copying.
        let mut end = input.len().saturating_sub(1);
        end -= end % BLOCKBYTES;
        if end > 0 {
            self.implementation.compress1_loop(
                &input[..end],
                &mut self.words,
                self.count,
                self.last_node,
                Finalize::No,
                Stride::Serial,
            );
            self.count = self.count.wrapping_add(end as Count);
            input = &input[end..];
        }
        // Buffer any remaining input, to be either compressed or finalized in a subsequent call.
        // Note that this represents some copying overhead, which in theory we could avoid in
        // all-at-once setting. A function hardcoded for exactly BLOCKSIZE input bytes is about 10%
        // faster than using this implementation for the same input.
        self.fill_buf(&mut input);
        self
    }

    /// Finalize the state and return a `Hash`. This method is idempotent, and calling it multiple
    /// times will give the same result. It's also possible to `update` with more input in between.
    pub fn finalize(&self) -> Hash {
        let mut words_copy = self.words;
        self.implementation.compress1_loop(
            &self.buf[..self.buflen as usize],
            &mut words_copy,
            self.count,
            self.last_node,
            Finalize::Yes,
            Stride::Serial,
        );
        Hash {
            bytes: state_words_to_bytes(&words_copy),
            len: self.hash_length,
        }
    }

    /// Set a flag indicating that this is the last node of its level in a tree hash. This is
    /// equivalent to [`Params::last_node`], except that it can be set at any time before calling
    /// `finalize`. That allows callers to begin hashing a node without knowing ahead of time
    /// whether it's the last in its level. For more details about the intended use of this flag
    /// [the BLAKE2 spec].
    ///
    /// [`Params::last_node`]: struct.Params.html#method.last_node
    /// [the BLAKE2 spec]: https://blake2.net/blake2.pdf
    pub fn set_last_node(&mut self, last_node: bool) -> &mut Self {
        self.last_node = if last_node {
            LastNode::Yes
        } else {
            LastNode::No
        };
        self
    }

    /// Return the total number of bytes input so far.
    ///
    /// Note that `count` doesn't include the bytes of the key block, if any.
    /// It's exactly the total number of input bytes fed to `update`.
    pub fn count(&self) -> Count {
        let mut ret = self.count.wrapping_add(self.buflen as Count);
        if self.is_keyed {
            ret -= BLOCKBYTES as Count;
        }
        ret
    }
}

#[inline(always)]
fn state_words_to_bytes(state_words: &[Word; 8]) -> [u8; OUTBYTES] {
    let mut bytes = [0; OUTBYTES];
    {
        const W: usize = size_of::<Word>();
        let refs = mut_array_refs!(&mut bytes, W, W, W, W, W, W, W, W);
        *refs.0 = state_words[0].to_le_bytes();
        *refs.1 = state_words[1].to_le_bytes();
        *refs.2 = state_words[2].to_le_bytes();
        *refs.3 = state_words[3].to_le_bytes();
        *refs.4 = state_words[4].to_le_bytes();
        *refs.5 = state_words[5].to_le_bytes();
        *refs.6 = state_words[6].to_le_bytes();
        *refs.7 = state_words[7].to_le_bytes();
    }
    bytes
}

impl std::io::Write for State {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl fmt::Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // NB: Don't print the words. Leaking them would allow length extension.
        write!(
            f,
            "State {{ count: {}, hash_length: {}, last_node: {} }}",
            self.count(),
            self.hash_length,
            self.last_node.yes(),
        )
    }
}

impl Default for State {
    fn default() -> Self {
        Self::with_params(&Params::default())
    }
}

type HexString = arrayvec::ArrayString<{ 2 * OUTBYTES }>;

/// A finalized BLAKE2 hash, with constant-time equality.
#[derive(Clone, Copy)]
pub struct Hash {
    bytes: [u8; OUTBYTES],
    len: u8,
}

impl Hash {
    /// Convert the hash to a byte slice. Note that if you're using BLAKE2 as a MAC, you need
    /// constant time equality, which `&[u8]` doesn't provide.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// Convert the hash to a byte array. Note that if you're using BLAKE2 as a
    /// MAC, you need constant time equality, which arrays don't provide. This
    /// panics in debug mode if the length of the hash isn't `OUTBYTES`.
    #[inline]
    pub fn as_array(&self) -> &[u8; OUTBYTES] {
        debug_assert_eq!(self.len as usize, OUTBYTES);
        &self.bytes
    }

    /// Convert the hash to a lowercase hexadecimal
    /// [`ArrayString`](https://docs.rs/arrayvec/0.7/arrayvec/struct.ArrayString.html).
    pub fn to_hex(&self) -> HexString {
        bytes_to_hex(self.as_bytes())
    }
}

fn bytes_to_hex(bytes: &[u8]) -> HexString {
    let mut s = arrayvec::ArrayString::new();
    let table = b"0123456789abcdef";
    for &b in bytes {
        s.push(table[(b >> 4) as usize] as char);
        s.push(table[(b & 0xf) as usize] as char);
    }
    s
}

impl From<[u8; OUTBYTES]> for Hash {
    fn from(bytes: [u8; OUTBYTES]) -> Self {
        Self {
            bytes,
            len: OUTBYTES as u8,
        }
    }
}

impl From<&[u8; OUTBYTES]> for Hash {
    fn from(bytes: &[u8; OUTBYTES]) -> Self {
        Self::from(*bytes)
    }
}

/// This implementation is constant time, if the two hashes are the same length.
impl PartialEq for Hash {
    fn eq(&self, other: &Hash) -> bool {
        constant_time_eq::constant_time_eq(&self.as_bytes(), &other.as_bytes())
    }
}

/// This implementation is constant time, if the slice is the same length as the hash.
impl PartialEq<[u8]> for Hash {
    fn eq(&self, other: &[u8]) -> bool {
        constant_time_eq::constant_time_eq(&self.as_bytes(), other)
    }
}

impl Eq for Hash {}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Hash(0x{})", self.to_hex())
    }
}

// G is the mixing function, called eight times per round in the compression
// function. V is the 16-word state vector of the compression function, usually
// described as a 4x4 matrix. A, B, C, and D are the mixing indices, set by the
// caller first to the four columns of V, and then to its four diagonals. X and
// Y are words of input, chosen by the caller according to the message
// schedule, SIGMA.
#[inline(always)]
fn g(v: &mut [Word; 16], a: usize, b: usize, c: usize, d: usize, x: Word, y: Word) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

#[inline(always)]
fn round(r: usize, m: &[Word; 16], v: &mut [Word; 16]) {
    // Select the message schedule based on the round.
    let s = SIGMA[r];

    // Mix the columns.
    g(v, 0, 4, 8, 12, m[s[0] as usize], m[s[1] as usize]);
    g(v, 1, 5, 9, 13, m[s[2] as usize], m[s[3] as usize]);
    g(v, 2, 6, 10, 14, m[s[4] as usize], m[s[5] as usize]);
    g(v, 3, 7, 11, 15, m[s[6] as usize], m[s[7] as usize]);

    // Mix the rows.
    g(v, 0, 5, 10, 15, m[s[8] as usize], m[s[9] as usize]);
    g(v, 1, 6, 11, 12, m[s[10] as usize], m[s[11] as usize]);
    g(v, 2, 7, 8, 13, m[s[12] as usize], m[s[13] as usize]);
    g(v, 3, 4, 9, 14, m[s[14] as usize], m[s[15] as usize]);
}

#[inline(always)]
fn compress_block(
    block: &[u8; BLOCKBYTES],
    words: &mut [Word; 8],
    count: Count,
    last_block: Word,
    last_node: Word,
) {
    // Initialize the compression state.
    let mut v = [
        words[0],
        words[1],
        words[2],
        words[3],
        words[4],
        words[5],
        words[6],
        words[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        IV[4] ^ count_low(count),
        IV[5] ^ count_high(count),
        IV[6] ^ last_block,
        IV[7] ^ last_node,
    ];

    // Parse the message bytes as ints in little endian order.
    const W: usize = size_of::<Word>();
    let msg_refs = array_refs!(block, W, W, W, W, W, W, W, W, W, W, W, W, W, W, W, W);
    let m = [
        Word::from_le_bytes(*msg_refs.0),
        Word::from_le_bytes(*msg_refs.1),
        Word::from_le_bytes(*msg_refs.2),
        Word::from_le_bytes(*msg_refs.3),
        Word::from_le_bytes(*msg_refs.4),
        Word::from_le_bytes(*msg_refs.5),
        Word::from_le_bytes(*msg_refs.6),
        Word::from_le_bytes(*msg_refs.7),
        Word::from_le_bytes(*msg_refs.8),
        Word::from_le_bytes(*msg_refs.9),
        Word::from_le_bytes(*msg_refs.10),
        Word::from_le_bytes(*msg_refs.11),
        Word::from_le_bytes(*msg_refs.12),
        Word::from_le_bytes(*msg_refs.13),
        Word::from_le_bytes(*msg_refs.14),
        Word::from_le_bytes(*msg_refs.15),
    ];

    round(0, &m, &mut v);
    round(1, &m, &mut v);
    round(2, &m, &mut v);
    round(3, &m, &mut v);
    round(4, &m, &mut v);
    round(5, &m, &mut v);
    round(6, &m, &mut v);
    //round(7, &m, &mut v);
    //round(8, &m, &mut v);
    //round(9, &m, &mut v);

    words[0] ^= v[0] ^ v[8];
    words[1] ^= v[1] ^ v[9];
    words[2] ^= v[2] ^ v[10];
    words[3] ^= v[3] ^ v[11];
    words[4] ^= v[4] ^ v[12];
    words[5] ^= v[5] ^ v[13];
    words[6] ^= v[6] ^ v[14];
    words[7] ^= v[7] ^ v[15];
}

pub fn compress1_loop(
    input: &[u8],
    words: &mut [Word; 8],
    mut count: Count,
    last_node: LastNode,
    finalize: Finalize,
    stride: Stride,
) {
    input_debug_asserts(input, finalize);

    let mut local_words = *words;

    let mut fin_offset = input.len().saturating_sub(1);
    fin_offset -= fin_offset % stride.padded_blockbytes();
    let mut buf = [0; BLOCKBYTES];
    let (fin_block, fin_len, _) = final_block(input, fin_offset, &mut buf, stride);
    let fin_last_block = flag_word(finalize.yes());
    let fin_last_node = flag_word(finalize.yes() && last_node.yes());

    let mut offset = 0;
    loop {
        let block;
        let count_delta;
        let last_block;
        let last_node;
        if offset == fin_offset {
            block = fin_block;
            count_delta = fin_len;
            last_block = fin_last_block;
            last_node = fin_last_node;
        } else {
            block = array_ref!(input, offset, BLOCKBYTES);
            count_delta = BLOCKBYTES;
            last_block = flag_word(false);
            last_node = flag_word(false);
        };

        count = count.wrapping_add(count_delta as Count);
        compress_block(block, &mut local_words, count, last_block, last_node);

        // Check for termination before bumping the offset, to avoid overflow.
        if offset == fin_offset {
            break;
        }

        offset += stride.padded_blockbytes();
    }

    *words = local_words;
}

#[test]
pub fn test_blake2s7r()
{
    use {blake2s7r, Params};
    
    let expected = "b763fe1b196c46e129acf0a6e723420232f5804062db91dd0f51a9b65f2d59bf";
    let hash = blake2s7r(b"foo");
    assert_eq!(expected, &hash.to_hex());
    
    let hash = Params::new()
        .hash_length(16)
        .key(b"Squeamish Ossifrage")
        .personal(b"Shaftoe")
        .to_state()
        .update(b"foo")
        .update(b"bar")
        .update(b"baz")
        .finalize();
    assert_eq!("ee7e3facc558f9f37ac71ce1784cabc1", &hash.to_hex());
}

#[test]
pub fn test_blake2s7r_blank_hash()
{
    use Params;
    
    let hash = Params::new()
        .hash_length(32)
        .key(b"")
        .personal(b"12345678")
        .to_state()
        .finalize();
    assert_eq!("5f498b5a48f35ac196750ee10a4076fbe9d37157b03649aad426d4c6a1035310", &hash.to_hex());
}

#[test]
fn test_blake2s7r_256_vars() {
    use hex_literal::hex;

    let data: Vec<u8> = hex!("be9f9c485e670acce8b1516a378176161b20583637b6f1c536fbc1158a0a3296831df2920e57a442d5738f4be4dd6be89dd7913fc8b4d1c0a815646a4d674b77f7caf313bd880bf759fcac27037c48c2b2a20acd2fd5248e3be426c84a341c0a3c63eaf36e0d537d10b8db5c6e4c801832c41eb1a3ed602177acded8b4b803bd34339d99a18b71df399641cc8dfae2ad193fcd74b5913e704551777160d14c78f2e8d5c32716a8599c1080cb89a40ccd6ba596694a8b4a065d9f2d0667ef423ed2e418093caff884540858b4f4b62acd47edcea880523e1b1cda8eb225c128c2e9e83f14f6e7448c5733a195cac7d79a53dde5083172462c45b2f799e42af1c9").to_vec();
    assert_eq!(data.len(), 256);

    let hash = Params::new()
        .hash_length(32)
        .key(b"")
        .personal(b"12345678")
        .to_state()
        .update(&data)
        .finalize();
    assert_eq!("362215da919104ccbc728cbda275d4be642b6e80761cdea273ec56e3406fd55e", &hash.to_hex());
}

#[test]
fn test_blake2s7r_700_vars() {
    use hex_literal::hex;

    let data: Vec<u8> = hex!("5dcfe8bab4c758d2eb1ddb7ef337583e0df3e2c358e1755b7cd303a658de9a1227eed1d1114179a5c3c38d692ff2cf2d4e5c92a9516de750106774bbf9f7d063f707f4c9b6a02c0a77e4feb99e036c3ccaee7d1a31cb144093aa074bc9da608f8ff30b39c3c60e4a243cc0bbd406d1262a7d6607b31c60275c6bcc8b0ac49a06a4b629a98693c5f7640f3bca45e4977cfabc5b17f52838af3433b1fd407dbbdc131e8e4bd58bcee85bbab4b57b656c6a2ec6cf852525bc8423675e2bf29159139cd5df99db94719f3f7167230e0d5bd76f6d7891b656732cef9c3c0d48a5fa3d7a879988157b39015a85451b25af0301ca5e759ac35fea79dca38c673ec6db9f3885d9103e2dcb3304bd3d59b0b1d01babc97ef8a74d91b6ab6bf50f29eb5adf7250a28fd85db37bff0133193635da69caeefc72979cf3bef1d2896d847eea7e8a81e0927893dbd010feb6fb845d0399007d9a148a0596d86cd8f4192631f975c560f4de8da5f712c161342063af3c11029d93d6df7ff46db48343499de9ec4786cac059c4025ef418c9fe40132428ff8b91259d71d1709ff066add84ae944b45a817f60b4c1bf719e39ae23e9b413469db2310793e9137cf38741e5dd2a3c138a566dbde1950c00071b20ac457b46ba9b0a7ebdddcc212bd228d2a4c4146a970e54158477247c27871af1564b176576e9fd43bf63740bf77434bc4ea3b1a4b430e1a11714bf43160145578a575c3f78ddeaa48de97f73460f26f8df2b5d63e31800100d16bc27160fea5ced5a977ef541cfe8dadc7b3991ed1c0d4f16a3076bbfed96ba3e155113e794987af8abb133f06feefabc2ac32eb4d4d4ba1541ca08b9e518d2e74b7f946b0cbd2663d58c689359b9a565821acc619011233d1011963fa302cde34fc9c5ba2e03eeb2512f547391e940d56218e22ae325f2dfa38d4bae35744ee707aa5dc9c17674025d15390a08f5c452343546ef6da0f7").to_vec();
    assert_eq!(data.len(), 700);

    let hash = Params::new()
        .hash_length(32)
        .key(b"")
        .personal(b"12345678")
        .to_state()
        .update(&data)
        .finalize();
    assert_eq!("da0c0745e31c2abf07ed24c3be0a5f3f37d5f882e45372e316fa7a79308d38df", &hash.to_hex());
}
