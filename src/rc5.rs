/*
 * RC5-32/12/16
 */ 

// some names are preserved as in RC-5 paper for reference purposes
#![allow(non_snake_case)]

pub type Word                  = u32; // w
const NUMBER_OF_ROUNDS: u8     = 12;  // r \in [0,1,.. 255]
pub const KEY_LENGTH_BYTES: u8 = 16;  // b \in [0,1,.. 255]

pub type Key = [u8; KEY_LENGTH_BYTES as usize]; // K[0..b-1]


pub const BLOCK_BYTES_SIZE: usize = 2 * std::mem::size_of::<Word>();
pub type BlockBytes = [u8; BLOCK_BYTES_SIZE];

pub fn encrypt_bytes(key: Key, plaintext: BlockBytes) -> BlockBytes {
    println!("encrypt_bytes: key = {:02x?}, plaintext = {:02x?}", key, plaintext);

    let mut pt = [0; 2];
    utils::bytes_to_words(&plaintext, &mut pt);

    let (A, B) = algo::encrypt(key, (pt[0], pt[1]));

    let mut ciphertext: BlockBytes = [0; BLOCK_BYTES_SIZE];
    ciphertext[0..4].copy_from_slice(&A.to_le_bytes());
    ciphertext[4..8].copy_from_slice(&B.to_le_bytes());

    ciphertext
}

pub fn decrypt_bytes(key: Key, ciphertext: BlockBytes) -> BlockBytes {
    println!("decrypt_bytes: key = {:02x?}, ciphertext = {:02x?}", key, ciphertext);

    let mut ct = [0; 2];
    utils::bytes_to_words(&ciphertext, &mut ct);

    let (A, B) = algo::decrypt(key, (ct[0], ct[1]));

    let mut plaintext: BlockBytes = [0; BLOCK_BYTES_SIZE];
    plaintext[0..4].copy_from_slice(&A.to_le_bytes());
    plaintext[4..8].copy_from_slice(&B.to_le_bytes());

    plaintext
}


mod ops {
    use super::Word;
    type NumberOfBits = u32;

    // two's complement addition of words modulo-2^w
    pub(crate) fn plus(x: Word, y: Word) -> Word {
        x.wrapping_add(y)
    }

    // two's complement subtraction of words modulo-2^w
    pub(crate) fn minus(x: Word, y: Word) -> Word {
        x.wrapping_sub(y)
    }

    pub(crate) fn bitwise_xor(x: Word, y: Word) -> Word {
        x ^ y
    }

    // cyclic rotation of `x` left by `y` bits
    pub(crate) fn left_rotation(x: Word, y: NumberOfBits) -> Word {
        Word::rotate_left(x, y)
    }

    // cyclic rotation of `x` right by `y` bits
    pub(crate) fn right_rotation(x: Word, y: NumberOfBits) -> Word {
        Word::rotate_right(x, y)
    }
}

mod utils {
    use super::{ops, Word};

    pub(crate) fn bytes_to_words(bytes: &[u8], dst: &mut [Word]) {
        println!("bytes = {:02x?}", bytes);
        println!("bytes.len() = {:x?}", bytes.len());

        println!("dst = {:02x?}", dst);
        println!("dst.len() = {:x?}", dst.len());

        const BITS_PER_BYTE: usize = 8;

        for i in (0..bytes.len()).rev() {
            let e = i as usize / std::mem::size_of::<Word>();
            dst[e] = ops::plus(ops::left_rotation(dst[e],BITS_PER_BYTE as u32), bytes[i as usize] as Word);
        }

        println!("dst = {:08x?}", dst);
    }
}

mod algo {
    use super::*;

    type Block = (Word, Word);

    const EXPANDED_KEY_TABLE_SIZE: usize = 2 * (NUMBER_OF_ROUNDS as usize + 1);	// t = 2(r+1)
    type ExpandedKeyTable = [Word; EXPANDED_KEY_TABLE_SIZE];					// S[0..t-1]

    // FIXME: should be `max(KEY_LENGTH_BYTES,1) / mem::size_of::<Word>()` to support
    // `KEY_LENGTH_BYTES == 0`
    pub(crate) const KEY_WORDS_SIZE: usize = KEY_LENGTH_BYTES as usize / std::mem::size_of::<Word>();
    pub(crate) type KeyWords = [Word; KEY_WORDS_SIZE];

    fn initialize_expanded_key_table(expanded_key: &mut ExpandedKeyTable) {
        // magic constants
        const P_32: u32 = 0xb7e15163;
        const Q_32: u32 = 0x9e3779b9;
        let P_W = P_32;
        let Q_W = Q_32;

        expanded_key[0] = P_W;
        for i in 1..EXPANDED_KEY_TABLE_SIZE {
            expanded_key[i] = ops::plus(expanded_key[i - 1], Q_W);
        }
    }

    fn expand_key(key: Key) -> ExpandedKeyTable {
        // convert the secret key from bytes to words
        // let mut L: KeyWords = utils::key_bytes_to_words(key);
        let mut L: KeyWords = [0; KEY_WORDS_SIZE];
        utils::bytes_to_words(&key, &mut L[..]);

        // initialize the array S
        let mut S: ExpandedKeyTable = [0; EXPANDED_KEY_TABLE_SIZE];
        initialize_expanded_key_table(&mut S);
        println!("S = {:08x?}", &S[..]);

        // mix in the secret key
        let mut i = 0;
        let mut j = 0;
        let mut A = 0;
        let mut B = 0;
        println!("EXPANDED_KEY_TABLE_SIZE = {}, KEY_WORDS_SIZE = {}", EXPANDED_KEY_TABLE_SIZE, KEY_WORDS_SIZE);
        for _ in 0..3 * std::cmp::max(EXPANDED_KEY_TABLE_SIZE,KEY_WORDS_SIZE) {	// 3*max(t,c) times
            S[i] = ops::left_rotation(ops::plus(S[i], ops::plus(A, B)), 3);
            A = S[i];
            L[j] = ops::left_rotation(ops::plus(L[j], ops::plus(A, B)), ops::plus(A, B));
            B = L[j];

            println!("S[{}] = {:08x?}", i, S[i]);
            println!("L[{}] = {:08x?}", j, L[j]);

            i = (i + 1) % EXPANDED_KEY_TABLE_SIZE;
            j = (j + 1) % KEY_WORDS_SIZE;
        }

        println!("S = {:08x?}", &S[..]);
        println!("L = {:08x?}", &L[..]);
        S
    }

    pub(crate) fn encrypt(key: Key, plaintext: Block) -> Block {
        let (mut A, mut B) = plaintext;
        println!("A = {:08x?}, B = {:08x?}", A, B);

        let S = expand_key(key);

        A = ops::plus(A,S[0]);
        B = ops::plus(B,S[1]);

        for i in 1..=NUMBER_OF_ROUNDS {
            A = ops::plus(ops::left_rotation(ops::bitwise_xor(A, B), B),S[ 2*i      as usize]);
            B = ops::plus(ops::left_rotation(ops::bitwise_xor(B, A), A),S[(2*i + 1) as usize]);
            println!("A = {:08x?}, B = {:08x?}", A, B);
        }

        (A, B)
    }

    pub(crate) fn decrypt(key: Key, ciphertext: Block) -> Block {
        let (mut A, mut B) = ciphertext;
        println!("A = {:08x?}, B = {:08x?}", A, B);

        let S = expand_key(key);

        for i in (1..=NUMBER_OF_ROUNDS).rev() {
            B = ops::bitwise_xor(ops::right_rotation(ops::minus(B, S[(2*i + 1) as usize]), A), A);
            A = ops::bitwise_xor(ops::right_rotation(ops::minus(A, S[ 2*i      as usize]), B), B);
        }
        B = ops::minus(B, S[1]);
        A = ops::minus(A, S[0]);

        (A, B)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arr_u8_to_u32_all() {
        let bytes = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let words = [0x03020100, 0x07060504, 0x0B0A0908, 0x0F0E0D0C];

        let mut res = [0; 4];
        utils::bytes_to_words(&bytes, &mut res);

        assert_eq!(&words[..], &res[..], "\nExpected\n{:08x?}\nfound\n{:08x?}", &words[..], &res[..]);
    }

    #[test]
    fn arr_u8_to_u32_less() {
        let bytes = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E];
        let words = [0x03020100, 0x07060504, 0x0B0A0908, 0x000E0D0C];

        let mut res = [0; 4];
        utils::bytes_to_words(&bytes, &mut res);

        assert_eq!(&words[..], &res[..], "\nExpected\n{:08x?}\nfound\n{:08x?}", &words[..], &res[..]);
    }

    #[test]
    fn encode_a() {
        let key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let pt  = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let ct  = [0x2D, 0xDC, 0x14, 0x9B, 0xCF, 0x08, 0x8B, 0x9E];
        let res = encrypt_bytes(key, pt);
        assert_eq!(ct, res, "\nExpected\n{:08x?}\nfound\n{:08x?}", ct, res);
    }

    #[test]
    fn encode_c() {
        let key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let pt  = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let ct  = [0xC8, 0xD3, 0xB3, 0xC4, 0x86, 0x70, 0x0C, 0xFA];
        let res = encrypt_bytes(key, pt);
        assert_eq!(ct, res, "\nExpected\n{:08x?}\nfound\n{:08x?}", ct, res);
    }
}
