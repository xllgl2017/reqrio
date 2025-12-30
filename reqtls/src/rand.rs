use bytemuck::{Pod, Zeroable};
use p256::elliptic_curve::rand_core::{CryptoRng, RngCore};
use std::cell::RefCell;

#[derive(Clone)]
pub struct Random {
    state: [u32; 16],
    buffer: [u32; 16],
    index: usize,
}

impl Random {
    #[inline(always)]
    fn new() -> Self {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("OS RNG failed");

        let mut state = [0u32; 16];

        // ChaCha constants
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        // Key
        for i in 0..8 {
            state[4 + i] = u32::from_le_bytes([
                seed[i * 4],
                seed[i * 4 + 1],
                seed[i * 4 + 2],
                seed[i * 4 + 3],
            ]);
        }

        // Counter + nonce
        state[12] = 0;
        state[13] = 0;
        state[14] = 0;
        state[15] = 0;

        Self {
            state,
            buffer: [0; 16],
            index: 16,
        }
    }

    #[inline]
    fn refill(&mut self) {
        self.buffer = self.state;

        for _ in 0..4 { // ChaCha8 = 4 double-rounds
            quarter_round(&mut self.buffer, 0, 4, 8, 12);
            quarter_round(&mut self.buffer, 1, 5, 9, 13);
            quarter_round(&mut self.buffer, 2, 6, 10, 14);
            quarter_round(&mut self.buffer, 3, 7, 11, 15);

            quarter_round(&mut self.buffer, 0, 5, 10, 15);
            quarter_round(&mut self.buffer, 1, 6, 11, 12);
            quarter_round(&mut self.buffer, 2, 7, 8, 13);
            quarter_round(&mut self.buffer, 3, 4, 9, 14);
        }

        for i in 0..16 {
            self.buffer[i] = self.buffer[i].wrapping_add(self.state[i]);
        }

        // counter++
        self.state[12] = self.state[12].wrapping_add(1);
        self.index = 0;
    }
}
#[inline]
fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(16);

    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(12);

    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(8);

    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(7);
}

pub struct CryptRand {
    rng: RefCell<Random>,
}

impl CryptRand {
    pub fn new() -> CryptRand {
        CryptRand {
            rng: RANDOM.with(|c| c.clone())
        }
    }
}

impl RngCore for CryptRand {
    #[inline]
    fn next_u32(&mut self) -> u32 {
        let mut rng = self.rng.borrow_mut();
        if rng.index >= 16 {
            rng.refill();
        }
        let v = rng.buffer[rng.index];
        rng.index += 1;
        v
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        let lo = self.next_u32() as u64;
        let hi = self.next_u32() as u64;
        lo | (hi << 32)
    }

    #[inline]
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        let mut i = 0;
        let len = dst.len();

        while i + 4 <= len {
            dst[i..i + 4].copy_from_slice(&self.next_u32().to_le_bytes());
            i += 4;
        }

        if i < len {
            let v = self.next_u32().to_le_bytes();
            dst[i..].copy_from_slice(&v[..len - i]);
        }
    }
}

impl CryptoRng for CryptRand {}


pub fn random<T: RandomValue>() -> T {
    let mut rng = CryptRand::new();
    T::random(&mut rng)
}

thread_local! {
    static RANDOM: RefCell<Random> = RefCell::new(Random::new());
}


pub trait RandomValue {
    fn random(rng: &mut CryptRand) -> Self;
}

impl RandomValue for f32 {
    #[inline(always)]
    fn random(rng: &mut CryptRand) -> f32 {
        let mut res = 0.0;
        rng.fill_bytes(bytemuck::bytes_of_mut(&mut res));
        res
    }
}

impl RandomValue for f64 {
    #[inline(always)]
    fn random(rng: &mut CryptRand) -> f64 {
        let mut res = 0.0;
        rng.fill_bytes(bytemuck::bytes_of_mut(&mut res));
        res
    }
}


impl<T, const N: usize> RandomValue for [T; N]
where
    T: Pod + Zeroable,
{
    #[inline(always)]
    fn random(rng: &mut CryptRand) -> [T; N] {
        let mut res = [T::zeroed(); N];
        let bytes: &mut [u8] = bytemuck::cast_slice_mut(&mut res);
        rng.fill_bytes(bytes);
        res
    }
}