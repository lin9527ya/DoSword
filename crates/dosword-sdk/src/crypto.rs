//! 现代流密码算法自实现（不依赖外部加密库）：
//! - ChaCha20：RFC 8439，256 位密钥 / 96 位 nonce / 32 位计数器
//! - Rabbit：RFC 4503（eSTREAM 最终推荐），128 位密钥 / 64 位 IV
//!
//! PHP 5+ 侧有完全对应的纯实现（stub 内嵌），两端用官方测试向量互验。

fn le32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn be32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

// ---------------------------------------------------------------------------
// ChaCha20
// ---------------------------------------------------------------------------

fn chacha_quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

/// ChaCha20 块函数：输入 32 字节密钥 / 32 位计数器 / 12 字节 nonce，输出 64 字节密钥流块。
pub fn chacha20_block(key: &[u8], counter: u32, nonce: &[u8]) -> [u8; 64] {
    assert!(key.len() == 32 && nonce.len() == 12);
    let mut state = [0u32; 16];
    state[0] = 0x6170_7865;
    state[1] = 0x3320_646e;
    state[2] = 0x7962_2d32;
    state[3] = 0x6b20_6574;
    // 长度已断言为 4 的倍数，as_chunks 保证无余数（相比 chunks_exact 不产生尾部残片）
    let (key_words, _) = key.as_chunks::<4>();
    for (i, chunk) in key_words.iter().enumerate() {
        state[4 + i] = le32(chunk);
    }
    state[12] = counter;
    let (nonce_words, _) = nonce.as_chunks::<4>();
    for (i, chunk) in nonce_words.iter().enumerate() {
        state[13 + i] = le32(chunk);
    }
    let initial = state;
    for _ in 0..10 {
        chacha_quarter_round(&mut state, 0, 4, 8, 12);
        chacha_quarter_round(&mut state, 1, 5, 9, 13);
        chacha_quarter_round(&mut state, 2, 6, 10, 14);
        chacha_quarter_round(&mut state, 3, 7, 11, 15);
        chacha_quarter_round(&mut state, 0, 5, 10, 15);
        chacha_quarter_round(&mut state, 1, 6, 11, 12);
        chacha_quarter_round(&mut state, 2, 7, 8, 13);
        chacha_quarter_round(&mut state, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for (i, word) in state.iter().enumerate() {
        let w = word.wrapping_add(initial[i]);
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

/// 用 ChaCha20 密钥流 XOR 加解密（`counter_start` 起连续块）。
pub fn chacha20_xor(key: &[u8], nonce: &[u8], counter_start: u32, input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut counter = counter_start;
    let mut offset = 0usize;
    while offset < input.len() {
        let block = chacha20_block(key, counter, nonce);
        for byte in block.iter() {
            if offset >= input.len() {
                break;
            }
            out.push(input[offset] ^ byte);
            offset += 1;
        }
        counter = counter.wrapping_add(1);
    }
    out
}

// ---------------------------------------------------------------------------
// Rabbit
// ---------------------------------------------------------------------------

const RABBIT_A: [u32; 8] = [
    0x4D34_D34D,
    0xD34D_34D3,
    0x34D3_4D34,
    0x4D34_D34D,
    0xD34D_34D3,
    0x34D3_4D34,
    0x4D34_D34D,
    0xD34D_34D3,
];

#[derive(Clone)]
struct RabbitState {
    x: [u32; 8],
    c: [u32; 8],
    carry: u64,
}

impl RabbitState {
    fn new(key: &[u8]) -> Self {
        assert!(key.len() == 16);
        // RFC 4503 §2.3：key 按 OS2IP 大端整数，K0 = K[15..0]（最低 16 位 = 末尾 2 字节），
        // Ki 依次向前取 2 字节（每 2 字节大端）
        let mut k = [0u16; 8];
        for i in 0..8 {
            k[i] = ((key[14 - 2 * i] as u16) << 8) | key[15 - 2 * i] as u16;
        }
        let mut s = RabbitState {
            x: [0; 8],
            c: [0; 8],
            carry: 0,
        };
        for j in 0..8 {
            if j % 2 == 0 {
                s.x[j] = ((k[(j + 1) % 8] as u32) << 16) | (k[j] as u32);
                s.c[j] = ((k[(j + 4) % 8] as u32) << 16) | (k[(j + 5) % 8] as u32);
            } else {
                s.x[j] = ((k[(j + 5) % 8] as u32) << 16) | (k[(j + 4) % 8] as u32);
                s.c[j] = ((k[j] as u32) << 16) | (k[(j + 1) % 8] as u32);
            }
        }
        for _ in 0..4 {
            s.counter_update();
            s.next_state();
        }
        for j in 0..8 {
            s.c[j] ^= s.x[(j + 4) % 8];
        }
        s
    }

    fn iv_setup(&mut self, iv: &[u8]) {
        assert!(iv.len() == 8);
        // RFC 4503 §2.4：IV 为 OS2IP 大端 64 位整数；IV[31..0] = 后 4 字节，IV[63..32] = 前 4 字节
        let iv0 = be32(&iv[4..8]);
        let iv1 = be32(&iv[0..4]);
        // C1/C5 ^= (IV[63..48] || IV[31..16])；C3/C7 ^= (IV[47..32] || IV[15..0])
        let mix_high = ((iv1 >> 16) << 16) | ((iv0 >> 16) & 0xFFFF);
        let mix_low = ((iv1 & 0xFFFF) << 16) | (iv0 & 0xFFFF);
        self.c[0] ^= iv0;
        self.c[1] ^= mix_high;
        self.c[2] ^= iv1;
        self.c[3] ^= mix_low;
        self.c[4] ^= iv0;
        self.c[5] ^= mix_high;
        self.c[6] ^= iv1;
        self.c[7] ^= mix_low;
        for _ in 0..4 {
            self.counter_update();
            self.next_state();
        }
    }

    fn counter_update(&mut self) {
        for (c, a) in self.c.iter_mut().zip(RABBIT_A.iter()) {
            let t = *c as u64 + *a as u64 + self.carry;
            self.carry = t >> 32;
            *c = (t & 0xFFFF_FFFF) as u32;
        }
    }

    fn g(u: u32, v: u32) -> u32 {
        let s = (u.wrapping_add(v)) as u64;
        let sq = s.wrapping_mul(s);
        (sq as u32) ^ ((sq >> 32) as u32)
    }

    fn next_state(&mut self) {
        let g: Vec<u32> = (0..8).map(|j| Self::g(self.x[j], self.c[j])).collect();
        let rot16 = |v: u32| v.rotate_left(16);
        let rot8 = |v: u32| v.rotate_left(8);
        let (g0, g1, g2, g3, g4, g5, g6, g7) = (g[0], g[1], g[2], g[3], g[4], g[5], g[6], g[7]);
        let x = [
            g0.wrapping_add(rot16(g7)).wrapping_add(rot16(g6)),
            g1.wrapping_add(rot8(g0)).wrapping_add(g7),
            g2.wrapping_add(rot16(g1)).wrapping_add(rot16(g0)),
            g3.wrapping_add(rot8(g2)).wrapping_add(g1),
            g4.wrapping_add(rot16(g3)).wrapping_add(rot16(g2)),
            g5.wrapping_add(rot8(g4)).wrapping_add(g3),
            g6.wrapping_add(rot16(g5)).wrapping_add(rot16(g4)),
            g7.wrapping_add(rot8(g6)).wrapping_add(g5),
        ];
        self.x = x;
    }

    fn extract_block(&self) -> [u8; 16] {
        let words = [
            (self.x[0] & 0xFFFF) ^ (self.x[5] >> 16),
            (self.x[0] >> 16) ^ (self.x[3] & 0xFFFF),
            (self.x[2] & 0xFFFF) ^ (self.x[7] >> 16),
            (self.x[2] >> 16) ^ (self.x[5] & 0xFFFF),
            (self.x[4] & 0xFFFF) ^ (self.x[1] >> 16),
            (self.x[4] >> 16) ^ (self.x[7] & 0xFFFF),
            (self.x[6] & 0xFFFF) ^ (self.x[3] >> 16),
            (self.x[6] >> 16) ^ (self.x[1] & 0xFFFF),
        ];
        let mut out = [0u8; 16];
        // 输出 16 位块按逆序写入（RFC 4503 位标号与字节流顺序相反，以官方向量校准）
        for (i, word) in words.iter().enumerate() {
            out[(7 - i) * 2] = ((word >> 8) & 0xFF) as u8;
            out[(7 - i) * 2 + 1] = (word & 0xFF) as u8;
        }
        out
    }

    /// 生成 `out.len()` 字节密钥流（内部持续推进）。
    fn keystream(&mut self, out: &mut [u8]) {
        let mut offset = 0usize;
        while offset < out.len() {
            self.counter_update();
            self.next_state();
            let block = self.extract_block();
            for byte in block.iter() {
                if offset >= out.len() {
                    break;
                }
                out[offset] = *byte;
                offset += 1;
            }
        }
    }
}

/// Rabbit 密钥流 XOR 加解密（`skip` 字节偏移后开始，用于请求/响应密钥流分离）。
pub fn rabbit_xor(key: &[u8], iv: &[u8], skip: usize, input: &[u8]) -> Vec<u8> {
    let mut state = RabbitState::new(key);
    state.iv_setup(iv);
    let mut keystream = vec![0u8; skip + input.len()];
    state.keystream(&mut keystream);
    keystream
        .iter()
        .skip(skip)
        .zip(input)
        .map(|(k, b)| b ^ k)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn chacha20_rfc8439_block_vector() {
        // RFC 8439 §2.3.2：key=00..1f, nonce=000000090000004a00000000, counter=1
        let key = (0u8..32).collect::<Vec<u8>>();
        let nonce = hex("000000090000004a00000000");
        let block = chacha20_block(&key, 1, &nonce);
        let expect = hex(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e\
             d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
        );
        assert_eq!(block.to_vec(), expect, "RFC 8439 ChaCha20 块向量不符");
    }

    #[test]
    fn chacha20_rfc8439_cipher_vector() {
        // RFC 8439 §2.4.2：counter 起点 1，Ladies and Gentlemen 明文
        let key = (0u8..32).collect::<Vec<u8>>();
        let nonce = hex("000000000000004a00000000");
        let plaintext = hex(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66\
                 202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e6520\
                 74697020666f7220746865206675747572652c2073756e73637265656e20776f756c6420\
                 62652069742e",
        );
        let cipher = chacha20_xor(&key, &nonce, 1, &plaintext);
        let expect = hex(
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b\
             f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8\
             07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736\
             5af90bbf74a35be6b40b8eedf2785e42874d",
        );
        assert_eq!(cipher, expect, "RFC 8439 ChaCha20 加密向量不符");
    }

    #[test]
    fn rabbit_rfc4503_no_iv_vector() {
        // RFC 4503 §A.1：key=0 无 IV setup，前三块
        let key = [0u8; 16];
        let mut state = RabbitState::new(&key);
        let mut ks = vec![0u8; 48];
        state.keystream(&mut ks);
        let expect = hex("b15754f036a5d6ecf56b45261c4af702\
             88e8d815c59c0c397b696c4789c68aa7\
             f416a1c3700cd451da68d1881673d696");
        assert_eq!(ks, expect, "RFC 4503 Rabbit 无 IV 向量不符");
    }

    #[test]
    fn rabbit_rfc4503_key_vector() {
        // RFC 4503 §A.1：key=912813292e3d36fe3bfc62f1dc51c3ac
        let key = hex("912813292e3d36fe3bfc62f1dc51c3ac");
        let mut state = RabbitState::new(&key);
        let mut ks = vec![0u8; 16];
        state.keystream(&mut ks);
        let expect = hex("3d2df3c83ef627a1e97fc38487e2519c");
        assert_eq!(ks, expect, "RFC 4503 Rabbit 密钥向量不符");
    }

    #[test]
    fn rabbit_rfc4503_iv_vector() {
        // RFC 4503 §A.2：key=0, iv=0 与 iv=c373f575c1267e59
        let key = [0u8; 16];
        let iv = [0u8; 8];
        let mut ks = rabbit_xor(&key, &iv, 0, &[0u8; 16]);
        assert_eq!(
            ks,
            hex("c6a7275ef85495d87ccd5d376705b7ed"),
            "RFC 4503 Rabbit IV=0 向量不符"
        );
        let iv2 = hex("c373f575c1267e59");
        ks = rabbit_xor(&key, &iv2, 0, &[0u8; 16]);
        assert_eq!(
            ks,
            hex("1fcd4eb9580012e2e0dccc9222017d6d"),
            "RFC 4503 Rabbit IV 向量不符"
        );
    }

    #[test]
    fn rabbit_skip_offset_matches_continuous() {
        // 响应密钥流偏移验证：skip=64 后与连续生成第 65 字节起一致
        let key = [7u8; 16];
        let iv = [9u8; 8];
        let head = rabbit_xor(&key, &iv, 0, &[0u8; 80]);
        let tail = rabbit_xor(&key, &iv, 64, &[0u8; 16]);
        assert_eq!(&head[64..], &tail[..], "Rabbit skip 偏移不一致");
    }
}
