use std::collections::HashSet;
use crate::structures::{Cache, Compressor, YACC};
use rand::random;

const BUFFER_SIZE: usize = 256;

pub struct VictimProgramYACC {
    cache: YACC, // Probably needs to be RefCell since both attacker and victim will modify
    secret: Vec<u8>,
    buffer_base: u64,
    verbose: bool
}

impl VictimProgramYACC {
    /// Makes a new victim program.
    pub fn new(secret_length: usize, compressor: Compressor, verbose: bool) -> VictimProgramYACC {
        let mut victim = VictimProgramYACC {
            cache: YACC::new(compressor),
            secret: Vec::new(),
            buffer_base: random::<u64>() & 0x0000FFFF_FFFF0000u64,
            verbose
        };
        let mut used_bytes: HashSet<u8> = HashSet::new();
        for i in 0..secret_length {
            let mut byte: u8 = random();
            while byte == 0 || used_bytes.contains(&byte) {byte = random();} // Assume the secret has no zero bytes and only unique bytes
            used_bytes.insert(byte);
            victim.secret.push(byte);
            victim.cache.write_byte(victim.buffer_base + (BUFFER_SIZE - secret_length + i) as u64, byte);
        }
        if victim.verbose {
            println!("Victim has picked the following secret: {:X?}", victim.secret);
        }
        return victim;
    }

    /// Makes a new victim program.
    #[allow(dead_code)]
    pub fn new_with_custom_secret(secret: Vec<u8>, compressor: Compressor, verbose: bool) -> VictimProgramYACC {
        let mut victim = VictimProgramYACC {
            cache: YACC::new(compressor),
            secret,
            buffer_base: random::<u64>() & 0x0000FFFF_FFFF0000u64,
            verbose
        };
        for i in 0..victim.secret.len() {
            victim.cache.write_byte(victim.buffer_base + (BUFFER_SIZE - victim.secret.len() + i) as u64, victim.secret[i]);
        }
        if victim.verbose {
            println!("Victim has picked the following secret: {:X?}", victim.secret);
        }
        return victim;
    }

    /// Writes a byte to the victim's buffer.
    /// Returns false if the index provided lands out of bounds or on top of the victim's secret.
    /// Returns true otherwise, indicating that the write was successful.
    pub fn write_byte(&mut self, index: usize, byte: u8) -> bool {
        if index >= BUFFER_SIZE - self.secret.len() {return false;}
        self.cache.write_byte(self.buffer_base + (index as u64), byte);
        return true;
    }

    /// Reads a byte from the victim's buffer.
    /// Returns None if the index provided lands out of bounds or on top of the victim's secret.
    /// Returns Some with the data if the index is fine.
    pub fn read_byte(&mut self, index: usize) -> Option<u8> {
        if index >= BUFFER_SIZE - self.secret.len() {return None;}
        return Some(self.cache.read_byte(self.buffer_base + index as u64).0);
    }

    /// Returns a reference to the cache, for the attacker to use.
    /// Note: the attacker cannot read the victim's entries directly.
    /// The attacker can only read and write to the attacker's own address space.
    pub fn cache(&mut self) -> &mut YACC {return &mut self.cache;}

    /// Prints out the compressibility of the secret line to the console.
    /// This is purely for debugging and not used by the attack algorithm.
    #[allow(dead_code)]
    pub fn print_compressibility(&self) {
        let c = self.cache.compress_bits((self.buffer_base >> 6) + 3);
        println!("Secret line compressibility: {} bits or {} bytes", c, (c + 7) >> 3);
    }

    /// Prints out the secret line.
    /// This is purely for debugging and not used by the attack algorithm.
    #[allow(dead_code)]
    pub fn print_secret_line(&self) {
        println!("Secret line: {:X?}", self.cache.peek_line((self.buffer_base >> 6) + 3));
    }

    /// Returns whether or not a guess matches the victim's secret.
    /// This function should only be called when the attacker knows the victim's secret.
    pub fn validate_secret(&self, guess: &Vec<u8>) -> bool {
        for i in 0..self.secret.len() {
            if let Some(&b) = guess.get(i) {
                if b != self.secret[i] {return false;}
            } else {return false;}
        }
        return true;
    }
}