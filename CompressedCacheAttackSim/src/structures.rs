use std::collections::HashMap;
use std::collections::HashSet;

pub const ASSOCIATIVITY: usize = 8;

pub fn cpack_bits(line: &[u8;64]) -> u64 {
    let mut history: HashSet<u32> = HashSet::new();
    let mut no_byte_history: HashSet<u32> = HashSet::new();
    let mut no_short_history: HashSet<u32> = HashSet::new();
    let mut bits = 0u64;
    for i in 0..16 {
        // Little-endian conversion
        let word = (line[i*4] as u32) | ((line[i*4+1] as u32) << 8) | ((line[i*4+2] as u32) << 16) | ((line[i*4+3] as u32) << 24);
        if word == 0 {bits += 2}
        else if history.contains(&word) {bits += 6;}
        else if word & 0x0FF == word {bits += 12;}
        else if no_byte_history.contains(&(word & 0xFFFFFF00)) {bits += 16;}
        else if no_short_history.contains(&(word & 0xFFFF0000)) {bits += 24;}
        else {bits += 34;}
        history.insert(word);
        no_byte_history.insert(word & 0xFFFFFF00);
        no_short_history.insert(word & 0xFFFF0000);
    }
    return bits;
}

pub fn cpack_bytes(line: &[u8;64]) -> u64 {
    return (cpack_bits(line) + 7) / 8;
}

#[derive(PartialEq, Clone, Copy)]
pub enum AccessSpeed {HIT, MISS}

pub trait Cache {

    /// Reads a byte from the cache. Returns the byte, along with whether there was a hit or miss.
    /// byte_addr is the address of the byte.
    fn read_byte(&mut self, byte_addr: u64) -> (u8, AccessSpeed);

    /// Writes a byte to the cache. No timing data is returned, but the necessary line is loaded in.
    /// byte_addr is the address of the byte. data is the byte to be written.
    fn write_byte(&mut self, byte_addr: u64, data: u8);
}

const EMPTY_LINE: [u8; 64] = [0u8;64];

struct MainMemory {
    memory_map: HashMap<u64, [u8;64]>
}

impl MainMemory {
    fn new() -> MainMemory {
        MainMemory {
            memory_map: HashMap::new()
        }
    }

    /// Gets a reference to a line.
    /// If line_addr does not yet exist, a pointer to a default EMPTY_LINE is returned.
    fn get_line(&self, line_addr: u64) -> &[u8; 64] {
        self.memory_map.get(&line_addr).unwrap_or(&EMPTY_LINE)
    }
    /// Gets a mutable reference to a line.
    /// If line_addr does not yet exist, a new all-zeros line is created.
    fn get_line_mut(&mut self, line_addr: u64) -> &mut[u8; 64] {
        if !self.memory_map.contains_key(&line_addr) {
            self.memory_map.insert(line_addr, EMPTY_LINE.clone());
        }
        return self.memory_map.get_mut(&line_addr).expect("empty line didn't get inserted?");
    }
}

#[derive(PartialEq, Clone, Copy)]
enum YACCEntry {
    INVALID,
    SINGLE {line_addr: u64},
    DOUBLE {sb_addr: u64, block0: u64, block1: u64},
    TRIO {sb_addr: u64, block0: u64, block1: u64, block2: u64},
    QUAD {sb_addr: u64}
}

#[derive(PartialEq, Clone, Copy)]
pub enum Compressor {
    CPACK
}

pub struct YACC {
    entries: [YACCEntry;ASSOCIATIVITY],
    lru_state: Vec<usize>,
    memory: MainMemory,
    compressor: Compressor
}

impl YACC {
    pub fn new(comp: Compressor) -> YACC {
        YACC {
            entries: [YACCEntry::INVALID; 8],
            lru_state: Vec::new(),
            memory: MainMemory::new(),
            compressor: comp
        }
    }

    /// Checks whether a line is cached.
    /// Returns the index in the entries array where the line is located, if it is cached.
    fn is_line_cached(&self, requested_line_addr: u64) -> Option<usize> {
        let requested_sb_addr = requested_line_addr >> 2;
        let requested_block_number = requested_line_addr & 0b011;
        for i in 0..ASSOCIATIVITY {
            if match self.entries[i] {
                YACCEntry::SINGLE { line_addr } => line_addr == requested_line_addr,
                YACCEntry::DOUBLE { sb_addr, block0, block1 } => sb_addr == requested_sb_addr && (
                    block0 == requested_block_number || block1 == requested_block_number
                ),
                YACCEntry::TRIO { sb_addr, block0, block1, block2 } => sb_addr == requested_sb_addr && (
                    block0 == requested_block_number || block1 == requested_block_number || block2 == requested_block_number
                ),
                YACCEntry::QUAD { sb_addr } => sb_addr == requested_sb_addr,
                YACCEntry::INVALID => false
            } {
                return Some(i);
            }
        }
        return None;
    }

    /// Returns the compressed size of a line.
    pub fn compress_bytes(&self, line_addr: u64) -> u64 {
        let line = self.memory.get_line(line_addr);
        return match self.compressor {
            Compressor::CPACK => cpack_bytes(line)
        };
    }

    /// Returns the compressed size of a line, in bits.
    #[allow(dead_code)]
    pub fn compress_bits(&self, line_addr: u64) -> u64 {
        let line = self.memory.get_line(line_addr);
        return match self.compressor {
            Compressor::CPACK => cpack_bits(line)
        };
    }

    /// Returns a line directly from memory. For debug purposes only.
    #[allow(dead_code)]
    pub fn peek_line(&self, line_addr: u64) -> &[u8;64] {
        return self.memory.get_line(line_addr);
    }

    /// Accesses a line. Returns whether or not the access was a hit.
    /// This also updates the LRU state.
    fn access(&mut self, requested_line_addr: u64) -> AccessSpeed {
        let requested_sb_addr = requested_line_addr >> 2;
        let requested_sb_number = requested_line_addr & 0b011;

        // Step 1: if the line is already there, return immediately.
        if let Some(i) = self.is_line_cached(requested_line_addr) {
            self.update_lru_state(i);
            return AccessSpeed::HIT;
        }

        // Step 2: search for empty slots or slots that can be compressed.
        let mut empty_found: Option<usize> = None;
        let mut single_found: Option<usize> = None;
        let mut double_found: Option<usize> = None;
        let mut trio_found: Option<usize> = None;
        let compressed_size = self.compress_bytes(requested_line_addr);
        for i in 0..self.entries.len() {
            match self.entries[i] {
                YACCEntry::INVALID => {
                    empty_found = Some(i);
                },
                YACCEntry::SINGLE {line_addr} => {
                    if (line_addr >> 2) == requested_sb_addr && compressed_size <= 32 && self.compress_bytes(line_addr) <= 32 {
                        single_found = Some(i);
                    }
                },
                YACCEntry::DOUBLE {sb_addr, block0, block1} => {
                    if sb_addr == requested_sb_addr && compressed_size <= 16
                        && self.compress_bytes((sb_addr << 2) | block0) <= 16
                        && self.compress_bytes((sb_addr << 2) | block1) <= 16 {
                        double_found = Some(i);
                    }
                },
                YACCEntry::TRIO {sb_addr, block0:_, block1:_, block2:_} => {
                    if sb_addr == requested_sb_addr && compressed_size <= 16 { // No need to check compressibility of preexisting blocks
                        trio_found = Some(i);
                        break; // This is the best option, so break immediately
                    }
                },
                YACCEntry::QUAD {sb_addr: _} => ()
            }
        }

        // Step 3: upgrade the slot that was found.
        if let Some(i) = trio_found {
            self.entries[i] = YACCEntry::QUAD {sb_addr: requested_sb_addr};
            self.update_lru_state(i);
            return AccessSpeed::MISS;
        }
        if let Some(i) = double_found {
            let (b0, b1) = match self.entries[i] {
                YACCEntry::DOUBLE { sb_addr: _, block0, block1} => (block0, block1),
                _ => unreachable!()
            };
            self.entries[i] = YACCEntry::TRIO {
                sb_addr: requested_sb_addr,
                block0: b0,
                block1: b1,
                block2: requested_sb_number
            };
            self.update_lru_state(i);
            return AccessSpeed::MISS;
        }
        if let Some(i) = single_found {
            let b0 = match self.entries[i] {
                YACCEntry::SINGLE {line_addr} => line_addr & 0b011,
                _ => unreachable!()
            };
            self.entries[i] = YACCEntry::DOUBLE {
                sb_addr: requested_sb_addr,
                block0: b0,
                block1: requested_sb_number
            };
            self.update_lru_state(i);
            return AccessSpeed::MISS;
        }
        if let Some(i) = empty_found {
            self.entries[i] = YACCEntry::SINGLE {line_addr: requested_line_addr};
            self.update_lru_state(i);
            return AccessSpeed::MISS;
        }

        // Step 4: evict some space for the new line, then insert it.
        let freed_index = self.lru_state[0];
        self.entries[freed_index] = YACCEntry::SINGLE {line_addr: requested_line_addr};
        self.update_lru_state(freed_index);
        return AccessSpeed::MISS;
    }

    /// Removes a line from the cache so that it can be re-inserted properly.
    /// This function is designed to quickly take out the line, without computing compressibilities.
    fn remove_line(&mut self, modified_line: u64) {
        let modified_sb = modified_line >> 2;
        let modified_block = modified_line & 0b11;
        for i in 0..ASSOCIATIVITY {
            let mut replacement: Option<YACCEntry> = None;
            match self.entries[i] {
                YACCEntry::SINGLE {line_addr} => {
                    if line_addr == modified_line {
                        replacement = Some(YACCEntry::INVALID);
                    }
                },
                YACCEntry::DOUBLE {sb_addr, block0, block1} => {
                    if modified_sb == sb_addr {
                        if modified_block == block0 {
                            replacement = Some(YACCEntry::SINGLE {line_addr: (sb_addr << 2) | block1});
                        } else if modified_block == block1 {
                            replacement = Some(YACCEntry::SINGLE {line_addr: (sb_addr << 2) | block0});
                        }
                    }
                },
                YACCEntry::TRIO {sb_addr, block0, block1, block2} => {
                    if modified_sb == sb_addr {
                        if modified_block == block0 {
                            replacement = Some(YACCEntry::DOUBLE {sb_addr, block0: block2, block1});
                        } else if modified_block == block1 {
                            replacement = Some(YACCEntry::DOUBLE {sb_addr, block0, block1: block2});
                        } else if modified_block == block2 {
                            replacement = Some(YACCEntry::DOUBLE {sb_addr, block0, block1});
                        }
                    }
                },
                YACCEntry::QUAD {sb_addr} => {
                    if modified_sb == sb_addr {
                        let remnants: Vec<u64> = (0..=3).filter(|&x| x != modified_block).collect();
                        replacement = Some(YACCEntry::TRIO {sb_addr, block0: remnants[0], block1: remnants[1], block2: remnants[2]});
                    }
                },
                _ => ()
            }
            if let Some(rep) = replacement {
                self.entries[i] = rep;
                return;
            }
        }
    }

    /// Bumps an index to the back of the LRU list so that it is the most recently accessed.
    fn update_lru_state(&mut self, accessed_index: usize) {
        self.lru_state = self.lru_state.iter().filter_map(|&x| if x != accessed_index {Some(x)} else {None}).collect();
        self.lru_state.push(accessed_index);
    }
}

impl Cache for YACC {
    fn read_byte(&mut self, byte_addr: u64) -> (u8, AccessSpeed) {
        let requested_line_addr = byte_addr >> 6;
        let requested_byte_offset = (byte_addr & 0b0111111) as usize;
        let speed = self.access(requested_line_addr);
        return (self.memory.get_line(requested_line_addr)[requested_byte_offset],speed);
    }

    fn write_byte(&mut self, byte_addr: u64, data: u8) {
        let requested_line_addr = byte_addr >> 6;
        let requested_byte_offset = (byte_addr & 0b0111111) as usize;
        self.memory.get_line_mut(requested_line_addr)[requested_byte_offset] = data;
        self.remove_line(requested_line_addr);
        self.access(requested_line_addr);
    }
}