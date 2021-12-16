use std::cmp::min;
use std::collections::HashSet;
use crate::structures::{AccessSpeed, ASSOCIATIVITY, Cache};
use crate::victim::VictimProgramYACC;

#[derive(Debug)]
pub struct AttackStats {
    pub success: bool,
    pub secret: Vec<u8>,
    pub guesses_needed: usize,
    pub bytes_written_to_victim: usize,
    pub bytes_read_from_victim: usize,
    pub attacker_cache_lines_loaded: usize,
    pub set_evictions: usize
}

impl AttackStats {
    fn new() -> AttackStats {
        AttackStats {
            success: false,
            secret: Vec::new(),
            guesses_needed: 0,
            bytes_written_to_victim: 0,
            bytes_read_from_victim: 0,
            attacker_cache_lines_loaded: 0,
            set_evictions: 0
        }
    }
}

/// Attacks a victim with the following characteristics:
/// * Secret is 4 bytes and placed at the end of a 256-byte superblock
/// * All other bytes in the superblock can be read/written by the attacker
/// * The compressed cache is YACC w/ C-PACK
/// * The cache associativity is as defined in structures.rs (default: 8)
/// * The cache replacement policy is LRU
#[allow(dead_code)]
pub fn attack_yacc_cpack_4byte_secret(victim: &mut VictimProgramYACC, verbose: bool) -> AttackStats {
    let mut stats = AttackStats::new();
    let mut buffer_state = [0u8;60];

    // Step 1: crack the leading 2 bytes (bytes 2 and 3 of the secret).
    let mut potential_shorts: Vec<u16> = (0x0001..=0xFFFF).collect();
    // Step 1a: eliminate potential leading 2 bytes in groups of 6.
    if verbose {println!("Cracking the leading short...")}
    while potential_shorts.len() > 6 {
        let mut shorts_to_test: Vec<u16> = Vec::new();
        for _ in 0..6 {shorts_to_test.push(potential_shorts.pop().unwrap());}
        let attack_string = make_first_attack_string(&shorts_to_test, &HashSet::new(), 4);
        if prime_and_probe_yacc_lru(victim, &attack_string, &mut buffer_state, &mut stats) {
            potential_shorts = shorts_to_test;
        }
    }
    if verbose {println!("Determined that the leading short is one of the following: {:X?}", potential_shorts.as_slice());}
    // Step 1b: once 6 or fewer candidates are found, find the one that fits.
    let mut maybe_first_short: Option<u16> = None;
    let excludes: HashSet<u16> = potential_shorts.iter().map(|&x|x).collect();
    while !potential_shorts.is_empty() {
        let short_to_test = potential_shorts.pop().unwrap();
        let attack_string = make_first_attack_string(&vec![short_to_test], &excludes, 4);
        if prime_and_probe_yacc_lru(victim, &attack_string, &mut buffer_state, &mut stats) {
            maybe_first_short = Some(short_to_test);
            potential_shorts.clear();
        }
    }
    if maybe_first_short.is_none() {
        // if verbose {
            println!("Attack failed to find the first short");
            victim.print_secret_line();
        // }
        return stats;
    }
    let first_short = maybe_first_short.unwrap();
    if verbose {println!("First short found: {:X?}", first_short);}

    // Step 2: crack the second-to-least significant byte (byte 1 of the secret)
    let maybe_second_byte = crack_second_byte(victim, 4, first_short, &mut buffer_state, &mut stats, verbose);
    if maybe_second_byte.is_none() {
        // if verbose {
            println!("Attack failed to find the second-least byte (the first short is {:X?} though)", first_short);
            victim.print_secret_line();
        // }
        return stats;
    }
    let second_byte = maybe_second_byte.unwrap();
    if verbose {println!("Second byte found: {:X?}", second_byte);}

    // Step 3: crack the least significant byte (byte 0 of the secret)
    let maybe_last_byte = crack_last_byte(victim, 4, first_short, second_byte, &mut buffer_state, &mut stats, verbose);
    if maybe_last_byte.is_none() {
        // if verbose {
            println!("Attack failed to find the last byte (the first short and second byte are {:X?} and {:X?} though)", first_short, second_byte);
            victim.print_secret_line();
        // }
        return stats;
    }
    let last_byte = maybe_last_byte.unwrap();
    if verbose {println!("Last byte found: {:X?}", last_byte);}

    // Step 4: assemble and validate the secret
    let secret = vec![last_byte, second_byte, (first_short & 0xFF) as u8, ((first_short >> 8) & 0xFF) as u8];
    let correct = victim.validate_secret(&secret);
    stats.guesses_needed += 1;
    if verbose {println!("First guess: {:X?}", secret.as_slice());}
    if correct {
        stats.success = true;
        stats.secret = secret;
        if verbose {println!("Guess was correct!")}
    } else if verbose {
        println!("Guess was wrong")
    }
    return stats;
}

fn crack_second_byte(victim: &mut VictimProgramYACC, secret_size: usize, first_short: u16, buffer_state: &mut[u8], stats: &mut AttackStats, verbose: bool) -> Option<u8> {
    let mut potential_second_bytes: Vec<u8> = (0x01..=0xFF).collect();
    if verbose {println!("Cracking the second byte...")}
    let throughput = match secret_size {
        4 => 9,
        8 => 7,
        _ => panic!("Bad secret size")
    };
    while potential_second_bytes.len() > throughput {
        let mut second_bytes_to_test: Vec<u8> = Vec::new();
        for _ in 0..throughput {second_bytes_to_test.push(potential_second_bytes.pop().unwrap());}
        let attack_string = make_second_attack_string(first_short, &second_bytes_to_test, &HashSet::new(), secret_size);
        if prime_and_probe_yacc_lru(victim, &attack_string, buffer_state, stats) {
            potential_second_bytes = second_bytes_to_test;
        }
    }
    if verbose {println!("Determined that the second byte is one of the following: {:X?}", potential_second_bytes.as_slice());}
    let mut maybe_second_byte: Option<u8> = None;
    let excludes: HashSet<u8> = potential_second_bytes.iter().map(|&x|x).collect();
    while !potential_second_bytes.is_empty() {
        let second_byte_to_test = potential_second_bytes.pop().unwrap();
        let attack_string = make_second_attack_string(first_short,&vec![second_byte_to_test], &excludes, secret_size);
        if prime_and_probe_yacc_lru(victim, &attack_string, buffer_state, stats) {
            maybe_second_byte = Some(second_byte_to_test);
            potential_second_bytes.clear();
        }
    }
    return maybe_second_byte;
}

fn crack_last_byte(victim: &mut VictimProgramYACC, secret_size: usize, first_short: u16, second_byte: u8, buffer_state: &mut[u8], stats: &mut AttackStats, verbose: bool) -> Option<u8> {
    let mut potential_last_bytes: Vec<u8> = (0x01..=0xFF).collect();
    if verbose {println!("Cracking the last byte...")}
    let throughput = match secret_size {
        4 => 14,
        8 => 12,
        _ => panic!("Bad secret size")
    };
    while potential_last_bytes.len() > throughput {
        let mut last_bytes_to_test: Vec<u8> = Vec::new();
        for _ in 0..throughput {last_bytes_to_test.push(potential_last_bytes.pop().unwrap());}
        let attack_string = make_third_attack_string(first_short, second_byte, &last_bytes_to_test, &HashSet::new(), secret_size);
        if prime_and_probe_yacc_lru(victim, &attack_string, buffer_state, stats) {
            potential_last_bytes = last_bytes_to_test;
        }
    }
    if verbose {println!("Determined that the last byte is one of the following: {:X?}", potential_last_bytes.as_slice());}
    let mut maybe_last_byte: Option<u8> = None;
    let excludes: HashSet<u8> = potential_last_bytes.iter().map(|&x|x).collect();
    while !potential_last_bytes.is_empty() {
        let last_byte_to_test = potential_last_bytes.pop().unwrap();
        let attack_string = make_third_attack_string(first_short, second_byte,&vec![last_byte_to_test], &excludes, secret_size);
        if prime_and_probe_yacc_lru(victim, &attack_string, buffer_state, stats) {
            maybe_last_byte = Some(last_byte_to_test);
            potential_last_bytes.clear();
        }
    }
    return maybe_last_byte;
}

/// Attacks a victim with the following characteristics:
/// * Secret is 8 bytes and placed at the end of a 256-byte superblock
/// * All other bytes in the superblock can be read/written by the attacker
/// * The compressed cache is YACC w/ C-PACK
/// * The cache associativity is as defined in structures.rs (default: 8)
/// * The cache replacement policy is LRU
#[allow(dead_code)]
pub fn attack_yacc_cpack_8byte_secret(victim: &mut VictimProgramYACC, verbose: bool) -> AttackStats {
    let mut stats = AttackStats::new();
    let mut buffer_state = [0u8;56];

    // Step 1: crack the leading 2 bytes of each secret word (bytes 2 and 3 of the secret).
    let mut potential_shorts: Vec<u16> = (0x0001..=0xFFFF).collect();
    // Step 1a: eliminate potential leading 2 bytes in groups of 6.
    if verbose {println!("Cracking the leading shorts...")}
    let mut shorts_shortlist: Vec<u16> = Vec::new();
    while !potential_shorts.is_empty() {
        let mut shorts_to_test: Vec<u16> = Vec::new();
        for _ in 0..min(5,potential_shorts.len()) {shorts_to_test.push(potential_shorts.pop().unwrap());}
        let attack_string = make_first_attack_string(&shorts_to_test, &HashSet::new(), 8);
        if prime_and_probe_yacc_lru(victim, &attack_string, &mut buffer_state, &mut stats) {
            for s in shorts_to_test {shorts_shortlist.push(s);}
        }
    }
    if verbose {println!("Determined that the leading shorts are two of the following: {:X?}", shorts_shortlist.as_slice());}

    // Step 1b: Find the two shorts in the shortlist that start the two words.
    let mut maybe_short1: Option<u16> = None;
    let mut maybe_short2: Option<u16> = None;
    let excludes: HashSet<u16> = shorts_shortlist.iter().map(|&x|x).collect();
    while !shorts_shortlist.is_empty() && maybe_short2.is_none() {
        let short_to_test = shorts_shortlist.pop().unwrap();
        let attack_string = make_first_attack_string(&vec![short_to_test], &excludes, 8);
        if prime_and_probe_yacc_lru(victim, &attack_string, &mut buffer_state, &mut stats) {
            if maybe_short1.is_none() {maybe_short1 = Some(short_to_test);}
            else {
                maybe_short2 = Some(short_to_test);
                break;
            }
        }
    }
    if maybe_short1.is_none() || maybe_short2.is_none() {
        // if verbose {
        println!("Attack failed to find the first shorts");
        victim.print_secret_line();
        // }
        return stats;
    }
    let short1 = maybe_short1.unwrap();
    let short2 = maybe_short2.unwrap();
    if verbose {println!("First shorts found: {:X?} {:X?}", short1, short2);}

    // Step 2: crack the second-to-least significant bytes (byte 1 of the secret)
    let maybe_second_byte1 = crack_second_byte(victim, 8, short1, &mut buffer_state, &mut stats, verbose);
    let maybe_second_byte2 = crack_second_byte(victim, 8, short2, &mut buffer_state, &mut stats, verbose);
    if maybe_second_byte1.is_none() || maybe_second_byte2.is_none() {
        // if verbose {
        println!("Attack failed to find the second-least bytes (the first shorts are {:X?} and {:X?} though)", short1, short2);
        victim.print_secret_line();
        // }
        return stats;
    }
    let second_byte1 = maybe_second_byte1.unwrap();
    let second_byte2 = maybe_second_byte2.unwrap();
    if verbose {println!("Second bytes found: {:X?} {:X?}", second_byte1, second_byte2);}

    // Step 3: crack the least significant bytes (byte 0 of the secret)
    let maybe_last_byte1 = crack_last_byte(victim, 8, short1, second_byte1, &mut buffer_state, &mut stats, verbose);
    let maybe_last_byte2 = crack_last_byte(victim, 8, short2, second_byte2, &mut buffer_state, &mut stats, verbose);
    if maybe_last_byte1.is_none() || maybe_last_byte2.is_none() {
        // if verbose {
        println!("Attack failed to find the last bytes (the first shorts and second bytes are {:X?} {:X?} {:X?} {:X?} though)", short1, short2, second_byte1, second_byte2);
        victim.print_secret_line();
        // }
        return stats;
    }
    let last_byte1 = maybe_last_byte1.unwrap();
    let last_byte2 = maybe_last_byte2.unwrap();
    if verbose {println!("Last bytes found: {:X?} {:X?}", last_byte1, last_byte2);}

    // Step 4: assemble and validate the secret
    let secret1 = vec![last_byte1, second_byte1, (short1 & 0xFF) as u8, ((short1 >> 8) & 0xFF) as u8, last_byte2, second_byte2, (short2 & 0xFF) as u8, ((short2 >> 8) & 0xFF) as u8];
    let secret2 = vec![last_byte2, second_byte2, (short2 & 0xFF) as u8, ((short2 >> 8) & 0xFF) as u8, last_byte1, second_byte1, (short1 & 0xFF) as u8, ((short1 >> 8) & 0xFF) as u8];
    let correct1 = victim.validate_secret(&secret1);
    let correct2 = victim.validate_secret(&secret2);
    if verbose {
        println!("First guess: {:X?}", secret1.as_slice());
        println!("Second guess (if needed): {:X?}", secret2.as_slice());
    }
    if correct1 { // We'll assume the first secret was guessed first
        stats.success = true;
        stats.secret = secret1;
        stats.guesses_needed += 1;
        if verbose {println!("First guess was correct!")}
    } else if correct2 {
        stats.success = true;
        stats.secret = secret2;
        stats.guesses_needed += 2;
        if verbose {println!("Second guess was correct!")}
    } else if verbose {
        println!("Both guesses were wrong")
    }
    return stats;
}

/// Given a victim and attack string, determines if the attack string makes the victim's secret cache line compressible to 32B.
/// Returns true if 32B compression occurred, false otherwise.
fn prime_and_probe_yacc_lru(victim: &mut VictimProgramYACC, attack_string: &Vec<u8>, buffer_state: &mut [u8], stats: &mut AttackStats) -> bool {
    // Step 1: prime the victim's secret cache line with the attack string (changing as few bytes as needed).
    for i in 0..attack_string.len() {
        if attack_string[i] != buffer_state[i] {
            assert!(victim.write_byte(192 + i, attack_string[i])); // Make sure we're not writing OoB
            buffer_state[i] = attack_string[i];
            stats.bytes_written_to_victim += 1;
        }
    }
    // Step 2: flush all victim lines from the cache
    for i in 0..ASSOCIATIVITY {
        victim.cache().read_byte((i as u64) * 256); // Read from a different superblock each time to prevent compression
        stats.attacker_cache_lines_loaded += 1;
    }
    stats.set_evictions += 1;
    // Step 3: reload the primed secret line and one of the other lines in the superblock (which should be all zeros, very compressible)
    victim.read_byte(192);
    victim.read_byte(0);
    stats.bytes_read_from_victim += 2;
    // Step 4: since we know the replacement algorithm is LRU, there is only a need to check the second-to-least recently used attacker block.
    // The least recently used block was definitely evicted, but the second-to-least might still be present if compression occurred.
    // So, if accessing the second-to-least recently used block is a hit, then compression occurred.
    let time = victim.cache().read_byte(256).1;
    stats.attacker_cache_lines_loaded += 1;
    let success = time == AccessSpeed::HIT;
    // if success {
    //     victim.print_secret_line();
    //     victim.print_compressibility();
    // }
    return success;
}

/// Creates an attack string that helps deduce the upper two bytes in a 4-byte C-PACK word.
/// includes: the set of shorts to target in the attack string. Should be 1-6 shorts for 4B secrets and 1-5 for 8B secrets.
/// excludes: the set of shorts to explicitly avoid targeting in the attack string.
/// secret_size: the size of the secret.
fn make_first_attack_string(includes: &Vec<u16>, excludes: &HashSet<u16>, secret_size: usize) -> Vec<u8> {
    if secret_size == 4 {
        // Words to write: 15
        // Bits to compress to: 224 to 232
        // 224 bits is the minimum needed to make compression to 32B impossible if the last word is incompressible
        // 232 bits is the maximum that allows compression to 32B if the last word compresses to 24 bits using the match-except-last-short rule
        // 6 uncompressed short-testing words can be included (34 compressed bits each)
        // Adding 8 zero words and 1 byte-word takes it up to 226, which is within the bounds
        let mut attack_string: Vec<u8> = Vec::with_capacity(60);
        if includes.len() < 1 || includes.len() > 6 {
            panic!("Bad number of shorts to include")
        }
        for &include in includes { // Push all short-testing words
            attack_string.push(0);
            attack_string.push(0);
            attack_string.push((include & 0xFF) as u8);
            attack_string.push(((include >> 8) & 0xFF) as u8);
        }
        if includes.len() < 6 {
            let mut valid_filler: Vec<u16> = (1u16..=100).filter(|x|!includes.contains(x) && !excludes.contains(x)).rev().collect();
            for _ in 0..(6 - includes.len()) { // Push other short-testing words as filler
                let short = valid_filler.pop().unwrap();
                attack_string.push(0);
                attack_string.push(0);
                attack_string.push((short & 0xFF) as u8);
                attack_string.push(((short >> 8) & 0xFF) as u8);
            }
        }
        // Finally, push one word that's just a zero-extended byte, followed by 8 zero words
        attack_string.push(0xFF);
        for _ in 0..35 {attack_string.push(0);}

        assert_eq!(attack_string.len(), 60);
        return attack_string;
    } else if secret_size == 8 {
        // Words to write: 14
        // Bits to compress to: 190 to 198
        // 190 bits is the minimum needed to make compression to 32B impossible if the last two words are incompressible
        // 198 bits is the max that allows 32B compression if one of the last two words compresses to 24 bits
        // 5 uncompressed short-testing words can be included (34 compressed bits each)
        // Adding 8 zero words and 1 byte-word takes it up to 192, which is within the bounds
        let mut attack_string: Vec<u8> = Vec::with_capacity(56);
        if includes.len() < 1 || includes.len() > 5 {
            panic!("Bad number of shorts to include")
        }
        for &include in includes { // Push all short-testing words
            attack_string.push(0);
            attack_string.push(0);
            attack_string.push((include & 0xFF) as u8);
            attack_string.push(((include >> 8) & 0xFF) as u8);
        }
        if includes.len() < 5 {
            let mut valid_filler: Vec<u16> = (1u16..=100).filter(|x|!includes.contains(x) && !excludes.contains(x)).rev().collect();
            for _ in 0..(5 - includes.len()) { // Push other random short-testing words as filler
                let short = valid_filler.pop().unwrap();
                attack_string.push(0);
                attack_string.push(0);
                attack_string.push((short & 0xFF) as u8);
                attack_string.push(((short >> 8) & 0xFF) as u8);
            }
        }
        // Finally, push one word that's just a zero-extended byte, followed by 8 zero words
        attack_string.push(0xFF);
        for _ in 0..35 {attack_string.push(0);}

        assert_eq!(attack_string.len(), 56);
        return attack_string;
    } else {
        panic!("Bad secret size")
    }
}

/// Creates an attack string that helps deduce the second-to-least significant bit of a 4-byte C-PACK word.
/// short: the upper 2 bytes of the secret
/// includes: the set of bytes to target in the attack string. Should be 1-9 bytes for 4B secrets and 1-7 for 8B secrets.
/// excludes: the set of bytes to explicitly avoid targeting in the attack string.
/// secret_size: the size of the secret.
fn make_second_attack_string(short: u16, includes: &Vec<u8>, excludes: &HashSet<u8>, secret_size: usize) -> Vec<u8> {
    if secret_size == 4 {
        // Words to write: 15
        // Bits to compress to: 234 to 240 (must allow 32B compression when last word compresses to 16 bits, but not when it's 24 bits)
        // One byte-testing word at the front will be uncompressed (34 bits)
        // Following byte-testing words will be compressed due to the match-except-the-last-short rule (24 bits each)
        // 9 byte-testing words can be accommodated including the first one (total of 226 bits)
        // This leaves 6 words which can be all zeros (12 bits for all) which totals 238 bits, within the bounds
        let mut attack_string: Vec<u8> = Vec::with_capacity(60);
        if includes.len() < 1 || includes.len() > 9 {
            panic!("Bad number of bytes to include")
        }
        for &include in includes { // Push all byte-testing words
            attack_string.push(0);
            attack_string.push(include);
            attack_string.push((short & 0xFF) as u8);
            attack_string.push(((short >> 8) & 0xFF) as u8);
        }
        if includes.len() < 9 {
            let mut valid_filler: Vec<u8> = (1u8..=100).filter(|x|!includes.contains(x) && !excludes.contains(x)).rev().collect();
            for _ in 0..(9-includes.len()) { // Push other byte-testing words as filler
                let byte = valid_filler.pop().unwrap();
                attack_string.push(0);
                attack_string.push(byte);
                attack_string.push((short & 0xFF) as u8);
                attack_string.push(((short >> 8) & 0xFF) as u8);
            }
        }
        // Finally, push 6 zero words
        for _ in 0..24 {attack_string.push(0);}

        assert_eq!(attack_string.len(), 60);
        return attack_string;
    } else if secret_size == 8 {
        // Words to write: 14
        // Bits to compress to: 200 to 206 (must allow 32B compression when words compress to 34 and 16 bits, but not 34 and 24 bits)
        // One byte-testing word at the front will be uncompressed (34 bits)
        // Following byte-testing words will be compressed due to the match-except-the-last-short rule (24 bits each)
        // 7 byte-testing words can be accommodated including the first one (total of 178 bits)
        // This leaves 7 words which can be 1 zero-extended byte and 6 zero bytes to total 202 bits
        let mut attack_string: Vec<u8> = Vec::with_capacity(56);
        if includes.len() < 1 || includes.len() > 7 {
            panic!("Bad number of bytes to include")
        }
        for &include in includes { // Push all byte-testing words
            attack_string.push(0);
            attack_string.push(include);
            attack_string.push((short & 0xFF) as u8);
            attack_string.push(((short >> 8) & 0xFF) as u8);
        }
        if includes.len() < 7 {
            let mut valid_filler: Vec<u8> = (1u8..=100).filter(|x|!includes.contains(x) && !excludes.contains(x)).rev().collect();
            for _ in 0..(7-includes.len()) { // Push other byte-testing words as filler
                let byte = valid_filler.pop().unwrap();
                attack_string.push(0);
                attack_string.push(byte);
                attack_string.push((short & 0xFF) as u8);
                attack_string.push(((short >> 8) & 0xFF) as u8);
            }
        }
        // Finally, push a zero-extended-byte word and 6 zero words
        attack_string.push(0xFF);
        for _ in 0..27 {attack_string.push(0);}

        assert_eq!(attack_string.len(), 56);
        return attack_string;
    } else {
        panic!("Bad secret size")
    }
}

/// Creates an attack string that helps deduce the least significant bit of a 4-byte C-PACK word.
/// short: the upper 2 bytes of the secret
/// second_byte: the second-to-least significant byte of the secret
/// includes: the set of bytes to target in the attack string. Should be 1-14 bytes for 4B secrets and 1-12 for 8B secrets.
/// excludes: the set of bytes to explicitly avoid targeting in the attack string.
/// secret_size: the size of the secret.
fn make_third_attack_string(short: u16, second_byte: u8, includes: &Vec<u8>, excludes: &HashSet<u8>, secret_size: usize) -> Vec<u8> {
    if secret_size == 4 {
        // Words to write: 15
        // Bits to compress to: 242 to 250 (must allow 32B compression when last word compresses to 6 bits, but not when it's 16 bits)
        // One byte-testing word at the front will be uncompressed (34 bits)
        // Following byte-testing words will be compressed due to the match-except-the-last-byte rule (16 bits each)
        // 14 byte-testing words can be accommodated including the first one (total of 242 bits)
        // This leaves 1 word which can be all zeros, bringing the total to 244, within the bounds.
        let mut attack_string: Vec<u8> = Vec::with_capacity(60);
        if includes.len() < 1 || includes.len() > 14 {
            panic!("Bad number of bytes to include")
        }
        for &include in includes { // Push all byte-testing words
            attack_string.push(include);
            attack_string.push(second_byte);
            attack_string.push((short & 0xFF) as u8);
            attack_string.push(((short >> 8) & 0xFF) as u8);
        }
        if includes.len() < 14 {
            let mut valid_filler: Vec<u8> = (1u8..=100).filter(|x|!includes.contains(x) && !excludes.contains(x)).rev().collect();
            for _ in 0..(14-includes.len()) { // Push other random byte-testing words as filler
                let first_byte = valid_filler.pop().unwrap();
                attack_string.push(first_byte);
                attack_string.push(second_byte);
                attack_string.push((short & 0xFF) as u8);
                attack_string.push(((short >> 8) & 0xFF) as u8);
            }
        }
        // Finally, push a zero word
        for _ in 0..4 {attack_string.push(0);}

        assert_eq!(attack_string.len(), 60);
        return attack_string;
    } else if secret_size == 8 {
        // Words to write: 14
        // Bits to compress to: 208 to 216 (must allow 32B compression when words compress to 34 and 6, but not 34 and 16)
        // One byte-testing word at the front will be uncompressed (34 bits)
        // Following byte-testing words will be compressed due to the match-except-the-last-byte rule (16 bits each)
        // 12 byte-testing words can be accommodated including the first one (total of 210 bits)
        // This leaves 2 words which can be all zeros, bringing the total to 214, within the bounds.
        let mut attack_string: Vec<u8> = Vec::with_capacity(56);
        if includes.len() < 1 || includes.len() > 12 {
            panic!("Bad number of bytes to include")
        }
        for &include in includes { // Push all byte-testing words
            attack_string.push(include);
            attack_string.push(second_byte);
            attack_string.push((short & 0xFF) as u8);
            attack_string.push(((short >> 8) & 0xFF) as u8);
        }
        if includes.len() < 12 {
            let mut valid_filler: Vec<u8> = (1u8..=100).filter(|x|!includes.contains(x) && !excludes.contains(x)).rev().collect();
            for _ in 0..(12-includes.len()) { // Push other random byte-testing words as filler
                let first_byte = valid_filler.pop().unwrap();
                attack_string.push(first_byte);
                attack_string.push(second_byte);
                attack_string.push((short & 0xFF) as u8);
                attack_string.push(((short >> 8) & 0xFF) as u8);
            }
        }
        // Finally, push 2 zero words
        for _ in 0..8 {attack_string.push(0);}

        assert_eq!(attack_string.len(), 56);
        return attack_string;
    } else {
        panic!("Bad secret size")
    }
}