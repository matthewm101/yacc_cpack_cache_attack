use crate::attacker::{attack_yacc_cpack_4byte_secret, attack_yacc_cpack_8byte_secret, AttackStats};
use crate::structures::Compressor;
use crate::victim::VictimProgramYACC;
use rayon::prelude::*;

mod structures;
mod victim;
mod attacker;

fn main() {
    simulate_4byte_attacks();
    //simulate_8byte_attacks();
}

#[allow(dead_code)]
fn test_4_byte_attack() {
    let mut victim = VictimProgramYACC::new(4, Compressor::CPACK, true);
    let results = attack_yacc_cpack_4byte_secret(&mut victim, true);
    println!("{:#?}", results);
}

#[allow(dead_code)]
fn test_8_byte_attack() {
    let mut victim = VictimProgramYACC::new(8, Compressor::CPACK, true);
    let results = attack_yacc_cpack_8byte_secret(&mut victim, true);
    println!("{:#?}", results);
}

struct AggregateAttackStats {
    successes: usize,
    guesses_needed: usize,
    bytes_written_to_victim: usize,
    bytes_read_from_victim: usize,
    attacker_cache_lines_loaded: usize,
    set_evictions: usize
}

impl AggregateAttackStats {
    fn new() -> AggregateAttackStats {
        AggregateAttackStats {
            successes: 0,
            guesses_needed: 0,
            bytes_written_to_victim: 0,
            bytes_read_from_victim: 0,
            attacker_cache_lines_loaded: 0,
            set_evictions: 0
        }
    }
}

#[allow(dead_code)]
fn simulate_4byte_attacks() {
    let iterations = 10000;
    let subdivisions = 100;
    let parallel_iterations = iterations / subdivisions;
    println!("Running {} iterations in {} parallel groups of {}...", iterations, subdivisions, parallel_iterations);
    let mut all_results: Vec<AttackStats> = Vec::new();
    for i in 0..subdivisions {
        let mut current_results: Vec<AttackStats> = (0..parallel_iterations).into_par_iter().map(|_|
            attack_yacc_cpack_4byte_secret(&mut VictimProgramYACC::new(4, Compressor::CPACK, false), false)
        ).collect();
        println!("Group {} completed", i+1);
        all_results.append(&mut current_results);
    }
    let results = all_results.into_iter().fold(AggregateAttackStats::new(),
        |x,y| AggregateAttackStats {
            successes: x.successes + if y.success {1} else {0},
            guesses_needed: x.guesses_needed + y.guesses_needed,
            bytes_written_to_victim: x.bytes_written_to_victim + y.bytes_written_to_victim,
            bytes_read_from_victim: x.bytes_read_from_victim + y.bytes_read_from_victim,
            attacker_cache_lines_loaded: x.attacker_cache_lines_loaded + y.attacker_cache_lines_loaded,
            set_evictions: x.set_evictions + y.set_evictions
        }
    );
    println!();
    println!("Iterations: {}", iterations);
    println!("Successes: {}", results.successes);
    println!("Guesses needed: {}", results.guesses_needed);
    println!("Bytes written to the victim buffer: {}", results.bytes_written_to_victim);
    println!("Bytes read from the victim buffer: {}", results.bytes_read_from_victim);
    println!("Lines loaded directly by the attacker: {}", results.attacker_cache_lines_loaded);
    println!("Number of set evictions performed by the attacker: {}", results.set_evictions);
}

#[allow(dead_code)]
fn simulate_8byte_attacks() {
    let iterations = 10000;
    let subdivisions = 100;
    let parallel_iterations = iterations / subdivisions;
    println!("Running {} iterations in {} parallel groups of {}...", iterations, subdivisions, parallel_iterations);
    let mut all_results: Vec<AttackStats> = Vec::new();
    for i in 0..subdivisions {
        let mut current_results: Vec<AttackStats> = (0..parallel_iterations).into_par_iter().map(|_|
            attack_yacc_cpack_8byte_secret(&mut VictimProgramYACC::new(8, Compressor::CPACK, false), false)
        ).collect();
        println!("Group {} completed", i+1);
        all_results.append(&mut current_results);
    }
    let results = all_results.into_iter().fold(AggregateAttackStats::new(),
       |x,y| AggregateAttackStats {
           successes: x.successes + if y.success {1} else {0},
           guesses_needed: x.guesses_needed + y.guesses_needed,
           bytes_written_to_victim: x.bytes_written_to_victim + y.bytes_written_to_victim,
           bytes_read_from_victim: x.bytes_read_from_victim + y.bytes_read_from_victim,
           attacker_cache_lines_loaded: x.attacker_cache_lines_loaded + y.attacker_cache_lines_loaded,
           set_evictions: x.set_evictions + y.set_evictions
       }
    );
    println!();
    println!("Iterations: {}", iterations);
    println!("Successes: {}", results.successes);
    println!("Guesses needed: {}", results.guesses_needed);
    println!("Bytes written to the victim buffer: {}", results.bytes_written_to_victim);
    println!("Bytes read from the victim buffer: {}", results.bytes_read_from_victim);
    println!("Lines loaded directly by the attacker: {}", results.attacker_cache_lines_loaded);
    println!("Number of set evictions performed by the attacker: {}", results.set_evictions);
}
