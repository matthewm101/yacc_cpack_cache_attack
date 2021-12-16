# YACC+C-PACK Compressed Cache Attack Sim

This repository contains a simulation of a proof-of-concept compressed cache attack on a cache using YACC as its architecture and C-PACK as its compression algorithm. This attack is based on the attack used in the Safecracker paper.

Further details about how the attack works can be found in my paper: TODO

Information about YACC, C-PACK, and Safecracker can be found using the following sources:

* S. Sardashti, A. Seznec, and D. A. Wood, “Yet another compressedcache:  A  low-cost  yet  effective  compressed  cache,”ACM Trans.Archit. Code Optim.,  vol.  13,  no.  3,  Sep.  2016.  [Online].  Available:https://doi.org/10.1145/2976740
* X. Chen, L. Yang, R. P. Dick, L. Shang, and H. Lekatsas, “C-pack: Ahigh-performance  microprocessor  cache  compression  algorithm,”IEEE Transactions on Very Large Scale Integration (VLSI) Systems,vol. 18, no. 8, pp. 1196–1208, 2010.
* P.-A. Tsai, A. Sanchez, C. W. Fletcher, and D. Sanchez, “Safecracker:Leaking  secrets  through  compressed  caches,”  inProceedings of theTwenty-Fifth International Conference on Architectural Support for Pro-gramming Languages and Operating Systems, 2020, pp. 1125–1140.

## Simulation Details

* Cache
  * A single set from an 8-way YACC cache is simulated. C-PACK is used as the compression algorithm.
  * Cache lines are 64 bytes.
  * The cache is attached to a simulated main memory, which is simply a map from line numbers (address minus the last 6 bits) to line data.
  * Any read from the cache returns the data along with a HIT or MISS. It is assumed that in a real simulation, the HIT or MISS of an access can be inferred by the process accessing the cache by using a timing attack.
* Victim Program
  * The victim "program" is simulated as a data structure with access to the compressed cache.
  * It maintains a 256B buffer, equivalent to 4 cache lines or one YACC superblock.
  * At the end of this buffer is a secret, either 4 or 8 bytes long.
    * The secret is randomly generated, bytewise.
    * To reduce the number of edge cases needed to be handled by the attacker, each byte in the secret is unique and not zero.
  * The victim allows any other program to read or write to its buffer, except to the region containing the secret.
    * Any access to the buffer will make the victim load that line into the cache, if necessary.
  * The victim also contains functions to print out the secret. These are purely for debugging and not used by the attacker.
* Attacker
  * The attacker "program" is simulated as a function that can interact with the cache and the victim data structure.
  * The attacker may only do the following:
    * Read and write bytes to the victim's buffer (except to the section containing the secret, which the victim will not allow access to)
    * Access the attacker's own lines in the cache. The attacker cannot read the victim's lines.
  * At the end of the attack, the attacker may send what it thinks the secret is to the victim to confirm it is correct.
    * If needed, the attacker can guess multiple times, but the attacker may not brute-force this function.

## Simulation Results

* After 10000 successful simulations of an attacker leaking a 4-byte secret from a victim:
  * 1 guess was needed for each attempt (attacker was always correct the first time)
  * 33588.6662 bytes were written to the victim buffer on average (in order to prime the buffer with attack strings)
  * 10904.0348 bytes were read from the victim buffer on average (in order to reload the victim's secret line and one other compressible line)
  * 49068.1566 lines were reloaded by the attacker on average (in order to evict the victim's lines)
  * 5452.0174 entire set evictions were performed by the attacker (equal to the previous stat divided by the cache associativity, which is 8)
* After 10000 successful simulations of an attacker leaking an 8-byte secret from a victim:
  * 1.4978 guesses were needed on average (guessed wrong initially half the time, since the word order was unknown)
  * 67516.6206 bytes were written to the victim buffer on average (about double the writes from the 4-byte simulations)
  * 26391.4028 bytes were read from the victim buffer on average (a little more than double the 4-byte simulations)
  * 118761.3126 lines were reloaded by the attacker on average (again a little more than double)
  * 13195.7014 entire set evictions were performed by the attacker on average
* See {4,8}byte_secret_attack_output.txt for the raw data

## Building

* The simulator is a Rust project, so it can be executed using `cargo run --release` 