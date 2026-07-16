#![cfg_attr(target_arch = "wasm32", no_std)]

use core::sync::atomic::{Ordering, compiler_fence};

const WORDS: usize = 16 * 1024;
static mut MEMORY: [u32; WORDS] = [0; WORDS];

#[unsafe(no_mangle)]
pub extern "C" fn turn(
    role: i32,
    bit: i32,
    trial_low: i32,
    trial_high: i32,
    profile_word: i32,
) -> i32 {
    let salt = (trial_low as u32) ^ (trial_high as u32).rotate_left(13);
    let result = match role {
        0 if matches!(bit, 0 | 1) => sender(bit as u8, profile_word as u32),
        1 => probe(profile_word as u32),
        2 => background(profile_word as u32),
        3 => control(profile_word as u32),
        _ => return 1,
    };
    compiler_fence(Ordering::SeqCst);
    if result == salt.wrapping_add(0xfeed_beef) {
        2
    } else {
        0
    }
}

fn sender(bit: u8, profile_word: u32) -> u32 {
    let rounds = iteration_count(profile_word, if bit == 1 { 64 } else { 2 });
    touch_memory(rounds, if bit == 1 { 17 } else { 1021 }) ^ spin(rounds / 2 + 1)
}

fn probe(profile_word: u32) -> u32 {
    let rounds = iteration_count(profile_word, 24);
    touch_memory(rounds, 31) ^ spin(rounds)
}

fn background(profile_word: u32) -> u32 {
    let rounds = iteration_count(profile_word, 12);
    touch_memory(rounds, 127)
}

fn control(profile_word: u32) -> u32 {
    spin(iteration_count(profile_word, 8))
}

fn iteration_count(profile_word: u32, default: u32) -> u32 {
    let requested = profile_word & 0x000f_ffff;
    if requested == 0 {
        default
    } else {
        requested.min(100_000)
    }
}

fn touch_memory(rounds: u32, stride: usize) -> u32 {
    let mut acc = 0x9e37_79b9u32;
    for round in 0..rounds {
        let mut index = round as usize % WORDS;
        for _ in 0..256 {
            // The guest is single-threaded and every instance owns its linear memory.
            unsafe {
                let ptr = core::ptr::addr_of_mut!(MEMORY).cast::<u32>().add(index);
                let value = ptr.read_volatile().wrapping_add(acc ^ index as u32);
                ptr.write_volatile(value);
                acc = acc.rotate_left(5) ^ value;
            }
            index = (index + stride) % WORDS;
        }
    }
    acc
}

fn spin(rounds: u32) -> u32 {
    let mut value = 0x243f_6a88u32;
    for i in 0..rounds.saturating_mul(128) {
        value = value
            .wrapping_add(i ^ 0x85eb_ca6b)
            .rotate_left(7)
            .wrapping_mul(0xc2b2_ae35);
    }
    value
}

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
