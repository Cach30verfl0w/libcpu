#![feature(abi_x86_interrupt)]
#![no_std]

extern crate alloc;

// Register
#[cfg(target_pointer_width = "32")]
pub type Register = u32;

#[cfg(target_pointer_width = "32")]
pub type MemoryAddress = u32;

#[cfg(target_pointer_width = "64")]
pub type Register = u64;

#[cfg(target_pointer_width = "64")]
pub type MemoryAddress = u64;

// x86 and x86_64 API
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) mod x86;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use x86::*;

// ARM and ARM64 API
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub(crate) mod arm;

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub use arm::*;

pub fn halt_cpu() -> ! {
    loop {
        wait_for_interrupts();
    }
}
