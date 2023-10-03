#![no_std]

extern crate alloc;

// x86 and x86_64 API
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod x86;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use x86::*;

// ARM and ARM64 API
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
mod arm;

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub use arm::*;