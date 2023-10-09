use core::arch::asm;

pub fn wait_for_interrupts() {
    unsafe {
        asm!("wfi");
    }
}
