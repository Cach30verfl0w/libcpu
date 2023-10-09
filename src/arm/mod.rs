pub(crate) mod macros;

use core::arch::asm;
use bit_field::BitField;
use crate::cpu_features;

cpu_features! {
    #[allow(non_camel_case_types)]
    #[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub enum CPUFeature {
        CRC32("ID_AA64ISAR0_EL1", "CRC32", 16, 20) = 0b0001
    }
}

pub fn wait_for_interrupts() {
    unsafe {
        asm!("wfi");
    }
}
