use core::arch::x86_64::{__cpuid, __cpuid_count, CpuidResult};

#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub enum CPUIDRequest {
    Features,
    ExtendedFeatures1,
    ExtendedFeatures2,
    ExtendedFeatures3,
    ExtendedFeatures4
}

impl CPUIDRequest {

    pub(crate) fn cpuid(&self) -> CpuidResult {
        let leaf = self.leaf();
        unsafe {
            match self.sub_leaf() {
                None => __cpuid(leaf),
                Some(sub_leaf) => __cpuid_count(leaf, sub_leaf)
            }
        }
    }

    fn leaf(&self) -> u32 {
        match self {
            CPUIDRequest::Features => 1,
            CPUIDRequest::ExtendedFeatures1 => 7,
            CPUIDRequest::ExtendedFeatures2 => 7,
            CPUIDRequest::ExtendedFeatures3 => 7,
            CPUIDRequest::ExtendedFeatures4 => 0x80000001
        }
    }

    fn sub_leaf(&self) -> Option<u32> {
        match self {
            CPUIDRequest::ExtendedFeatures1 => Some(0),
            CPUIDRequest::ExtendedFeatures2 => Some(1),
            CPUIDRequest::ExtendedFeatures3 => Some(2),
            _ => None
        }
    }

}