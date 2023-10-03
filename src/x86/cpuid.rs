use core::arch::x86_64::{__cpuid, __cpuid_count, CpuidResult};

#[macro_export]
macro_rules! cpu_features {
    ($(#[$attr:meta])* $vis: vis enum $name: ident {
        $($(#[$feat_attr:meta])* $feat_ident: ident ($register: ident, $feat_name: literal, $request: path) = $value: expr),*
    }) => {
        $(#[$attr])*
        $vis enum $name {
            $(
            $(#[$feat_attr])*
            $feat_ident,
            )*
        }

        impl alloc::fmt::Display for $name {
            fn fmt(&self, formatter: &mut alloc::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
                write!(formatter, "{}", match self {
                    $(
                    Self::$feat_ident => $feat_name,
                    )*
                })
            }
        }

        impl $name {

            #[inline]
            pub fn enabled_features() -> alloc::vec::Vec<Self> {
                let mut enabled_features = alloc::vec::Vec::new();
                Self::enabled_features_by(CPUIDRequest::Features, &mut enabled_features);
                Self::enabled_features_by(CPUIDRequest::ExtendedFeatures1, &mut enabled_features);
                Self::enabled_features_by(CPUIDRequest::ExtendedFeatures2, &mut enabled_features);
                Self::enabled_features_by(CPUIDRequest::ExtendedFeatures3, &mut enabled_features);
                enabled_features
            }

            #[inline]
            pub fn all_features() -> alloc::vec::Vec<Self> {
                alloc::vec![
                    $(
                    Self::$feat_ident,
                    )*
                ]
            }

            fn enabled_features_by(request: crate::x86::cpuid::CPUIDRequest, vec: &mut alloc::vec::Vec<Self>) {
                let cpuid = request.cpuid();
                $(
                if $request == request && (cpuid.$register & $value) == $value {
                    vec.push(Self::$feat_ident);
                }
                )*
            }

        }
    }
}

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