use crate::{CPUFeature, CPUVendor};

#[cfg(feature = "cpuid_cache")]
pub(crate) static mut VENDOR_CACHE: Option<CPUVendor>                     = None;
#[cfg(feature = "cpuid_cache")]
pub(crate) static mut FEATURES_CACHE: Option<alloc::vec::Vec<CPUFeature>> = None;

#[macro_export]
macro_rules! cpu_vendor {
    ($(#[$attr:meta])* $vis: vis enum $name: ident {
        $($(#[$vendor_attr:meta])* $vendor_enum: ident ($vendor_string_start: literal $(, $vendor_string: literal)?) = $literal: literal),*
    }) => {
        $(#[$attr])*
        $vis enum $name {
            $(
            $(#[$vendor_attr])*
            $vendor_enum,
            )*
            Unknown
        }

        impl alloc::fmt::Display for $name {
            fn fmt(&self, formatter: &mut alloc::fmt::Formatter<'_>) -> alloc::fmt::Result {
                write!(formatter, "{}", match self {
                    $(
                    Self::$vendor_enum => $literal,
                    )*
                    Self::Unknown => "Unknown Vendor"
                })
            }
        }

        impl $name {

            pub fn get_vendor() -> Self {
                #[cfg(target = "cpuid_cache")]
                if let Some(vendor) = unsafe { crate::macros::VENDOR_CACHE } {
                    return vendor;
                }

                use alloc::string::String;
                let result = crate::x86::cpuid::CPUIDRequest::Vendor.cpuid();
                let vendor = match String::from_utf8_lossy(&[
                    result.ebx.to_ne_bytes(),
                    result.edx.to_ne_bytes(),
                    result.ecx.to_ne_bytes()
                ].concat()).trim() {
                    $(
                    $vendor_string_start $(| $vendor_string)? => Self::$vendor_enum,
                    )*
                    _ => Self::Unknown
                };
                #[cfg(target = "cpuid_cache")]
                unsafe {crate::macros::VENDOR_CACHE = Some(vendor) };
                vendor
            }
        }
    }
}

#[macro_export]
macro_rules! cpu_register {
    ($name: ident, $register: literal, $flags_struct: ident) => {
        paste::paste! {
            pub fn [<set_ $name>](value: $flags_struct) {
                unsafe {
                    core::arch::asm!(
                        concat!("mov ", $register, ", {}"),
                        in(reg) (value | [<get_ $name>]()).bits(),
                        options(nomem, nostack, preserves_flags)
                    );
                }
            }

            #[allow(unused_assignments)]
            pub fn [<get_ $name>]() -> $flags_struct {
                let mut value = 0;
                unsafe {
                    core::arch::asm!(
                        concat!("mov {}, ", $register),
                        out(reg) value,
                        options(nomem, nostack, preserves_flags)
                    );
                }
                $flags_struct::from_bits_truncate(value)
            }
        }
    };
    ($name: ident, $register: literal) => {
        paste::paste! {
            pub fn [<set_ $name>](value: crate::Register) {
                unsafe {
                    core::arch::asm!(
                        concat!("mov ", $register, ", {}"),
                        in(reg) value,
                        options(nomem, nostack, preserves_flags)
                    );
                }
            }

            #[allow(unused_assignments)]
            pub fn [<get_ $name>]() -> crate::Register {
                let mut value = 0;
                unsafe {
                    core::arch::asm!(
                        concat!("mov {}, ", $register),
                        out(reg) value,
                        options(nomem, nostack, preserves_flags)
                    );
                }
                value
            }
        }
    };
}

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
                #[cfg(feature = "cpuid_cache")]
                if let Some(features) = unsafe { crate::macros::FEATURES_CACHE.clone() } {
                    return features;
                }

                let mut enabled_features = alloc::vec::Vec::new();
                Self::enabled_features_by(CPUIDRequest::Features, &mut enabled_features);
                Self::enabled_features_by(CPUIDRequest::ExtendedFeatures1, &mut enabled_features);
                Self::enabled_features_by(CPUIDRequest::ExtendedFeatures2, &mut enabled_features);
                Self::enabled_features_by(CPUIDRequest::ExtendedFeatures3, &mut enabled_features);
                Self::enabled_features_by(CPUIDRequest::ExtendedFeatures4, &mut enabled_features);

                #[cfg(feature = "cpuid_cache")]
                unsafe { crate::macros::FEATURES_CACHE = Some(enabled_features.clone()) };
                enabled_features
            }

            fn enabled_features_by(request: crate::x86::cpuid::CPUIDRequest, vec: &mut alloc::vec::Vec<Self>) {
                let cpuid = request.cpuid();
                $(
                if $request == request && (cpuid.$register & $value) == $value {
                    vec.push(Self::$feat_ident);
                }
                )*
            }

            #[inline]
            pub fn all_features() -> alloc::vec::Vec<Self> {
                alloc::vec![
                    $(
                    Self::$feat_ident,
                    )*
                ]
            }

        }
    }
}
