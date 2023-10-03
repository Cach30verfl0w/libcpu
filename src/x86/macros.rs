#[macro_export]
macro_rules! cpu_register {
    ($name: ident, $register: literal $(, $flags_struct: ident)?) => {
        pub struct $name;

        impl $name {

            $(
            pub fn set_flags(value: $flags_struct) {
                Self::set(Self::get() | value.bits());
            }

            pub fn get_flags() -> $flags_struct {
                $flags_struct::from_bits_truncate(Self::get())
            }
            )?

            pub fn set(value: crate::Register) {
                unsafe {
                    core::arch::asm!(
                        concat!("mov ", $register, ", {}"),
                        in(reg) value,
                        options(nomem, nostack, preserves_flags)
                    );
                }
            }

            pub fn get() -> crate::Register {
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
    }
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