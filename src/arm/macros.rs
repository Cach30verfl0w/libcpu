#[macro_export]
macro_rules! cpu_features {
    ($(#[$attr:meta])* $vis: vis enum $name: ident {
        $($(#[$feat_attr:meta])* $feat_ident: ident ($register: literal, $feat_name: literal, $start_bit: expr, $end_bit: expr) = $value: expr),*
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

            pub fn enabled_features() -> alloc::vec::Vec<Self> {
                let mut data = alloc::vec::Vec::new();
                {
                    let mut register: crate::Register = 0;
                    unsafe {
                        asm!(
                            "mrs {0}, ID_AA64ISAR0_EL1",
                            out(reg) register,
                            options(pure, nomem, preserves_flags, nostack)
                        );
                    }
                    Self::enabled_features_of("ID_AA64ISAR0_EL1", register, &mut data);
                }
                data
            }

            #[inline]
            pub fn all_features() -> alloc::vec::Vec<Self> {
                alloc::vec![
                    $(
                    Self::$feat_ident,
                    )*
                ]
            }

            fn enabled_features_of(register: &str, data: crate::Register, features: &mut alloc::vec::Vec<Self>) {
                $(
                if register == $register && (data.get_bits($start_bit..$end_bit) & $value) == $value {
                    features.push(Self::$feat_ident);
                }
                )*
            }
        }
    }
}