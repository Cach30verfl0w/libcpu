//! This module implements the x86/x86_64 specific functionality as a Rust "Wrapper" of the Global
//! Descriptor Table (GDT). The GDT is used to configure memory segments.
//!
//! A single GDT descriptor contains the segment start as a linear address (only used on 32-bit
//! systems), a limit which tells the maximum addressable unit, the access flags for the segment
//! and the flags for the segment.
//!
//! The following structure shows how a single descriptor is represented in the memory on x86
//! systems (MLI = Middle Limit, DFL = Descriptor Flags):
//! ```text
//! 0                   1                   2                   3                   4
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |          Lower Base Address           |              Lower Limit              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |       Base        |    Access Bits    |   MLI   |   DFL   |    Higher Base    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//! The limit values and base address values are only for 32-bit systems. As said before, these
//! values are ignored in the 64-bit mode. Each selector covers the entire linear address space.
//!
//! # Examples
//! The following examples shows the creation of a basic GDT for a Ring 0 only system.
//! ```rust
//! use libcpu::{
//!     gdt::{
//!         GDTDescriptor,
//!         GlobalDescriptorTable,
//!     },
//!     PrivilegeLevel,
//! };
//! let mut global_descriptor_table = GlobalDescriptorTable::default();
//! global_descriptor_table.insert(1, GDTDescriptor::code_segment(PrivilegeLevel::KernelSpace));
//! global_descriptor_table.insert(2, GDTDescriptor::data_segment(PrivilegeLevel::KernelSpace));
//! ```
//!
//! # See also
//! - [x86 Handling Exceptions](https://hackernoon.com/x86-handling-exceptions-lds3uxc)
//! by [HackerNoon.com](https://hackernoon.com)
//! - [Global Descriptor Table](https://wiki.osdev.org/Global_Descriptor_Table)
//! by [OSDev.org](https://wiki.osdev.org)

use crate::{
    x86::DescriptorTablePointer,
    DescriptorTable,
    MemoryAddress,
    PrivilegeLevel,
    SegmentSelector,
};
use bit_field::BitField;
use bitflags::bitflags;
use core::{
    arch::asm,
    mem::size_of,
};

bitflags! {
    /// This structure represents most of the flags for the access byte in the descriptor.
    ///
    /// Here is a list of all flags with description:
    /// - [Access::ACCESSED] - This bit is set by the CPU when the CPU accesses the
    /// descriptor. If the descriptor is stored in read only pages and this bit is set to 0, the
    /// CPU will trigger a page fault. You should set this bit.
    /// - [Access::PRESENT] - This bit must be always set to communicate the CPU, that
    /// this segment is valid.
    /// - [Access::USER_SEGMENT] - If set, the segment is a code or data segment. If not,
    /// this segment is a data segment (a.e. a Task State Segment). This flag
    /// - [Access::EXECUTABLE] - If defined, the segment is a executable code segment. If
    /// not, this segment is a data segment
    /// - [Access::READABLE] - This bit is only for code segments. If set, read access to
    /// the code segment is allowed. Write access is never allowed for these segments.
    /// - [Access::WRITABLE] - This bit is only for data segments. If set, write access to
    /// the data segment is allowed. Read access is always allowed for these segments.
    ///
    /// # See also
    /// - [Global Descriptor Table](https://wiki.osdev.org/Global_Descriptor_Table#Segment_Descriptor)
    /// by [OSDev.org](https://wiki.osdev.org)
    #[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Access: u8 {
        /// This bit is set by the CPU when the CPU accesses the descriptor. If the descriptor
        /// is stored in read only pages and this bit is set to 0, the CPU will trigger a page
        /// fault. You should set this bit.
        const ACCESSED     = 0b0000_0001;

        /// This bit must be always set to communicate the CPU, that this segment is valid.
        const PRESENT      = 0b1000_0000;

        /// If set, the segment is a code or data segment. If not, this segment is a data
        /// segment (a.e. a Task State Segment). This flag
        const USER_SEGMENT = 0b0001_0000;

        /// If defined, the segment is a executable code segment. If not, this segment is a data
        /// segment.
        const EXECUTABLE   = 0b0000_1000;

        /// This bit is only for code segments. If set, read access to the code segment is
        /// allowed. Write access is never allowed for these segments.
        const READABLE     = 0b0000_0010;

        /// This bit is only for data segments. If set, write access to the data segment is
        /// allowed. Read access is always allowed for these segments.
        const WRITABLE     = 0b0000_0010;
    }
}

bitflags! {
    /// This structure represents the flags, that can be set on a descriptor.
    ///
    /// Here is a list of all flags with description:
    /// - [Flags::GRANULARITY] - This flag indicates the scaling of the Limit value. If
    /// this flag is set, the limit is in 4 KiB blocks. If not, the Limit value is in 1 byte blocks.
    /// - [Flags::SIZE] - If this flag is set, this is a 32-bit protected mode segment. If
    /// not set, this is a 16-bit protected mode segment.
    /// - [Flags::LONG_MODE] - If this flag iet set, this is a 64-bit code segment. If
    /// this is set, you shouldn't set the size flag.
    ///
    /// # See also
    /// - [Global Descriptor Table](https://wiki.osdev.org/Global_Descriptor_Table#Segment_Descriptor)
    /// by [OSDev.org](https://wiki.osdev.org)
    #[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Flags: u8 {
        /// This flag indicates the scaling of the Limit value. If this flag is set, the limit
        /// is in 4 KiB blocks. If not, the Limit value is in 1 byte blocks.
        const GRANULARITY = 0b1000_0000;

        /// If this flag is set, this is a 32-bit protected mode segment. If not set, this is a
        /// 16-bit protected mode segment.
        const SIZE        = 0b0100_0000;

        /// If this flag iet set, this is a 64-bit code segment. If this is set, you shouldn't set
        /// the size flag.
        const LONG_MODE   = 0b0010_0000;
    }
}

/// This structure represents a single descriptor in the GDT (Global Descriptor Table). This
/// structure is compatible with the raw memory representation of a descriptor. Use the function
/// [`GDTDescriptor::NUL`] to use the Null descriptor. The implementation of the GDT is only needed
/// for IA-32 and x86_64 architectures.
///
/// **Disclaimer: The x86 only values are ignored by the CPU, if the target is x86_64**
/// - `lower_limit` - These bytes are storing the first 16 bits of the limit (x86_64 only)
/// - `lower_base_address` - These bytes are storing the first 16 bits of the base address of the
/// section (32bit only)
/// - `middle_base_address` - These bytes are storing the lower middle 16 bits of the base address
/// of the section (32bit only)
/// - `higher_base_address` - These bytes are storing the higher middle 16 bits of the base address
/// of the section. (32bit only)
/// - `highest_base_address` - These bytes are storing the last 32 bits of the base address of the
/// section. (64bit only)
/// - `access` - This field contains the access flags. All needed access flags are specified in
/// [Access]. This value is supported on 32-bit and 64-bit systems
/// - `flags` - This field contains the descriptor flags. All needed descriptor flags are specified
/// in [Flags]. This value is supported on 32-bit and 64-bit systems. This value is supported on
/// 32-bit and 64-bit systems. The flags are also containing the higher limit
///
/// # See also
/// - [Global Descriptor Table](https://wiki.osdev.org/Global_Descriptor_Table#Segment_Descriptor)
/// by [OSDev.org](https://wiki.osdev.org)
/// - [x86 Handling Exceptions](https://hackernoon.com/x86-handling-exceptions-lds3uxc) by
/// [HackerNoon.com](https://hackernoon.com)
#[repr(C, packed)]
#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub struct GDTDescriptor {
    /// These bytes are storing the first 16 bits of the limit. (32bit only)
    lower_limit_address: u16,

    /// These bytes are storing the first 16 bits of the base address of the section.
    /// (32bit only)
    lower_base_address: u16,

    /// These bytes are storing the lower middle 16 bits of the base address of the section.
    /// (32bit only)
    middle_base_address: u8,

    /// This field contains the access flags. All needed access flags are specified in
    /// [Access]. This value is supported on 32-bit and 64-bit systems.
    access: u8,

    /// This field contains the descriptor flags. All needed descriptor flags are specified in
    /// [Flags]. This value is supported on 32-bit and 64-bit systems. The flags are also containing
    /// the higher limit.
    flags: u8,

    /// These bytes are storing the higher middle 16 bits of the base address of the section.
    /// (32bit only)
    higher_base_address: u8,
}

impl GDTDescriptor {
    /// This function creates a new GDT descriptor with the specified values. The function parameters
    /// `privilege`, `kind` and `access` are merged to the access byte for the descriptor.
    ///
    /// Here is a list with the parameters:
    /// - `privilege` - This parameter defines the privilege level of the descriptor
    /// - `access` - This parameter defines the access flags of the descriptor
    /// - `flag` - This parameter defines the flags of the descriptor
    ///
    /// TODO: Validate x86 implementation and set data
    ///
    /// # See also
    /// - [GDT Tutorial](https://wiki.osdev.org/GDT_Tutorial#What_to_Put_In_a_GDT)
    /// by [OSDev.org](https://wiki.osdev.org)
    #[must_use]
    pub fn new(base_address: u32, limit_address: u32, privilege: PrivilegeLevel, access: Access, flags: Flags) -> Self {
        GDTDescriptor {
            lower_limit_address: limit_address as u16,
            lower_base_address: base_address as u16,
            middle_base_address: (base_address >> 16) as u8,
            access: (limit_address.get_bits(0..3) as u8) | access.bits() | (privilege as u8),
            flags: flags.bits(),
            higher_base_address: (base_address >> 16) as u8,
        }
    }

    #[inline]
    fn null() -> Self {
        Self {
            lower_limit_address: 0,
            lower_base_address: 0,
            middle_base_address: 0,
            access: 0,
            flags: 0,
            higher_base_address: 0,
        }
    }

    /// This function creates a new GDT descriptor with the default settings for a executable Code
    /// segment
    ///
    /// # See also
    /// - [GDT Tutorial](https://wiki.osdev.org/GDT_Tutorial#What_to_Put_In_a_GDT)
    /// by [OSDev.org](https://wiki.osdev.org)
    #[inline]
    #[must_use]
    pub fn code_segment(level: PrivilegeLevel) -> Self {
        Self::new(
            0x00000000,
            0xFFFFF,
            level,
            Access::PRESENT
                | Access::ACCESSED
                | Access::USER_SEGMENT
                | Access::READABLE
                | Access::EXECUTABLE,
            Flags::GRANULARITY | Flags::LONG_MODE,
        )
    }

    /// This function creates a new GDT descriptor with the default settings for a Data segment
    ///
    /// # See also
    /// - [GDT Tutorial](https://wiki.osdev.org/GDT_Tutorial#What_to_Put_In_a_GDT)
    /// by [OSDev.org](https://wiki.osdev.org)
    #[inline]
    #[must_use]
    pub fn data_segment(level: PrivilegeLevel) -> Self {
        Self::new(
            0x00000000,
            0xFFFFF,
            level,
            Access::PRESENT | Access::ACCESSED | Access::USER_SEGMENT | Access::WRITABLE,
            Flags::GRANULARITY | Flags::LONG_MODE,
        )
    }

    /// This function returns the descriptor's privilege level, set by the descriptor creator.
    ///
    /// # See also
    /// - [CPU Security Rings](https://wiki.osdev.org/Security#Rings) by [OSDev.org](https://wiki.osdev.org/)
    /// - [Global Descriptor Table](https://wiki.osdev.org/Global_Descriptor_Table#Segment_Descriptor)
    /// by [OSDev.org](https://wiki.osdev.org/)
    /// - [Protection Ring](https://en.wikipedia.org/wiki/Protection_ring) by
    /// [Wikipedia](https://wikipedia.org)
    /// - [PrivilegeLevel] (Source Code)
    #[inline]
    #[must_use]
    pub fn privilege_level(&self) -> PrivilegeLevel {
        PrivilegeLevel::from(self.access.get_bits(5..7) as u16)
    }

    /// This function returns the descriptor's access flags, set by the descriptor creator.
    ///
    /// # See also
    /// - [Global Descriptor Table](https://wiki.osdev.org/Global_Descriptor_Table#Segment_Descriptor)
    /// by [OSDev.org](https://wiki.osdev.org)
    /// - [Access] (Source Code)
    #[inline]
    #[must_use]
    pub fn access_flags(&self) -> Access {
        Access::from_bits_retain(self.access)
    }

    /// This function returns the descriptor's flags, set by the descriptor creator.
    ///
    /// # See also
    /// - [Global Descriptor Table](https://wiki.osdev.org/Global_Descriptor_Table#Segment_Descriptor)
    /// by [OSDev.org](https://wiki.osdev.org)
    /// - [Flags] (Source Code)
    #[inline]
    #[must_use]
    pub fn flags(&self) -> Flags {
        Flags::from_bits_retain(self.flags)
    }
}

/// This structure represents the Global Descriptor Table with the maximum of 8192 entries. In this
/// structure, we store the descriptors in a slice.
///
/// - `descriptors` - This field is a slice that can store 8192 [GDTDescriptor]s
/// - `count` This field holds the max index that is used to insert a descriptor for the
/// [DescriptorTablePointer]
///
/// # See also
/// - [Global Descriptor Table](https://wiki.osdev.org/Global_Descriptor_Table)
/// by [OSDev.org](https://wiki.osdev.org)
/// - [GDT Tutorial](https://wiki.osdev.org/GDT_Tutorial) by [OSDev.org](https://wiki.osdev.org)
/// - [GDTDescriptor] (Source Code)
#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub struct GlobalDescriptorTable {
    /// This field is a slice that can store 8192 [GDTDescriptor]
    descriptors: [GDTDescriptor; 8192],

    /// This field holds the max index that is used to insert a descriptor for the
    /// [DescriptorTablePointer]
    count: usize,
}

impl GlobalDescriptorTable {
    #[must_use]
    pub fn new() -> Self {
        Self {
            descriptors: [GDTDescriptor::null(); 8192],
            count: 1,
        }
    }

    /// This function generates a pointer to the GDT with the [GlobalDescriptorTable::as_ptr]
    /// function and loads it with the `lgdt` instruction.
    ///
    /// # See also
    /// - [LGDT/LIDT](https://www.felixcloutier.com/x86/lgdt:lidt) by
    /// [Felix Clountier](https://www.felixcloutier.com)
    pub fn load(&self) {
        unsafe {
            asm!("lgdt [{}]", in(reg) &self.as_ptr(), options(readonly, nostack, preserves_flags));
        }
    }

    /// This function inserts a [GDTDescriptor] at the specified index in the GDT. After the
    /// insertion, the function updates the count variable if necessary.
    pub fn push(&mut self, descriptor: GDTDescriptor) -> Option<SegmentSelector> {
        if self.count + 1 >= 8192 {
            return None;
        }

        self.descriptors[self.count] = descriptor;
        self.count += 1;
        Some(SegmentSelector::new(
            (self.count - 1) as u16,
            DescriptorTable::GDT,
            descriptor.privilege_level(),
        ))
    }

    /// This function generates a pointer to the Global Descriptor Table (GDT) with the base address
    /// and the size of the GDT as limit.
    ///
    /// # See also
    /// - [Global Descriptor Table](https://wiki.osdev.org/Global_Descriptor_Table#GDTR) by
    /// [OSDev.org](https://wiki.osdev.org)
    #[must_use]
    pub fn as_ptr(&self) -> DescriptorTablePointer {
        DescriptorTablePointer {
            base: self.descriptors.as_ptr() as MemoryAddress,
            size: (self.count * size_of::<GDTDescriptor>() - 1) as u16,
        }
    }
}
