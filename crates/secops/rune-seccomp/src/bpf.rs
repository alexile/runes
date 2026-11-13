//! Just enough classic BPF to build the x32 guard and per-call actions, and
//! to run a compiled filter in memory ([`crate::Program::evaluate`]).

use seccompiler::sock_filter;

pub const LD_W_ABS: u16 = 0x20;
pub const ALU_AND_K: u16 = 0x04 | 0x50;
pub const JMP_JA: u16 = 0x05;
pub const JMP_JEQ_K: u16 = 0x05 | 0x10;
pub const JMP_JGT_K: u16 = 0x05 | 0x20;
pub const JMP_JGE_K: u16 = 0x05 | 0x30;
pub const JMP_JSET_K: u16 = 0x05 | 0x40;
pub const RET_K: u16 = 0x06;

/// Offset of `seccomp_data.nr`.
pub const NR_OFFSET: u32 = 0;
/// Offset of `seccomp_data.arch`.
pub const ARCH_OFFSET: u32 = 4;
/// Offset of `seccomp_data.args[0]`; each argument takes 8 bytes, low half
/// first on the little-endian architectures this crate supports.
pub const ARGS_OFFSET: u32 = 16;

/// `__X32_SYSCALL_BIT`: set in the number of every x32-ABI system call.
pub const X32_SYSCALL_BIT: u32 = 0x4000_0000;

pub const fn stmt(code: u16, k: u32) -> sock_filter {
    sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

pub const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> sock_filter {
    sock_filter { code, jt, jf, k }
}

/// Runs `program` on a `seccomp_data` with the given architecture, number
/// and arguments, and a zero instruction pointer. Returns the filter's
/// return value, or `None` if the program uses an instruction this
/// evaluator does not know or runs off its end.
pub fn run(program: &[sock_filter], arch: u32, nr: u32, args: [u64; 6]) -> Option<u32> {
    let mut acc: u32 = 0;
    let mut pc: usize = 0;
    // Classic BPF only jumps forward, so this terminates; the bound is a
    // second guard.
    for _ in 0..=program.len() {
        let insn = program.get(pc)?;
        pc += 1;
        let skip = |taken: bool| usize::from(if taken { insn.jt } else { insn.jf });
        match insn.code {
            LD_W_ABS => {
                acc = match insn.k {
                    NR_OFFSET => nr,
                    ARCH_OFFSET => arch,
                    // Instruction pointer.
                    8 | 12 => 0,
                    offset @ ARGS_OFFSET..=60 if offset % 4 == 0 => {
                        let arg = args[usize::try_from((offset - ARGS_OFFSET) / 8).ok()?];
                        let half = if offset % 8 == 0 { arg } else { arg >> 32 };
                        #[allow(clippy::cast_possible_truncation, reason = "one 32-bit half")]
                        let half = half as u32;
                        half
                    }
                    _ => return None,
                };
            }
            ALU_AND_K => acc &= insn.k,
            JMP_JA => pc += usize::try_from(insn.k).ok()?,
            JMP_JEQ_K => pc += skip(acc == insn.k),
            JMP_JGT_K => pc += skip(acc > insn.k),
            JMP_JGE_K => pc += skip(acc >= insn.k),
            JMP_JSET_K => pc += skip(acc & insn.k != 0),
            RET_K => return Some(insn.k),
            _ => return None,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluates_a_hand_written_filter() {
        let program = [
            stmt(LD_W_ABS, NR_OFFSET),
            jump(JMP_JEQ_K, 39, 0, 1),
            stmt(RET_K, 1),
            jump(JMP_JGE_K, 100, 1, 0),
            stmt(RET_K, 2),
            stmt(RET_K, 3),
        ];
        assert_eq!(run(&program, 0, 39, [0; 6]), Some(1));
        assert_eq!(run(&program, 0, 40, [0; 6]), Some(2));
        assert_eq!(run(&program, 0, 100, [0; 6]), Some(3));
    }

    #[test]
    fn loads_both_halves_of_each_argument() {
        let args = [0, 0, 0x1234_5678_9abc_def0, 0, 0, 0];
        // Returns 1 if the word at `offset` is `want`.
        let check = |offset: u32, want: u32| {
            let program = [
                stmt(LD_W_ABS, offset),
                jump(JMP_JEQ_K, want, 0, 1),
                stmt(RET_K, 1),
                stmt(RET_K, 0),
            ];
            run(&program, 0, 0, args)
        };
        assert_eq!(check(ARGS_OFFSET + 2 * 8 + 4, 0x1234_5678), Some(1));
        assert_eq!(check(ARGS_OFFSET + 2 * 8, 0x9abc_def0), Some(1));
        assert_eq!(check(ARGS_OFFSET + 2 * 8, 0x1234_5678), Some(0));
        // Misaligned and out-of-range loads are not understood.
        assert_eq!(check(18, 0), None);
        assert_eq!(check(64, 0), None);
    }

    #[test]
    fn rejects_unknown_instructions_and_running_off_the_end() {
        assert_eq!(run(&[stmt(0x07, 0)], 0, 0, [0; 6]), None);
        assert_eq!(run(&[stmt(LD_W_ABS, NR_OFFSET)], 0, 0, [0; 6]), None);
        assert_eq!(run(&[stmt(JMP_JA, 5), stmt(RET_K, 0)], 0, 0, [0; 6]), None);
    }
}
