use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};

use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, IntelFormatter, OpKind};

#[derive(Debug)]
pub struct Decoded {
    pub size: usize,
    pub ip: u64,
    pub text: String,
    pub mnemonic: String,
    pub flow: &'static str,
    pub target: Option<u64>,
}

#[derive(Debug)]
pub struct Block {
    pub start: u64,
    pub end: u64,
    pub first_index: usize,
    pub instruction_count: usize,
    pub successors: Vec<u64>,
    pub unresolved: bool,
}

impl Decoded {
    pub fn successors(&self) -> Result<Vec<u64>, String> {
        let mut successors = Vec::with_capacity(2);
        if matches!(
            self.flow,
            "next" | "conditional_branch" | "call" | "indirect_call"
        ) {
            successors.push(
                self.ip
                    .checked_add(self.size as u64)
                    .ok_or("instruction address overflow")?,
            );
        }
        if matches!(self.flow, "conditional_branch" | "jump" | "call") {
            if let Some(target) = self.target {
                if !successors.contains(&target) {
                    successors.push(target);
                }
            }
        }
        Ok(successors)
    }
}

pub fn decode(bytes: &[u8], offset: usize, ip: u64, bitness: u32) -> Result<Decoded, String> {
    if !matches!(bitness, 16 | 32 | 64) {
        return Err("x86 bitness must be 16, 32, or 64".into());
    }
    if offset >= bytes.len() {
        return Err("instruction offset out of bounds".into());
    }
    let end = offset.saturating_add(15).min(bytes.len());
    let mut decoder = Decoder::with_ip(bitness, &bytes[offset..end], ip, DecoderOptions::NONE);
    let instruction = decoder.decode();
    if instruction.is_invalid() || instruction.len() == 0 {
        return Err("invalid or truncated x86 instruction".into());
    }
    let mut text = String::new();
    IntelFormatter::new().format(&instruction, &mut text);
    let flow = match instruction.flow_control() {
        FlowControl::Next => "next",
        FlowControl::UnconditionalBranch => "jump",
        FlowControl::IndirectBranch => "indirect_jump",
        FlowControl::ConditionalBranch => "conditional_branch",
        FlowControl::Return => "return",
        FlowControl::Call => "call",
        FlowControl::IndirectCall => "indirect_call",
        FlowControl::Interrupt => "interrupt",
        FlowControl::XbeginXabortXend => "transaction",
        FlowControl::Exception => "exception",
    };
    let target = if instruction.op_count() > 0 {
        match instruction.op0_kind() {
            OpKind::NearBranch16 => Some(u64::from(instruction.near_branch16())),
            OpKind::NearBranch32 => Some(u64::from(instruction.near_branch32())),
            OpKind::NearBranch64 => Some(instruction.near_branch64()),
            _ => None,
        }
    } else {
        None
    };
    Ok(Decoded {
        size: instruction.len(),
        ip,
        text,
        mnemonic: format!("{:?}", instruction.mnemonic()).to_ascii_lowercase(),
        flow,
        target,
    })
}

pub fn reachable(
    bytes: &[u8],
    start_offset: usize,
    base_ip: u64,
    bitness: u32,
    max_instructions: usize,
) -> Result<Vec<(usize, Decoded)>, String> {
    if start_offset >= bytes.len() {
        return Err("reachable entry offset out of bounds".into());
    }
    if max_instructions == 0 {
        return Err("reachable instruction count must be positive".into());
    }
    let mut pending = VecDeque::from([start_offset]);
    let mut queued = HashSet::from([start_offset]);
    let mut found = BTreeMap::new();
    while let Some(offset) = pending.pop_front() {
        if found.len() >= max_instructions {
            return Err("reachable disassembly exceeds max instruction count".into());
        }
        let ip = base_ip
            .checked_add(u64::try_from(offset).map_err(|_| "instruction offset out of range")?)
            .ok_or("instruction address overflow")?;
        let instruction = decode(bytes, offset, ip, bitness)?;
        let next = offset + instruction.size;
        let mut enqueue = |candidate: usize| {
            if candidate < bytes.len() && queued.insert(candidate) {
                pending.push_back(candidate);
            }
        };
        if matches!(
            instruction.flow,
            "next" | "conditional_branch" | "call" | "indirect_call"
        ) {
            enqueue(next);
        }
        if matches!(instruction.flow, "conditional_branch" | "jump" | "call") {
            if let Some(target) = instruction.target {
                if let Some(relative) = target.checked_sub(base_ip) {
                    if let Ok(relative) = usize::try_from(relative) {
                        enqueue(relative);
                    }
                }
            }
        }
        found.insert(offset, instruction);
    }
    Ok(found.into_iter().collect())
}

pub fn blocks(instructions: &[&Decoded]) -> Result<Vec<Block>, String> {
    if instructions.is_empty() {
        return Ok(Vec::new());
    }
    let addresses = instructions.iter().map(|i| i.ip).collect::<HashSet<_>>();
    if addresses.len() != instructions.len() {
        return Err("disassembly has duplicate instruction addresses".into());
    }
    let mut leaders = BTreeSet::from([instructions[0].ip]);
    for (index, instruction) in instructions.iter().enumerate() {
        let next = instruction
            .ip
            .checked_add(instruction.size as u64)
            .ok_or("instruction address overflow")?;
        if let Some(following) = instructions.get(index + 1) {
            if following.ip <= instruction.ip {
                return Err("disassembly instructions are not in address order".into());
            }
            if following.ip != next || instruction.flow != "next" {
                leaders.insert(following.ip);
            }
        }
        for target in instruction.successors()? {
            if addresses.contains(&target) && (target != next || instruction.flow != "next") {
                leaders.insert(target);
            }
        }
    }
    let mut result = Vec::new();
    let mut first_index = 0;
    for index in 1..=instructions.len() {
        if index < instructions.len() && !leaders.contains(&instructions[index].ip) {
            continue;
        }
        let last = instructions[index - 1];
        let successors = last.successors()?;
        result.push(Block {
            start: instructions[first_index].ip,
            end: last
                .ip
                .checked_add(last.size as u64)
                .ok_or("instruction address overflow")?,
            first_index,
            instruction_count: index - first_index,
            unresolved: matches!(last.flow, "indirect_jump" | "indirect_call")
                || successors.iter().any(|target| !addresses.contains(target)),
            successors,
        });
        first_index = index;
    }
    Ok(result)
}

/// Direct branch and call sites that name `target`, in instruction order.
pub fn xrefs(instructions: &[&Decoded], target: u64) -> Vec<u64> {
    instructions
        .iter()
        .filter(|instruction| {
            matches!(instruction.flow, "conditional_branch" | "jump" | "call")
                && instruction.target == Some(target)
        })
        .map(|instruction| instruction.ip)
        .collect()
}

/// Distinct direct call targets, sorted by address. External targets remain visible.
pub fn call_targets(instructions: &[&Decoded]) -> Vec<u64> {
    instructions
        .iter()
        .filter(|instruction| instruction.flow == "call")
        .filter_map(|instruction| instruction.target)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Marks starts that fall inside an earlier decoded instruction's byte span.
pub fn overlaps(instructions: &[&Decoded]) -> Result<Vec<bool>, String> {
    let mut end = 0_u64;
    let mut result = Vec::with_capacity(instructions.len());
    for instruction in instructions {
        result.push(instruction.ip < end);
        let next = instruction
            .ip
            .checked_add(instruction.size as u64)
            .ok_or("instruction address overflow")?;
        end = end.max(next);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::{blocks, call_targets, decode, overlaps, reachable, xrefs};

    #[test]
    fn decodes_single_instructions_without_running_them() {
        let nop = decode(b"\x90", 0, 0x1000, 64).unwrap();
        assert_eq!(
            (nop.size, nop.ip, nop.mnemonic.as_str()),
            (1, 0x1000, "nop")
        );
        assert_eq!((nop.flow, nop.target), ("next", None));
        let call = decode(b"\xe8\x02\0\0\0\x90", 0, 0x1000, 64).unwrap();
        assert_eq!(
            (call.size, call.flow, call.target),
            (5, "call", Some(0x1007))
        );
        assert_eq!(call.successors().unwrap(), [0x1005, 0x1007]);
        let call16 = decode(b"\xe8\x02\0", 0, 0x1000, 16).unwrap();
        assert_eq!((call16.size, call16.target), (3, Some(0x1005)));
        let call32 = decode(b"\xe8\x02\0\0\0", 0, 0x1000, 32).unwrap();
        assert_eq!((call32.size, call32.target), (5, Some(0x1007)));
        assert_eq!(
            decode(b"\x0f", 0, 0, 64).unwrap_err(),
            "invalid or truncated x86 instruction"
        );
        assert_eq!(
            decode(b"\x90", 1, 0, 64).unwrap_err(),
            "instruction offset out of bounds"
        );
        assert_eq!(
            decode(b"\x90", 0, 0, 8).unwrap_err(),
            "x86 bitness must be 16, 32, or 64"
        );
    }

    #[test]
    fn reachable_disassembly_follows_direct_branches_and_stops_at_returns() {
        let found = reachable(b"\x75\x03\x90\xc3\x90\xc3", 0, 0x1000, 64, 4).unwrap();
        assert_eq!(
            found.iter().map(|(offset, _)| *offset).collect::<Vec<_>>(),
            [0, 2, 3, 5]
        );
        assert_eq!(found[0].1.target, Some(0x1005));
        assert_eq!(found[0].1.successors().unwrap(), [0x1002, 0x1005]);
        assert_eq!(found[3].1.flow, "return");
        assert!(found[3].1.successors().unwrap().is_empty());
        assert_eq!(reachable(b"\xeb\xfe", 0, 0x1000, 64, 1).unwrap().len(), 1);
        assert!(reachable(b"\x75\x03\x90\xc3\x90\xc3", 0, 0x1000, 64, 3)
            .unwrap_err()
            .contains("exceeds max"));
    }

    #[test]
    fn reachable_disassembly_preserves_full_u64_addresses() {
        let base = 0x8000_0000_0000_0000;
        let found = reachable(b"\xeb\x01\x90\xc3", 0, base, 64, 2).unwrap();
        assert_eq!(found[0].1.target, Some(base + 3));
        assert_eq!(found[1].1.ip, base + 3);
    }

    #[test]
    fn basic_blocks_capture_branch_edges_and_unresolved_indirect_jumps() {
        let found = reachable(b"\x75\x03\x90\xc3\x90\xc3", 0, 0x1000, 64, 4).unwrap();
        let decoded = found
            .iter()
            .map(|(_, instruction)| instruction)
            .collect::<Vec<_>>();
        let graph = blocks(&decoded).unwrap();
        assert_eq!(graph.len(), 3);
        assert_eq!((graph[0].start, graph[0].end), (0x1000, 0x1002));
        assert_eq!(graph[0].successors, [0x1002, 0x1005]);
        assert_eq!((graph[1].first_index, graph[1].instruction_count), (1, 2));
        assert!(graph[1].successors.is_empty());
        assert_eq!(graph[2].start, 0x1005);
        let indirect = reachable(b"\xff\xe0\xc3", 0, 0x2000, 64, 3).unwrap();
        let decoded = indirect
            .iter()
            .map(|(_, instruction)| instruction)
            .collect::<Vec<_>>();
        let graph = blocks(&decoded).unwrap();
        assert_eq!(graph.len(), 1);
        assert!(graph[0].unresolved);
        assert!(graph[0].successors.is_empty());
        let outside = reachable(b"\xeb\x7f", 0, 0x3000, 64, 1).unwrap();
        let decoded = outside
            .iter()
            .map(|(_, instruction)| instruction)
            .collect::<Vec<_>>();
        let graph = blocks(&decoded).unwrap();
        assert!(graph[0].unresolved);
        assert_eq!(graph[0].successors, [0x3081]);
    }

    #[test]
    fn direct_xrefs_and_overlapping_instruction_starts_remain_visible() {
        let found = reachable(b"\xe8\x02\0\0\0\xeb\x01\x90\xc3", 0, 0x1000, 64, 4).unwrap();
        let decoded = found
            .iter()
            .map(|(_, instruction)| instruction)
            .collect::<Vec<_>>();
        assert_eq!(call_targets(&decoded), [0x1007]);
        assert_eq!(xrefs(&decoded, 0x1007), [0x1000]);
        assert_eq!(xrefs(&decoded, 0x1008), [0x1005]);
        assert_eq!(overlaps(&decoded).unwrap(), [false; 4]);

        let found = reachable(b"\xe8\x7f\0\0\0\xc3", 0, 0x3000, 64, 2).unwrap();
        let decoded = found
            .iter()
            .map(|(_, instruction)| instruction)
            .collect::<Vec<_>>();
        assert_eq!(call_targets(&decoded), [0x3084]);
        assert_eq!(xrefs(&decoded, 0x3084), [0x3000]);

        let found = reachable(b"\xeb\xff\xc3", 0, 0x2000, 64, 2).unwrap();
        let decoded = found
            .iter()
            .map(|(_, instruction)| instruction)
            .collect::<Vec<_>>();
        assert_eq!(xrefs(&decoded, 0x2001), [0x2000]);
        assert_eq!(overlaps(&decoded).unwrap(), [false, true]);
    }
}
