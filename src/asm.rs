use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, InstructionInfoFactory,
    InstructionInfoOptions, IntelFormatter, OpAccess, OpKind, RflagsBits,
};

pub const MAX_DISASSEMBLY: usize = 10_000;

#[derive(Clone, Debug)]
pub struct Decoded {
    pub size: usize,
    pub ip: u64,
    pub text: String,
    pub mnemonic: String,
    pub flow: &'static str,
    pub target: Option<u64>,
    pub data_target: Option<u64>,
    pub register_reads: Vec<String>,
    pub register_writes: Vec<String>,
    pub flags_read: Vec<String>,
    pub flags_modified: Vec<String>,
    pub register_usage_complete: bool,
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
        ) || (self.flow == "transaction"
            && matches!(self.mnemonic.as_str(), "xbegin" | "xabort" | "xend"))
        {
            successors.push(
                self.ip
                    .checked_add(self.size as u64)
                    .ok_or("instruction address overflow")?,
            );
        }
        if matches!(self.flow, "conditional_branch" | "jump" | "call")
            || (self.flow == "transaction" && self.mnemonic == "xbegin")
        {
            if let Some(target) = self.target {
                if !successors.contains(&target) {
                    successors.push(target);
                }
            }
        }
        Ok(successors)
    }
}

pub struct DecodeContext {
    info_factory: InstructionInfoFactory,
    formatter: IntelFormatter,
}

impl DecodeContext {
    pub fn new() -> Self {
        Self {
            info_factory: InstructionInfoFactory::new(),
            formatter: IntelFormatter::new(),
        }
    }

    pub fn decode(
        &mut self,
        bytes: &[u8],
        offset: usize,
        ip: u64,
        bitness: u32,
    ) -> Result<Decoded, String> {
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
        ip.checked_add(instruction.len() as u64)
            .ok_or("instruction address overflow")?;
        let mut text = String::new();
        self.formatter.format(&instruction, &mut text);
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
        let data_target = instruction
            .is_ip_rel_memory_operand()
            .then(|| instruction.ip_rel_memory_address());
        let info = self
            .info_factory
            .info_options(&instruction, InstructionInfoOptions::NO_MEMORY_USAGE);
        let mut register_reads = Vec::new();
        let mut register_writes = Vec::new();
        for register in info.used_registers() {
            let name = format!("{:?}", register.register()).to_ascii_lowercase();
            match register.access() {
                OpAccess::Read | OpAccess::CondRead => register_reads.push(name),
                OpAccess::Write | OpAccess::CondWrite => register_writes.push(name),
                OpAccess::ReadWrite | OpAccess::ReadCondWrite => {
                    register_reads.push(name.clone());
                    register_writes.push(name);
                }
                _ => {}
            }
        }
        register_reads.sort_unstable();
        register_reads.dedup();
        register_writes.sort_unstable();
        register_writes.dedup();
        let flags_read = flag_names(instruction.rflags_read());
        let flags_modified = flag_names(instruction.rflags_modified());
        Ok(Decoded {
            size: instruction.len(),
            ip,
            text,
            mnemonic: format!("{:?}", instruction.mnemonic()).to_ascii_lowercase(),
            flow,
            target,
            data_target,
            register_reads,
            register_writes,
            flags_read,
            flags_modified,
            register_usage_complete: !instruction.is_save_restore_instruction(),
        })
    }
}

pub fn decode(bytes: &[u8], offset: usize, ip: u64, bitness: u32) -> Result<Decoded, String> {
    DecodeContext::new().decode(bytes, offset, ip, bitness)
}

fn flag_names(mask: u32) -> Vec<String> {
    [
        ("cf", RflagsBits::CF),
        ("pf", RflagsBits::PF),
        ("af", RflagsBits::AF),
        ("zf", RflagsBits::ZF),
        ("sf", RflagsBits::SF),
        ("of", RflagsBits::OF),
        ("df", RflagsBits::DF),
        ("if", RflagsBits::IF),
        ("ac", RflagsBits::AC),
        ("uif", RflagsBits::UIF),
        ("c0", RflagsBits::C0),
        ("c1", RflagsBits::C1),
        ("c2", RflagsBits::C2),
        ("c3", RflagsBits::C3),
    ]
    .into_iter()
    .filter(|(_, bit)| mask & bit != 0)
    .map(|(name, _)| name.to_string())
    .collect()
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
    let mut decoder = DecodeContext::new();
    while let Some(offset) = pending.pop_front() {
        if found.len() >= max_instructions {
            return Err("reachable disassembly exceeds max instruction count".into());
        }
        let ip = base_ip
            .checked_add(u64::try_from(offset).map_err(|_| "instruction offset out of range")?)
            .ok_or("instruction address overflow")?;
        let instruction = decoder.decode(bytes, offset, ip, bitness)?;
        let mut enqueue = |candidate: usize| {
            if candidate < bytes.len() && queued.insert(candidate) {
                pending.push_back(candidate);
            }
        };
        for target in instruction.successors()? {
            if let Some(relative) = target.checked_sub(base_ip) {
                if let Ok(relative) = usize::try_from(relative) {
                    enqueue(relative);
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
            if following.ip != next
                || instruction.flow != "next"
                || matches!(instruction.mnemonic.as_str(), "xabort" | "xend")
            {
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
        // The abort destination depends on the surrounding outermost XBEGIN.
        let transaction_exit = matches!(last.mnemonic.as_str(), "xabort" | "xend");
        result.push(Block {
            start: instructions[first_index].ip,
            end: last
                .ip
                .checked_add(last.size as u64)
                .ok_or("instruction address overflow")?,
            first_index,
            instruction_count: index - first_index,
            unresolved: matches!(last.flow, "indirect_jump" | "indirect_call")
                || transaction_exit
                || successors.iter().any(|target| !addresses.contains(target)),
            successors,
        });
        first_index = index;
    }
    Ok(result)
}

/// Return the shortest path of known block starts, ignoring edges outside the
/// decoded graph. Successor order determines ties between equal-length paths.
pub fn block_path(blocks: &[Block], from: usize, to: usize) -> Result<Vec<u64>, String> {
    if from >= blocks.len() || to >= blocks.len() {
        return Err("block index out of range".into());
    }
    let by_start: HashMap<u64, usize> = blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.start, index))
        .collect();
    let mut previous = vec![None; blocks.len()];
    let mut visited = vec![false; blocks.len()];
    let mut queue = VecDeque::from([from]);
    visited[from] = true;
    while let Some(index) = queue.pop_front() {
        if index == to {
            let mut path = Vec::new();
            let mut cursor = Some(index);
            while let Some(at) = cursor {
                path.push(blocks[at].start);
                cursor = previous[at];
            }
            path.reverse();
            return Ok(path);
        }
        for successor in &blocks[index].successors {
            if let Some(&next) = by_start.get(successor) {
                if !visited[next] {
                    visited[next] = true;
                    previous[next] = Some(index);
                    queue.push_back(next);
                }
            }
        }
    }
    Ok(Vec::new())
}

/// Return the known dominators of `target`, ordered from `entry` to `target`.
/// Edges leaving the decoded graph are ignored; unreachable targets return [].
pub fn block_dominators(blocks: &[Block], entry: usize, target: usize) -> Result<Vec<u64>, String> {
    if entry >= blocks.len() || target >= blocks.len() {
        return Err("block index out of range".into());
    }
    let by_start: HashMap<u64, usize> = blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.start, index))
        .collect();
    let mut successors = vec![Vec::new(); blocks.len()];
    let mut predecessors = vec![Vec::new(); blocks.len()];
    for (index, block) in blocks.iter().enumerate() {
        for address in &block.successors {
            if let Some(&next) = by_start.get(address) {
                if !successors[index].contains(&next) {
                    successors[index].push(next);
                    predecessors[next].push(index);
                }
            }
        }
    }

    // Iterative DFS avoids overflowing the host stack on large disassemblies.
    let mut seen = vec![false; blocks.len()];
    let mut postorder = Vec::new();
    let mut stack = vec![(entry, 0)];
    seen[entry] = true;
    while let Some((node, next_edge)) = stack.last_mut() {
        if *next_edge == successors[*node].len() {
            postorder.push(*node);
            stack.pop();
        } else {
            let next = successors[*node][*next_edge];
            *next_edge += 1;
            if !seen[next] {
                seen[next] = true;
                stack.push((next, 0));
            }
        }
    }
    if !seen[target] {
        return Ok(Vec::new());
    }
    postorder.reverse();
    let mut order = vec![usize::MAX; blocks.len()];
    for (position, &node) in postorder.iter().enumerate() {
        order[node] = position;
    }
    let mut idom = vec![None; blocks.len()];
    idom[entry] = Some(entry);
    loop {
        let mut changed = false;
        for &node in postorder.iter().skip(1) {
            let mut incoming = predecessors[node]
                .iter()
                .copied()
                .filter(|&previous| idom[previous].is_some());
            let Some(mut candidate) = incoming.next() else {
                continue;
            };
            for previous in incoming {
                let (mut left, mut right) = (candidate, previous);
                while left != right {
                    while order[left] > order[right] {
                        left = idom[left].expect("reachable dominator");
                    }
                    while order[right] > order[left] {
                        right = idom[right].expect("reachable dominator");
                    }
                }
                candidate = left;
            }
            if idom[node] != Some(candidate) {
                idom[node] = Some(candidate);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let mut result = Vec::new();
    let mut node = target;
    loop {
        result.push(blocks[node].start);
        if node == entry {
            break;
        }
        node = idom[node].expect("reachable dominator");
    }
    result.reverse();
    Ok(result)
}

/// Direct branch and call sites that name `target`, in instruction order.
pub fn xrefs(instructions: &[&Decoded], target: u64) -> Vec<u64> {
    instructions
        .iter()
        .filter(|instruction| {
            (matches!(instruction.flow, "conditional_branch" | "jump" | "call")
                || (instruction.flow == "transaction" && instruction.mnemonic == "xbegin"))
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

/// Distinct IP-relative memory addresses, sorted by address.
pub fn data_refs(instructions: &[&Decoded]) -> Vec<u64> {
    instructions
        .iter()
        .filter_map(|instruction| instruction.data_target)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Instruction addresses that refer to `target` through IP-relative memory.
pub fn data_xrefs(instructions: &[&Decoded], target: u64) -> Vec<u64> {
    instructions
        .iter()
        .filter(|instruction| instruction.data_target == Some(target))
        .map(|instruction| instruction.ip)
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
    use super::{block_dominators, block_path, blocks, call_targets, data_refs, data_xrefs, decode, overlaps, reachable, xrefs, Block};

    #[test]
    fn register_and_flag_usage_includes_implicit_and_conditional_accesses() {
        let mov = decode(b"\x48\x89\xd8", 0, 0x1000, 64).unwrap();
        assert_eq!(mov.register_reads, ["rbx"]);
        assert_eq!(mov.register_writes, ["rax"]);
        assert!(mov.flags_read.is_empty());
        assert!(mov.flags_modified.is_empty());

        let add = decode(b"\x48\x01\xd8", 0, 0x1000, 64).unwrap();
        assert_eq!(add.register_reads, ["rax", "rbx"]);
        assert_eq!(add.register_writes, ["rax"]);
        assert_eq!(add.flags_modified, ["cf", "pf", "af", "zf", "sf", "of"]);

        let branch = decode(b"\x75\x01", 0, 0x1000, 64).unwrap();
        assert_eq!(branch.flags_read, ["zf"]);
        assert!(branch.register_reads.is_empty());

        let push = decode(b"\x50", 0, 0x1000, 64).unwrap();
        assert_eq!(push.register_reads, ["rax", "rsp"]);
        assert_eq!(push.register_writes, ["rsp"]);

        let fxsave = decode(b"\x0f\xae\x00", 0, 0x1000, 64).unwrap();
        assert!(!fxsave.register_usage_complete);
    }

    #[test]
    fn ip_relative_data_references_are_separate_from_branch_targets() {
        let bytes = b"\x48\x8d\x05\x09\0\0\0\x48\x8b\x05\x02\0\0\0\xc3";
        let found = reachable(bytes, 0, 0x1000, 64, 3).unwrap();
        let decoded = found
            .iter()
            .map(|(_, instruction)| instruction)
            .collect::<Vec<_>>();
        assert_eq!(decoded[0].data_target, Some(0x1010));
        assert_eq!(decoded[1].data_target, Some(0x1010));
        assert_eq!(decoded[0].target, None);
        assert_eq!(data_refs(&decoded), [0x1010]);
        assert_eq!(data_xrefs(&decoded, 0x1010), [0x1000, 0x1007]);
        assert!(xrefs(&decoded, 0x1010).is_empty());
        assert!(data_xrefs(&decoded, 0x1011).is_empty());
        let absolute = decode(b"\x48\xa1\x10\x10\0\0\0\0\0\0", 0, 0x2000, 64).unwrap();
        assert_eq!(absolute.data_target, None);
        let indirect = decode(b"\xff\x15\x02\0\0\0", 0, 0x3000, 64).unwrap();
        assert_eq!(indirect.flow, "indirect_call");
        assert_eq!(indirect.target, None);
        assert_eq!(indirect.data_target, Some(0x3008));
    }

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
    fn decoding_rejects_instruction_spans_that_overflow_u64() {
        assert_eq!(
            decode(b"\xc3", 0, u64::MAX, 64).unwrap_err(),
            "instruction address overflow"
        );
        assert_eq!(
            reachable(b"\xc3", 0, u64::MAX, 64, 1).unwrap_err(),
            "instruction address overflow"
        );
        assert_eq!(decode(b"\xc3", 0, u64::MAX - 1, 64).unwrap().size, 1);
    }

    #[test]
    fn transaction_instructions_preserve_fallback_and_fallthrough_paths() {
        let bytes = b"\xc7\xf8\x04\0\0\0\x90\x0f\x01\xd5\xc3";
        let found = reachable(bytes, 0, 0x1000, 64, 4).unwrap();
        assert_eq!(
            found.iter().map(|(offset, _)| *offset).collect::<Vec<_>>(),
            [0, 6, 7, 10]
        );
        let decoded = found
            .iter()
            .map(|(_, instruction)| instruction)
            .collect::<Vec<_>>();
        assert_eq!(decoded[0].mnemonic, "xbegin");
        assert_eq!(decoded[0].target, Some(0x100a));
        assert_eq!(decoded[0].successors().unwrap(), [0x1006, 0x100a]);
        assert_eq!(decoded[2].mnemonic, "xend");
        assert_eq!(decoded[2].successors().unwrap(), [0x100a]);
        assert_eq!(xrefs(&decoded, 0x100a), [0x1000]);
        let graph = blocks(&decoded).unwrap();
        assert_eq!(graph.len(), 3);
        assert_eq!(graph[0].successors, [0x1006, 0x100a]);
        assert_eq!(graph[1].successors, [0x100a]);
        assert!(!graph[0].unresolved);
        assert!(graph[1].unresolved);

        let abort = reachable(b"\xc6\xf8\0\xc3", 0, 0x2000, 64, 2).unwrap();
        let decoded = abort
            .iter()
            .map(|(_, instruction)| instruction)
            .collect::<Vec<_>>();
        assert_eq!(decoded[0].mnemonic, "xabort");
        assert_eq!(decoded[0].successors().unwrap(), [0x2003]);
        let graph = blocks(&decoded).unwrap();
        assert_eq!(graph[0].successors, [0x2003]);
        assert!(graph[0].unresolved);
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
    fn block_path_uses_shortest_known_edges_and_checks_indices() {
        let block = |start, successors: &[u64]| Block {
            start,
            end: start + 1,
            first_index: 0,
            instruction_count: 1,
            successors: successors.to_vec(),
            unresolved: false,
        };
        let graph = [
            block(0x10, &[0x20, 0x30, 0x999]),
            block(0x20, &[0x40]),
            block(0x30, &[0x30, 0x50]),
            block(0x40, &[]),
            block(0x50, &[0x40]),
        ];
        assert_eq!(block_path(&graph, 0, 3).unwrap(), [0x10, 0x20, 0x40]);
        assert_eq!(block_path(&graph, 0, 4).unwrap(), [0x10, 0x30, 0x50]);
        assert!(block_path(&graph, 1, 4).unwrap().is_empty());
        assert_eq!(block_path(&graph, 3, 3).unwrap(), [0x40]);
        assert_eq!(block_path(&graph, 5, 0).unwrap_err(), "block index out of range");
        assert_eq!(block_path(&graph, 0, 5).unwrap_err(), "block index out of range");
    }

    #[test]
    fn block_dominators_handle_diamonds_loops_and_unreachable_blocks() {
        let block = |start, successors: &[u64]| Block {
            start,
            end: start + 1,
            first_index: 0,
            instruction_count: 1,
            successors: successors.to_vec(),
            unresolved: false,
        };
        let graph = [
            block(0x10, &[0x20, 0x30, 0x999]),
            block(0x20, &[0x40]),
            block(0x30, &[0x40]),
            block(0x40, &[0x50]),
            block(0x50, &[0x40, 0x60]),
            block(0x60, &[]),
            block(0x70, &[]),
        ];
        assert_eq!(block_dominators(&graph, 0, 3).unwrap(), [0x10, 0x40]);
        assert_eq!(
            block_dominators(&graph, 0, 5).unwrap(),
            [0x10, 0x40, 0x50, 0x60]
        );
        assert_eq!(
            block_dominators(&graph, 1, 5).unwrap(),
            [0x20, 0x40, 0x50, 0x60]
        );
        assert!(block_dominators(&graph, 0, 6).unwrap().is_empty());
        assert_eq!(block_dominators(&graph, 6, 6).unwrap(), [0x70]);
        assert_eq!(
            block_dominators(&graph, 7, 0).unwrap_err(),
            "block index out of range"
        );
        assert_eq!(
            block_dominators(&graph, 0, 7).unwrap_err(),
            "block index out of range"
        );
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
