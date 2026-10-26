use crate::syntax::{Expr, ExprKind, MatchPattern, Op};
use std::collections::VecDeque;

const MAX_INSTRUCTIONS: usize = 1_000_000;
const MAX_STACK: usize = 1_000_000;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Program {
    pub instructions: Vec<Instruction>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum Instruction {
    Int(i64),
    UInt(u64),
    Bool(bool),
    Str(String),
    Load(String),
    Dup,
    Pop,
    Neg,
    BitNot,
    Not,
    EnsureBool,
    Binary(Op),
    Call(String, usize),
    MethodCall(String, usize),
    MakeList(usize),
    Index,
    Field(String),
    JumpIfFalse(usize),
    Jump(usize),
    Try,
}

impl Program {
    pub fn compile(expr: &Expr) -> Result<Self, String> {
        let mut instructions = Vec::new();
        emit(expr, &mut instructions);
        let program = Self { instructions };
        program.verify()?;
        Ok(program)
    }

    pub fn verify(&self) -> Result<(), String> {
        let code = &self.instructions;
        if code.is_empty() || code.len() > MAX_INSTRUCTIONS {
            return Err("bytecode instruction count out of range".into());
        }
        let mut heights = vec![None; code.len() + 1];
        let mut pending = VecDeque::new();
        heights[0] = Some(0_usize);
        pending.push_back(0_usize);
        while let Some(pc) = pending.pop_front() {
            if pc == code.len() {
                continue;
            }
            let height = heights[pc].ok_or("invalid bytecode control flow")?;
            let (pop, push) = match &code[pc] {
                Instruction::Int(_)
                | Instruction::UInt(_)
                | Instruction::Bool(_)
                | Instruction::Str(_)
                | Instruction::Load(_) => (0, 1),
                Instruction::Dup => (1, 2),
                Instruction::Pop => (1, 0),
                Instruction::Neg
                | Instruction::BitNot
                | Instruction::Not
                | Instruction::EnsureBool
                | Instruction::Try
                | Instruction::Field(_) => (1, 1),
                Instruction::Binary(Op::And | Op::Or) => {
                    return Err("logical operators require branch bytecode".into());
                }
                Instruction::Binary(_) => (2, 1),
                Instruction::Call(_, count) => (*count, 1),
                Instruction::MethodCall(_, count) => (count.saturating_add(1), 1),
                Instruction::MakeList(count) if *count <= 100_000 => (*count, 1),
                Instruction::MakeList(_) => return Err("bytecode list limit exceeded".into()),
                Instruction::Index => (2, 1),
                Instruction::JumpIfFalse(_) => (1, 0),
                Instruction::Jump(_) => (0, 0),
            };
            let after = height
                .checked_sub(pop)
                .and_then(|n| n.checked_add(push))
                .ok_or("bytecode stack underflow or overflow")?;
            if after > MAX_STACK {
                return Err("bytecode stack limit exceeded".into());
            }
            let mut successors = [pc + 1, pc + 1];
            let count = match &code[pc] {
                Instruction::JumpIfFalse(target) => {
                    if *target <= pc || *target > code.len() {
                        return Err("invalid bytecode jump".into());
                    }
                    successors[1] = *target;
                    2
                }
                Instruction::Jump(target) => {
                    if *target <= pc || *target > code.len() {
                        return Err("invalid bytecode jump".into());
                    }
                    successors[0] = *target;
                    1
                }
                _ => 1,
            };
            for &target in &successors[..count] {
                match heights[target] {
                    Some(existing) if existing != after => {
                        return Err("inconsistent bytecode stack at branch".into());
                    }
                    Some(_) => {}
                    None => {
                        heights[target] = Some(after);
                        pending.push_back(target);
                    }
                }
            }
        }
        if heights[code.len()] != Some(1) || heights[..code.len()].contains(&None) {
            return Err("invalid bytecode result or unreachable instruction".into());
        }
        Ok(())
    }
}

fn emit(expr: &Expr, out: &mut Vec<Instruction>) {
    match &expr.kind {
        ExprKind::Int(n) => out.push(Instruction::Int(*n)),
        ExprKind::UInt(n) => out.push(Instruction::UInt(*n)),
        ExprKind::Bool(value) => out.push(Instruction::Bool(*value)),
        ExprKind::Str(value) => out.push(Instruction::Str(value.clone())),
        ExprKind::Var(name) => out.push(Instruction::Load(name.clone())),
        ExprKind::List(items) => {
            for item in items {
                emit(item, out);
            }
            out.push(Instruction::MakeList(items.len()));
        }
        ExprKind::Index(list, index) => {
            emit(list, out);
            emit(index, out);
            out.push(Instruction::Index);
        }
        ExprKind::Field(value, field) => {
            emit(value, out);
            out.push(Instruction::Field(field.clone()));
        }
        ExprKind::Neg(inner) => {
            emit(inner, out);
            out.push(Instruction::Neg);
        }
        ExprKind::BitNot(inner) => {
            emit(inner, out);
            out.push(Instruction::BitNot);
        }
        ExprKind::Not(inner) => {
            emit(inner, out);
            out.push(Instruction::Not);
        }
        ExprKind::Binary(left, Op::And, right) => {
            emit(left, out);
            let false_jump = out.len();
            out.push(Instruction::JumpIfFalse(0));
            emit(right, out);
            out.push(Instruction::EnsureBool);
            let end_jump = out.len();
            out.push(Instruction::Jump(0));
            let false_target = out.len();
            out.push(Instruction::Bool(false));
            let end_target = out.len();
            out[false_jump] = Instruction::JumpIfFalse(false_target);
            out[end_jump] = Instruction::Jump(end_target);
        }
        ExprKind::Binary(left, Op::Or, right) => {
            emit(left, out);
            let right_jump = out.len();
            out.push(Instruction::JumpIfFalse(0));
            out.push(Instruction::Bool(true));
            let end_jump = out.len();
            out.push(Instruction::Jump(0));
            let right_target = out.len();
            emit(right, out);
            out.push(Instruction::EnsureBool);
            let end_target = out.len();
            out[right_jump] = Instruction::JumpIfFalse(right_target);
            out[end_jump] = Instruction::Jump(end_target);
        }
        ExprKind::Binary(left, op, right) => {
            emit(left, out);
            emit(right, out);
            out.push(Instruction::Binary(*op));
        }
        ExprKind::Call(name, args) => {
            for arg in args {
                emit(arg, out);
            }
            out.push(Instruction::Call(name.clone(), args.len()));
        }
        ExprKind::MethodCall(receiver, name, args) => {
            emit(receiver, out);
            for arg in args {
                emit(arg, out);
            }
            out.push(Instruction::MethodCall(name.clone(), args.len()));
        }
        ExprKind::Try(inner) => {
            emit(inner, out);
            out.push(Instruction::Try);
        }
        ExprKind::If(condition, yes, no) => {
            emit(condition, out);
            let false_jump = out.len();
            out.push(Instruction::JumpIfFalse(0));
            emit(yes, out);
            let end_jump = out.len();
            out.push(Instruction::Jump(0));
            let false_target = out.len();
            emit(no, out);
            let end_target = out.len();
            out[false_jump] = Instruction::JumpIfFalse(false_target);
            out[end_jump] = Instruction::Jump(end_target);
        }
        ExprKind::Match(subject, arms, default) => {
            emit(subject, out);
            let mut end_jumps = Vec::with_capacity(arms.len());
            for (pattern, value) in arms {
                out.push(Instruction::Dup);
                out.push(match pattern {
                    MatchPattern::Int(value) => Instruction::Int(*value),
                    MatchPattern::UInt(value) => Instruction::UInt(*value),
                    MatchPattern::Bool(value) => Instruction::Bool(*value),
                    MatchPattern::Str(value) => Instruction::Str(value.clone()),
                });
                out.push(Instruction::Binary(Op::Eq));
                let next_jump = out.len();
                out.push(Instruction::JumpIfFalse(0));
                out.push(Instruction::Pop);
                emit(value, out);
                end_jumps.push(out.len());
                out.push(Instruction::Jump(0));
                out[next_jump] = Instruction::JumpIfFalse(out.len());
            }
            out.push(Instruction::Pop);
            emit(default, out);
            let end = out.len();
            for jump in end_jumps {
                out[jump] = Instruction::Jump(end);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Instruction, Program};
    use crate::syntax::Op;

    #[test]
    fn rejects_malformed_control_flow() {
        assert!(Program {
            instructions: vec![Instruction::Neg]
        }
        .verify()
        .is_err());
        assert!(Program {
            instructions: vec![Instruction::MakeList(100_001)]
        }
        .verify()
        .is_err());
        assert!(Program {
            instructions: vec![Instruction::Int(0), Instruction::Index]
        }
        .verify()
        .is_err());
        assert!(Program {
            instructions: vec![Instruction::Jump(0)]
        }
        .verify()
        .is_err());
        assert!(Program {
            instructions: vec![
                Instruction::Bool(true),
                Instruction::JumpIfFalse(3),
                Instruction::Int(1)
            ]
        }
        .verify()
        .is_err());
        assert!(Program {
            instructions: vec![
                Instruction::Bool(true),
                Instruction::Bool(false),
                Instruction::Binary(Op::And),
            ]
        }
        .verify()
        .is_err());
    }
}
