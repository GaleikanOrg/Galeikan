use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, PartialEq)]
pub enum TokenKind {
    Ident(String),
    Number(i64),
    Unsigned(u64),
    String(String),
    Plus,
    Minus,
    Star,
    Slash,
    Ampersand,
    Pipe,
    Caret,
    Tilde,
    ShiftLeft,
    ShiftRight,
    UnsignedShiftRight,
    LParen,
    RParen,
    LBracket,
    RBracket,
    LBrace,
    RBrace,
    Comma,
    Dot,
    Colon,
    Arrow,
    FatArrow,
    Question,
    Equal,
    EqualEqual,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    Newline,
    Eof,
}

#[derive(Clone, Debug)]
pub struct Token {
    pub kind: TokenKind,
    pub line: usize,
    pub col: usize,
}

pub fn lex(input: &str) -> Result<Vec<Token>, String> {
    let mut lexer = Lexer {
        input,
        pos: 0,
        line: 1,
        col: 1,
    };
    let mut tokens = Vec::new();
    loop {
        let line = lexer.line;
        let col = lexer.col;
        let Some(ch) = lexer.peek() else { break };
        let kind = match ch {
            ' ' | '\t' | '\r' => {
                lexer.bump();
                continue;
            }
            '\n' => {
                lexer.bump();
                TokenKind::Newline
            }
            '#' => {
                while !matches!(lexer.peek(), None | Some('\n')) {
                    lexer.bump();
                }
                continue;
            }
            '+' => {
                lexer.bump();
                TokenKind::Plus
            }
            '-' => {
                lexer.bump();
                if lexer.peek() == Some('>') {
                    lexer.bump();
                    TokenKind::Arrow
                } else {
                    TokenKind::Minus
                }
            }
            ':' => {
                lexer.bump();
                TokenKind::Colon
            }
            '?' => {
                lexer.bump();
                TokenKind::Question
            }
            '*' => {
                lexer.bump();
                TokenKind::Star
            }
            '/' => {
                lexer.bump();
                TokenKind::Slash
            }
            '&' => {
                lexer.bump();
                TokenKind::Ampersand
            }
            '|' => {
                lexer.bump();
                TokenKind::Pipe
            }
            '^' => {
                lexer.bump();
                TokenKind::Caret
            }
            '~' => {
                lexer.bump();
                TokenKind::Tilde
            }
            '(' => {
                lexer.bump();
                TokenKind::LParen
            }
            ')' => {
                lexer.bump();
                TokenKind::RParen
            }
            '[' => {
                lexer.bump();
                TokenKind::LBracket
            }
            ']' => {
                lexer.bump();
                TokenKind::RBracket
            }
            '{' => {
                lexer.bump();
                TokenKind::LBrace
            }
            '}' => {
                lexer.bump();
                TokenKind::RBrace
            }
            ',' => {
                lexer.bump();
                TokenKind::Comma
            }
            '.' => {
                lexer.bump();
                TokenKind::Dot
            }
            '=' => {
                lexer.bump();
                if lexer.peek() == Some('=') {
                    lexer.bump();
                    TokenKind::EqualEqual
                } else if lexer.peek() == Some('>') {
                    lexer.bump();
                    TokenKind::FatArrow
                } else {
                    TokenKind::Equal
                }
            }
            '!' => {
                lexer.bump();
                if lexer.peek() != Some('=') {
                    return Err(format!("{line}:{col}: expected '=' after '!'"));
                }
                lexer.bump();
                TokenKind::NotEqual
            }
            '<' => {
                lexer.bump();
                if lexer.peek() == Some('<') {
                    lexer.bump();
                    TokenKind::ShiftLeft
                } else if lexer.peek() == Some('=') {
                    lexer.bump();
                    TokenKind::LessEqual
                } else {
                    TokenKind::Less
                }
            }
            '>' => {
                lexer.bump();
                if lexer.peek() == Some('>') {
                    lexer.bump();
                    if lexer.peek() == Some('>') {
                        lexer.bump();
                        TokenKind::UnsignedShiftRight
                    } else {
                        TokenKind::ShiftRight
                    }
                } else if lexer.peek() == Some('=') {
                    lexer.bump();
                    TokenKind::GreaterEqual
                } else {
                    TokenKind::Greater
                }
            }
            '"' => {
                lexer.bump();
                let mut value = String::new();
                loop {
                    match lexer.peek() {
                        None | Some('\n') => {
                            return Err(format!("{line}:{col}: unterminated string"))
                        }
                        Some('"') => {
                            lexer.bump();
                            break;
                        }
                        Some('\\') => {
                            lexer.bump();
                            let escaped = match lexer.peek() {
                                Some('n') => '\n',
                                Some('t') => '\t',
                                Some('r') => '\r',
                                Some('"') => '"',
                                Some('\\') => '\\',
                                _ => {
                                    return Err(format!(
                                        "{}:{}: invalid escape sequence",
                                        lexer.line, lexer.col
                                    ))
                                }
                            };
                            lexer.bump();
                            value.push(escaped);
                        }
                        Some(c) => {
                            lexer.bump();
                            value.push(c);
                        }
                    }
                }
                TokenKind::String(value)
            }
            c if c.is_ascii_digit() => {
                let start = lexer.pos;
                if c == '0' && lexer.input[lexer.pos..].starts_with("0x") {
                    lexer.bump();
                    lexer.bump();
                    let digits = lexer.pos;
                    while matches!(lexer.peek(), Some(c) if c.is_ascii_hexdigit()) {
                        lexer.bump();
                    }
                    if digits == lexer.pos {
                        return Err(format!("{line}:{col}: hex literal has no digits"));
                    }
                    let n = u64::from_str_radix(&lexer.input[digits..lexer.pos], 16)
                        .map_err(|_| format!("{line}:{col}: integer overflow"))?;
                    if lexer.input[lexer.pos..].starts_with("u64") {
                        for _ in 0..3 {
                            lexer.bump();
                        }
                        TokenKind::Unsigned(n)
                    } else {
                        TokenKind::Number(n as i64)
                    }
                } else {
                    while matches!(lexer.peek(), Some(c) if c.is_ascii_digit()) {
                        lexer.bump();
                    }
                    if lexer.input[lexer.pos..].starts_with("u64") {
                        let n = lexer.input[start..lexer.pos]
                            .parse::<u64>()
                            .map_err(|_| format!("{line}:{col}: integer overflow"))?;
                        for _ in 0..3 {
                            lexer.bump();
                        }
                        TokenKind::Unsigned(n)
                    } else {
                        let n = lexer.input[start..lexer.pos]
                            .parse::<i64>()
                            .map_err(|_| format!("{line}:{col}: integer overflow"))?;
                        TokenKind::Number(n)
                    }
                }
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let start = lexer.pos;
                while matches!(lexer.peek(), Some(c) if c.is_ascii_alphanumeric() || c == '_' || c == '.')
                {
                    lexer.bump();
                }
                TokenKind::Ident(lexer.input[start..lexer.pos].to_string())
            }
            _ => return Err(format!("{line}:{col}: unexpected character {ch:?}")),
        };
        tokens.push(Token { kind, line, col });
    }
    tokens.push(Token {
        kind: TokenKind::Eof,
        line: lexer.line,
        col: lexer.col,
    });
    Ok(tokens)
}

struct Lexer<'a> {
    input: &'a str,
    pos: usize,
    line: usize,
    col: usize,
}
impl Lexer<'_> {
    fn peek(&self) -> Option<char> {
        self.input[self.pos..].chars().next()
    }
    fn bump(&mut self) {
        if let Some(c) = self.peek() {
            self.pos += c.len_utf8();
            if c == '\n' {
                self.line += 1;
                self.col = 1;
            } else {
                self.col += 1;
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct Expr {
    pub kind: ExprKind,
    pub line: usize,
    pub col: usize,
}
#[derive(Clone, Debug)]
pub enum ExprKind {
    Int(i64),
    UInt(u64),
    Bool(bool),
    Str(String),
    Var(String),
    List(Vec<Expr>),
    Index(Box<Expr>, Box<Expr>),
    Field(Box<Expr>, String),
    Call(String, Vec<Expr>),
    MethodCall(Box<Expr>, String, Vec<Expr>),
    Neg(Box<Expr>),
    BitNot(Box<Expr>),
    Not(Box<Expr>),
    Binary(Box<Expr>, Op, Box<Expr>),
    If(Box<Expr>, Box<Expr>, Box<Expr>),
    Match(Box<Expr>, Vec<(MatchPattern, Expr)>, Box<Expr>),
    Try(Box<Expr>),
}
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum MatchPattern {
    Int(i64),
    UInt(u64),
    Bool(bool),
    Str(String),
}
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub enum Op {
    Add,
    Sub,
    Mul,
    Div,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    BitAnd,
    BitOr,
    BitXor,
    Shl,
    Shr,
    Ushr,
}

#[derive(Clone, Debug)]
pub struct Stmt {
    pub kind: StmtKind,
    pub line: usize,
    pub col: usize,
}
#[derive(Clone, Debug)]
pub enum StmtKind {
    Requires(Vec<String>),
    Import(String, String, Vec<String>),
    Struct(String, Vec<Param>),
    Let(String, Option<String>, Expr),
    Var(String, Option<String>, Expr),
    Assign(String, Expr),
    Function(String, Vec<Param>, Option<String>, FunctionBody),
    Print(Expr),
    Impact(Expr),
    For(String, Expr, Vec<BlockStmt>),
    While(Expr, Vec<BlockStmt>),
    If(Expr, Vec<BlockStmt>, Vec<BlockStmt>),
}

#[derive(Clone, Debug)]
pub struct BlockStmt {
    pub kind: BlockStmtKind,
    pub line: usize,
    pub col: usize,
}

#[derive(Clone, Debug)]
pub enum BlockStmtKind {
    Let(String, Option<String>, Expr),
    Var(String, Option<String>, Expr),
    Assign(String, Expr),
    Print(Expr),
    Impact(Expr),
    Return(Expr),
    Break,
    Continue,
    For(String, Expr, Vec<BlockStmt>),
    While(Expr, Vec<BlockStmt>),
    If(Expr, Vec<BlockStmt>, Vec<BlockStmt>),
}

#[derive(Clone, Debug)]
pub struct Param {
    pub name: String,
    pub annotation: Option<String>,
}

#[derive(Clone, Debug)]
pub enum FunctionBody {
    Expression(Expr),
    Block(Vec<BlockStmt>, Option<Expr>),
}

pub fn parse(tokens: Vec<Token>) -> Result<Vec<Stmt>, String> {
    let mut parser = Parser {
        tokens,
        pos: 0,
        expr_depth: 0,
        block_depth: 0,
        loop_depth: 0,
        from_imports: Vec::new(),
    };
    let mut statements = parser.program()?;
    resolve_from_imports(&mut statements, &parser.from_imports)?;
    Ok(statements)
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    expr_depth: usize,
    block_depth: usize,
    loop_depth: usize,
    from_imports: Vec<(String, String, usize, usize)>,
}
impl Parser {
    fn current(&self) -> &Token {
        &self.tokens[self.pos]
    }
    fn bump(&mut self) -> Token {
        let t = self.current().clone();
        if !matches!(t.kind, TokenKind::Eof) {
            self.pos += 1;
        }
        t
    }
    fn error(&self, message: &str) -> String {
        format!("{}:{}: {message}", self.current().line, self.current().col)
    }
    fn expect(&mut self, kind: TokenKind) -> Result<(), String> {
        if self.current().kind == kind {
            self.bump();
            Ok(())
        } else {
            Err(self.error(&format!("expected {kind:?}")))
        }
    }
    fn ident(&mut self) -> Result<String, String> {
        match self.bump().kind {
            TokenKind::Ident(v) => Ok(v),
            _ => Err(self.error("identifier expected")),
        }
    }
    fn binding_ident(&mut self) -> Result<String, String> {
        let name = self.ident()?;
        if valid_binding_name(&name) {
            Ok(name)
        } else {
            Err(self.error("invalid or reserved binding name"))
        }
    }
    fn type_name(&mut self) -> Result<String, String> {
        let name = self.ident()?;
        if name != "Result" && name != "List" {
            return Ok(name);
        }
        self.expect(TokenKind::Less)?;
        let inner = self.ident()?;
        self.expect(TokenKind::Greater)?;
        Ok(format!("{name}<{inner}>"))
    }
    fn optional_type(&mut self) -> Result<Option<String>, String> {
        if self.current().kind == TokenKind::Colon {
            self.bump();
            Ok(Some(self.type_name()?))
        } else {
            Ok(None)
        }
    }
    fn line_end(&mut self) -> Result<(), String> {
        match self.current().kind {
            TokenKind::Newline => {
                self.bump();
                Ok(())
            }
            TokenKind::Eof => Ok(()),
            _ => Err(self.error("end of line expected")),
        }
    }
    fn skip_newlines(&mut self) {
        while self.current().kind == TokenKind::Newline {
            self.bump();
        }
    }
    fn program(&mut self) -> Result<Vec<Stmt>, String> {
        let mut out = Vec::new();
        while !matches!(self.current().kind, TokenKind::Eof) {
            if matches!(self.current().kind, TokenKind::Newline) {
                self.bump();
                continue;
            }
            let line = self.current().line;
            let col = self.current().col;
            let word = self.ident()?;
            let mut extra = Vec::new();
            let kind = match word.as_str() {
                "requires" => {
                    self.expect(TokenKind::LBrace)?;
                    self.skip_newlines();
                    let mut effects = Vec::new();
                    while self.current().kind != TokenKind::RBrace {
                        effects.push(self.ident()?);
                        self.skip_newlines();
                        if self.current().kind != TokenKind::Comma {
                            break;
                        }
                        self.bump();
                        self.skip_newlines();
                    }
                    self.expect(TokenKind::RBrace)?;
                    StmtKind::Requires(effects)
                }
                "import" => {
                    let target = match self.bump().kind {
                        TokenKind::Ident(v) | TokenKind::String(v) => v,
                        _ => return Err(self.error("module name or path expected")),
                    };
                    let alias = if self.current().kind == TokenKind::Ident("as".into()) {
                        self.bump();
                        self.binding_ident()?
                    } else {
                        default_import_alias(&target)
                            .ok_or_else(|| self.error("import needs an explicit alias"))?
                    };
                    StmtKind::Import(target, alias, Vec::new())
                }
                "from" => {
                    let target = match self.bump().kind {
                        TokenKind::Ident(v) | TokenKind::String(v) => v,
                        _ => return Err(self.error("module name or path expected")),
                    };
                    self.expect(TokenKind::Ident("import".into()))?;
                    let hidden_alias = format!("__galeikan_from_{}", self.from_imports.len());
                    let grouped = self.current().kind == TokenKind::LParen;
                    if grouped {
                        self.bump();
                        self.skip_newlines();
                    }
                    let mut count = 0;
                    let mut selected_symbols = Vec::new();
                    loop {
                        if grouped && self.current().kind == TokenKind::RParen {
                            if count == 0 {
                                return Err(self.error("import group cannot be empty"));
                            }
                            self.bump();
                            break;
                        }
                        let symbol = self.binding_ident()?;
                        let alias = if self.current().kind == TokenKind::Ident("as".into()) {
                            self.bump();
                            self.binding_ident()?
                        } else {
                            symbol.clone()
                        };
                        self.from_imports.push((
                            alias,
                            format!("{hidden_alias}.{symbol}"),
                            line,
                            col,
                        ));
                        selected_symbols.push(symbol);
                        count += 1;
                        if self.current().kind != TokenKind::Comma {
                            if grouped {
                                self.skip_newlines();
                                self.expect(TokenKind::RParen)?;
                            }
                            break;
                        }
                        self.bump();
                        if grouped {
                            self.skip_newlines();
                        }
                    }
                    StmtKind::Import(target, hidden_alias, selected_symbols)
                }
                "let" => {
                    let name = self.binding_ident()?;
                    let annotation = self.optional_type()?;
                    self.expect(TokenKind::Equal)?;
                    StmtKind::Let(name, annotation, self.expr(0)?)
                }
                "struct" => {
                    let name = self.binding_ident()?;
                    self.expect(TokenKind::LBrace)?;
                    self.skip_newlines();
                    let mut fields = Vec::new();
                    while self.current().kind != TokenKind::RBrace {
                        if fields.len() >= 64 {
                            return Err(self.error("struct exceeds 64 fields"));
                        }
                        let field = self.binding_ident()?;
                        self.expect(TokenKind::Colon)?;
                        let annotation = self.type_name()?;
                        fields.push(Param {
                            name: field,
                            annotation: Some(annotation),
                        });
                        self.skip_newlines();
                        if self.current().kind == TokenKind::RBrace {
                            break;
                        }
                        self.expect(TokenKind::Comma)?;
                        self.skip_newlines();
                    }
                    self.expect(TokenKind::RBrace)?;
                    StmtKind::Struct(name, fields)
                }
                "class" => {
                    let (name, fields, methods) = self.class_decl()?;
                    extra = methods;
                    StmtKind::Struct(name, fields)
                }
                "var" => {
                    let name = self.binding_ident()?;
                    let annotation = self.optional_type()?;
                    self.expect(TokenKind::Equal)?;
                    StmtKind::Var(name, annotation, self.expr(0)?)
                }
                "fn" => {
                    let (name, params, result_type, body) = self.function_decl()?;
                    StmtKind::Function(name, params, result_type, body)
                }
                "print" => StmtKind::Print(self.expr(0)?),
                "impact" => StmtKind::Impact(self.expr(0)?),
                "for" => {
                    let (name, iterable, body) = self.for_statement()?;
                    StmtKind::For(name, iterable, body)
                }
                "while" => {
                    let (condition, body) = self.while_statement()?;
                    StmtKind::While(condition, body)
                }
                "if" => {
                    let (condition, yes, no) = self.if_statement()?;
                    StmtKind::If(condition, yes, no)
                }
                _ if valid_binding_name(&word) && self.current().kind == TokenKind::Equal => {
                    self.bump();
                    StmtKind::Assign(word, self.expr(0)?)
                }
                _ => return Err(format!("{line}:{col}: unknown statement '{word}'")),
            };
            self.line_end()?;
            out.push(Stmt { kind, line, col });
            out.extend(extra);
        }
        Ok(out)
    }
    fn function_decl(
        &mut self,
    ) -> Result<(String, Vec<Param>, Option<String>, FunctionBody), String> {
        let name = self.binding_ident()?;
        self.expect(TokenKind::LParen)?;
        self.skip_newlines();
        let mut params = Vec::new();
        if self.current().kind != TokenKind::RParen {
            loop {
                let name = self.binding_ident()?;
                let annotation = self.optional_type()?;
                params.push(Param { name, annotation });
                self.skip_newlines();
                if self.current().kind != TokenKind::Comma {
                    break;
                }
                self.bump();
                self.skip_newlines();
                if self.current().kind == TokenKind::RParen {
                    break;
                }
            }
        }
        self.expect(TokenKind::RParen)?;
        let result_type = if self.current().kind == TokenKind::Arrow {
            self.bump();
            Some(self.type_name()?)
        } else {
            None
        };
        let body = match self.current().kind {
            TokenKind::Equal => {
                self.bump();
                FunctionBody::Expression(self.expr(0)?)
            }
            TokenKind::LBrace => self.function_block()?,
            _ => return Err(self.error("expected '=' or a function block")),
        };
        Ok((name, params, result_type, body))
    }
    fn class_decl(&mut self) -> Result<(String, Vec<Param>, Vec<Stmt>), String> {
        let name = self.binding_ident()?;
        self.expect(TokenKind::LBrace)?;
        self.expect(TokenKind::Newline)?;
        let mut fields = Vec::new();
        let mut methods = Vec::new();
        let mut members = HashSet::new();
        loop {
            self.skip_newlines();
            if self.current().kind == TokenKind::RBrace {
                self.bump();
                break;
            }
            if self.current().kind == TokenKind::Eof {
                return Err(self.error("unterminated class"));
            }
            let line = self.current().line;
            let col = self.current().col;
            if self.current().kind == TokenKind::Ident("fn".into()) {
                if methods.len() >= 64 {
                    return Err(self.error("class exceeds 64 methods"));
                }
                self.bump();
                let (method, mut params, result_type, body) = self.function_decl()?;
                if !members.insert(method.clone()) || params.iter().any(|p| p.name == "self") {
                    return Err(self.error("duplicate class member or explicit self parameter"));
                }
                self.line_end()?;
                params.insert(
                    0,
                    Param {
                        name: "self".into(),
                        annotation: Some(name.clone()),
                    },
                );
                methods.push(Stmt {
                    kind: StmtKind::Function(
                        class_method_key(&name, &method),
                        params,
                        result_type,
                        body,
                    ),
                    line,
                    col,
                });
            } else {
                if fields.len() >= 64 {
                    return Err(self.error("class exceeds 64 fields"));
                }
                let field = self.binding_ident()?;
                if !members.insert(field.clone()) {
                    return Err(self.error("duplicate class member"));
                }
                self.expect(TokenKind::Colon)?;
                let annotation = self.type_name()?;
                self.line_end()?;
                fields.push(Param {
                    name: field,
                    annotation: Some(annotation),
                });
            }
        }
        Ok((name, fields, methods))
    }
    fn function_block(&mut self) -> Result<FunctionBody, String> {
        if self.block_depth >= 32 {
            return Err(self.error("block nesting too deep"));
        }
        self.block_depth += 1;
        self.expect(TokenKind::LBrace)?;
        self.expect(TokenKind::Newline)?;
        let mut steps = Vec::new();
        loop {
            while self.current().kind == TokenKind::Newline {
                self.bump();
            }
            if self.current().kind == TokenKind::RBrace {
                if !block_always_returns(&steps) {
                    return Err(self.error("function block needs a return on every path"));
                }
                self.bump();
                self.block_depth -= 1;
                return Ok(FunctionBody::Block(steps, None));
            }
            let line = self.current().line;
            let col = self.current().col;
            let word = self.ident()?;
            match word.as_str() {
                "return" => {
                    let result = self.expr(0)?;
                    self.line_end()?;
                    self.expect(TokenKind::RBrace)?;
                    self.block_depth -= 1;
                    return Ok(FunctionBody::Block(steps, Some(result)));
                }
                _ => {
                    let kind = self.block_step(&word)?;
                    self.line_end()?;
                    steps.push(BlockStmt { kind, line, col });
                }
            }
        }
    }
    fn for_statement(&mut self) -> Result<(String, Expr, Vec<BlockStmt>), String> {
        let name = self.binding_ident()?;
        self.expect(TokenKind::Ident("in".into()))?;
        let iterable = self.expr(0)?;
        self.loop_depth += 1;
        let body = self.action_block();
        self.loop_depth -= 1;
        let body = body?;
        Ok((name, iterable, body))
    }
    fn while_statement(&mut self) -> Result<(Expr, Vec<BlockStmt>), String> {
        let condition = self.expr(0)?;
        self.loop_depth += 1;
        let body = self.action_block();
        self.loop_depth -= 1;
        let body = body?;
        Ok((condition, body))
    }
    fn if_statement(&mut self) -> Result<(Expr, Vec<BlockStmt>, Vec<BlockStmt>), String> {
        let condition = self.expr(0)?;
        let yes = self.action_block()?;
        let mut next = self.pos;
        while self.tokens[next].kind == TokenKind::Newline {
            next += 1;
        }
        let no = if self.tokens[next].kind == TokenKind::Ident("else".into()) {
            self.pos = next + 1;
            self.skip_newlines();
            if self.current().kind == TokenKind::Ident("if".into()) {
                if self.block_depth >= 32 {
                    return Err(self.error("block nesting too deep"));
                }
                let token = self.bump();
                self.block_depth += 1;
                let result = self.if_statement();
                self.block_depth -= 1;
                let (condition, yes, no) = result?;
                vec![BlockStmt {
                    kind: BlockStmtKind::If(condition, yes, no),
                    line: token.line,
                    col: token.col,
                }]
            } else {
                self.action_block()?
            }
        } else {
            Vec::new()
        };
        Ok((condition, yes, no))
    }
    fn action_block(&mut self) -> Result<Vec<BlockStmt>, String> {
        if self.block_depth >= 32 {
            return Err(self.error("block nesting too deep"));
        }
        self.block_depth += 1;
        self.expect(TokenKind::LBrace)?;
        self.expect(TokenKind::Newline)?;
        let mut steps = Vec::new();
        loop {
            while self.current().kind == TokenKind::Newline {
                self.bump();
            }
            if self.current().kind == TokenKind::RBrace {
                self.bump();
                self.block_depth -= 1;
                return Ok(steps);
            }
            if self.current().kind == TokenKind::Eof {
                return Err(self.error("unterminated action block"));
            }
            let line = self.current().line;
            let col = self.current().col;
            let word = self.ident()?;
            let kind = self.block_step(&word)?;
            self.line_end()?;
            steps.push(BlockStmt { kind, line, col });
        }
    }
    fn block_step(&mut self, word: &str) -> Result<BlockStmtKind, String> {
        match word {
            "let" => {
                let name = self.binding_ident()?;
                let annotation = self.optional_type()?;
                self.expect(TokenKind::Equal)?;
                Ok(BlockStmtKind::Let(name, annotation, self.expr(0)?))
            }
            "var" => {
                let name = self.binding_ident()?;
                let annotation = self.optional_type()?;
                self.expect(TokenKind::Equal)?;
                Ok(BlockStmtKind::Var(name, annotation, self.expr(0)?))
            }
            "print" => Ok(BlockStmtKind::Print(self.expr(0)?)),
            "impact" => Ok(BlockStmtKind::Impact(self.expr(0)?)),
            "return" => Ok(BlockStmtKind::Return(self.expr(0)?)),
            "break" | "continue" if self.loop_depth == 0 => {
                Err(self.error("break and continue require a loop"))
            }
            "break" => Ok(BlockStmtKind::Break),
            "continue" => Ok(BlockStmtKind::Continue),
            "for" => {
                let (name, iterable, body) = self.for_statement()?;
                Ok(BlockStmtKind::For(name, iterable, body))
            }
            "while" => {
                let (condition, body) = self.while_statement()?;
                Ok(BlockStmtKind::While(condition, body))
            }
            "if" => {
                let (condition, yes, no) = self.if_statement()?;
                Ok(BlockStmtKind::If(condition, yes, no))
            }
            _ if valid_binding_name(word) && self.current().kind == TokenKind::Equal => {
                self.bump();
                Ok(BlockStmtKind::Assign(word.to_string(), self.expr(0)?))
            }
            _ => Err(self.error(
                "block supports let, var, assignment, print, impact, return, break, continue, for, while, and if",
            )),
        }
    }
    fn expr(&mut self, min_prec: u8) -> Result<Expr, String> {
        if self.expr_depth >= 128 {
            return Err(self.error("expression nesting too deep"));
        }
        self.expr_depth += 1;
        let result = self.expr_inner(min_prec);
        self.expr_depth -= 1;
        result
    }
    fn expr_inner(&mut self, min_prec: u8) -> Result<Expr, String> {
        let token = self.bump();
        let mut left = match token.kind {
            TokenKind::Number(n) => Expr {
                kind: ExprKind::Int(n),
                line: token.line,
                col: token.col,
            },
            TokenKind::Unsigned(n) => Expr {
                kind: ExprKind::UInt(n),
                line: token.line,
                col: token.col,
            },
            TokenKind::String(s) => Expr {
                kind: ExprKind::Str(s),
                line: token.line,
                col: token.col,
            },
            TokenKind::Ident(name) if name == "true" || name == "false" => Expr {
                kind: ExprKind::Bool(name == "true"),
                line: token.line,
                col: token.col,
            },
            TokenKind::Ident(name) if name == "if" => self.if_expression(token.line, token.col)?,
            TokenKind::Ident(name) if name == "match" => {
                self.match_expression(token.line, token.col)?
            }
            TokenKind::Ident(name) if name == "not" => {
                let inner = self.expr(3)?;
                Expr {
                    kind: ExprKind::Not(Box::new(inner)),
                    line: token.line,
                    col: token.col,
                }
            }
            TokenKind::Ident(name) => {
                if self.current().kind == TokenKind::LParen {
                    let args = self.call_args()?;
                    Expr {
                        kind: ExprKind::Call(name, args),
                        line: token.line,
                        col: token.col,
                    }
                } else {
                    Expr {
                        kind: ExprKind::Var(name),
                        line: token.line,
                        col: token.col,
                    }
                }
            }
            TokenKind::Minus => {
                let inner = self.expr(11)?;
                Expr {
                    kind: ExprKind::Neg(Box::new(inner)),
                    line: token.line,
                    col: token.col,
                }
            }
            TokenKind::Tilde => {
                let inner = self.expr(11)?;
                Expr {
                    kind: ExprKind::BitNot(Box::new(inner)),
                    line: token.line,
                    col: token.col,
                }
            }
            TokenKind::LParen => {
                self.skip_newlines();
                let value = self.expr(0)?;
                self.skip_newlines();
                self.expect(TokenKind::RParen)?;
                value
            }
            TokenKind::LBracket => {
                let mut items = Vec::new();
                self.skip_newlines();
                while self.current().kind != TokenKind::RBracket {
                    if items.len() >= 100_000 {
                        return Err(self.error("list literal exceeds 100000 items"));
                    }
                    items.push(self.expr(0)?);
                    self.skip_newlines();
                    if self.current().kind != TokenKind::Comma {
                        break;
                    }
                    self.bump();
                    self.skip_newlines();
                }
                self.expect(TokenKind::RBracket)?;
                Expr {
                    kind: ExprKind::List(items),
                    line: token.line,
                    col: token.col,
                }
            }
            _ => return Err(format!("{}:{}: expression expected", token.line, token.col)),
        };
        loop {
            if self.current().kind == TokenKind::Dot {
                self.bump();
                let fields = self.ident()?;
                let parts = fields.split('.').collect::<Vec<_>>();
                for (index, field) in parts.iter().enumerate() {
                    if !valid_binding_name(field) || field.is_empty() {
                        return Err(self.error("invalid field name"));
                    }
                    let kind = if index + 1 == parts.len()
                        && self.current().kind == TokenKind::LParen
                    {
                        ExprKind::MethodCall(Box::new(left), field.to_string(), self.call_args()?)
                    } else {
                        ExprKind::Field(Box::new(left), field.to_string())
                    };
                    left = Expr {
                        kind,
                        line: token.line,
                        col: token.col,
                    };
                }
                continue;
            }
            if self.current().kind == TokenKind::LBracket {
                self.bump();
                let index = self.expr(0)?;
                self.expect(TokenKind::RBracket)?;
                left = Expr {
                    kind: ExprKind::Index(Box::new(left), Box::new(index)),
                    line: token.line,
                    col: token.col,
                };
                continue;
            }
            if self.current().kind == TokenKind::Question {
                self.bump();
                let line = left.line;
                let col = left.col;
                left = Expr {
                    kind: ExprKind::Try(Box::new(left)),
                    line,
                    col,
                };
                continue;
            }
            let (prec, op) = match self.current().kind {
                TokenKind::Ident(ref word) if word == "or" => (1, Op::Or),
                TokenKind::Ident(ref word) if word == "and" => (2, Op::And),
                TokenKind::EqualEqual => (3, Op::Eq),
                TokenKind::NotEqual => (3, Op::Ne),
                TokenKind::Less => (4, Op::Lt),
                TokenKind::LessEqual => (4, Op::Le),
                TokenKind::Greater => (4, Op::Gt),
                TokenKind::GreaterEqual => (4, Op::Ge),
                TokenKind::Pipe => (5, Op::BitOr),
                TokenKind::Caret => (6, Op::BitXor),
                TokenKind::Ampersand => (7, Op::BitAnd),
                TokenKind::ShiftLeft => (8, Op::Shl),
                TokenKind::ShiftRight => (8, Op::Shr),
                TokenKind::UnsignedShiftRight => (8, Op::Ushr),
                TokenKind::Plus => (9, Op::Add),
                TokenKind::Minus => (9, Op::Sub),
                TokenKind::Star => (10, Op::Mul),
                TokenKind::Slash => (10, Op::Div),
                _ => break,
            };
            if prec < min_prec {
                break;
            }
            self.bump();
            let right = self.expr(prec + 1)?;
            let line = left.line;
            let col = left.col;
            left = Expr {
                kind: ExprKind::Binary(Box::new(left), op, Box::new(right)),
                line,
                col,
            };
        }
        Ok(left)
    }
    fn call_args(&mut self) -> Result<Vec<Expr>, String> {
        self.expect(TokenKind::LParen)?;
        self.skip_newlines();
        let mut args = Vec::new();
        if self.current().kind != TokenKind::RParen {
            loop {
                args.push(self.expr(0)?);
                self.skip_newlines();
                if self.current().kind != TokenKind::Comma {
                    break;
                }
                self.bump();
                self.skip_newlines();
                if self.current().kind == TokenKind::RParen {
                    break;
                }
            }
        }
        self.expect(TokenKind::RParen)?;
        Ok(args)
    }

    fn if_expression(&mut self, line: usize, col: usize) -> Result<Expr, String> {
        let condition = self.expr(0)?;
        self.skip_newlines();
        self.expect(TokenKind::LBrace)?;
        self.skip_newlines();
        let when_true = self.expr(0)?;
        self.skip_newlines();
        self.expect(TokenKind::RBrace)?;
        self.skip_newlines();
        self.expect(TokenKind::Ident("else".into()))?;
        self.skip_newlines();
        let when_false = if self.current().kind == TokenKind::Ident("if".into()) {
            if self.expr_depth >= 128 {
                return Err(self.error("expression nesting too deep"));
            }
            let next = self.bump();
            self.expr_depth += 1;
            let result = self.if_expression(next.line, next.col);
            self.expr_depth -= 1;
            result?
        } else {
            self.expect(TokenKind::LBrace)?;
            self.skip_newlines();
            let value = self.expr(0)?;
            self.skip_newlines();
            self.expect(TokenKind::RBrace)?;
            value
        };
        Ok(Expr {
            kind: ExprKind::If(
                Box::new(condition),
                Box::new(when_true),
                Box::new(when_false),
            ),
            line,
            col,
        })
    }

    fn match_expression(&mut self, line: usize, col: usize) -> Result<Expr, String> {
        let subject = self.expr(0)?;
        self.skip_newlines();
        self.expect(TokenKind::LBrace)?;
        self.skip_newlines();
        let mut arms = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let default = loop {
            if self.current().kind == TokenKind::Ident("_".into()) {
                self.bump();
                self.expect(TokenKind::FatArrow)?;
                let value = self.expr(0)?;
                self.skip_newlines();
                if self.current().kind == TokenKind::Comma {
                    self.bump();
                    self.skip_newlines();
                }
                self.expect(TokenKind::RBrace)?;
                break value;
            }
            if arms.len() >= 256 {
                return Err(self.error("match exceeds 256 patterns"));
            }
            let pattern = match self.bump().kind {
                TokenKind::Number(value) => MatchPattern::Int(value),
                TokenKind::Unsigned(value) => MatchPattern::UInt(value),
                TokenKind::Minus => {
                    let TokenKind::Number(value) = self.bump().kind else {
                        return Err(self.error("match pattern must be a literal"));
                    };
                    MatchPattern::Int(
                        value
                            .checked_neg()
                            .ok_or_else(|| self.error("integer overflow"))?,
                    )
                }
                TokenKind::String(value) => MatchPattern::Str(value),
                TokenKind::Ident(value) if value == "true" || value == "false" => {
                    MatchPattern::Bool(value == "true")
                }
                _ => return Err(self.error("match pattern must be a literal or '_'")),
            };
            if !seen.insert(pattern.clone()) {
                return Err(self.error("duplicate match pattern"));
            }
            self.expect(TokenKind::FatArrow)?;
            let value = self.expr(0)?;
            arms.push((pattern, value));
            if self.current().kind == TokenKind::Comma {
                self.bump();
                self.skip_newlines();
            } else if self.current().kind == TokenKind::Newline {
                self.skip_newlines();
            } else {
                return Err(self.error("match arms must be separated by a comma or newline"));
            }
        };
        Ok(Expr {
            kind: ExprKind::Match(Box::new(subject), arms, Box::new(default)),
            line,
            col,
        })
    }
}

fn resolve_from_imports(
    statements: &mut [Stmt],
    imports: &[(String, String, usize, usize)],
) -> Result<(), String> {
    if imports.is_empty() {
        return Ok(());
    }
    let mut names = HashSet::new();
    for statement in statements.iter() {
        match &statement.kind {
            StmtKind::Import(_, alias, _)
            | StmtKind::Struct(alias, _)
            | StmtKind::Let(alias, _, _)
            | StmtKind::Var(alias, _, _)
            | StmtKind::Function(alias, _, _, _) => {
                names.insert(alias.as_str());
            }
            _ => {}
        }
        if let StmtKind::Function(_, params, _, body) = &statement.kind {
            for param in params {
                names.insert(param.name.as_str());
            }
            if let FunctionBody::Block(steps, _) = body {
                collect_block_bindings(steps, &mut names);
            }
        }
        if let StmtKind::For(name, _, steps) = &statement.kind {
            names.insert(name.as_str());
            collect_block_bindings(steps, &mut names);
        }
        if let StmtKind::While(_, steps) = &statement.kind {
            collect_block_bindings(steps, &mut names);
        }
        if let StmtKind::If(_, yes, no) = &statement.kind {
            collect_block_bindings(yes, &mut names);
            collect_block_bindings(no, &mut names);
        }
    }
    let mut calls = HashMap::new();
    for (alias, qualified, line, col) in imports {
        if names.contains(alias.as_str())
            || calls.insert(alias.as_str(), qualified.as_str()).is_some()
        {
            return Err(format!(
                "{line}:{col}: imported name {alias} conflicts with another binding"
            ));
        }
    }
    for statement in statements {
        match &mut statement.kind {
            StmtKind::Let(_, annotation, expr) | StmtKind::Var(_, annotation, expr) => {
                rewrite_type_reference(annotation, &calls);
                rewrite_import_references(expr, &calls);
            }
            StmtKind::Assign(_, expr) | StmtKind::Print(expr) | StmtKind::Impact(expr) => {
                rewrite_import_references(expr, &calls)
            }
            StmtKind::Struct(_, fields) => {
                for field in fields {
                    rewrite_type_reference(&mut field.annotation, &calls);
                }
            }
            StmtKind::Function(_, params, result_type, body) => {
                for param in params {
                    rewrite_type_reference(&mut param.annotation, &calls);
                }
                rewrite_type_reference(result_type, &calls);
                match body {
                    FunctionBody::Expression(expr) => rewrite_import_references(expr, &calls),
                    FunctionBody::Block(steps, result) => {
                        rewrite_block_references(steps, &calls);
                        if let Some(result) = result {
                            rewrite_import_references(result, &calls);
                        }
                    }
                }
            }
            StmtKind::For(_, expr, steps) | StmtKind::While(expr, steps) => {
                rewrite_import_references(expr, &calls);
                rewrite_block_references(steps, &calls);
            }
            StmtKind::If(expr, yes, no) => {
                rewrite_import_references(expr, &calls);
                rewrite_block_references(yes, &calls);
                rewrite_block_references(no, &calls);
            }
            StmtKind::Requires(_) | StmtKind::Import(_, _, _) => {}
        }
    }
    Ok(())
}

fn block_always_returns(steps: &[BlockStmt]) -> bool {
    steps.iter().any(|step| match &step.kind {
        BlockStmtKind::Return(_) => true,
        BlockStmtKind::If(_, yes, no) => {
            !no.is_empty() && block_always_returns(yes) && block_always_returns(no)
        }
        _ => false,
    })
}

fn collect_block_bindings<'a>(steps: &'a [BlockStmt], names: &mut HashSet<&'a str>) {
    for step in steps {
        match &step.kind {
            BlockStmtKind::Let(name, _, _) | BlockStmtKind::Var(name, _, _) => {
                names.insert(name.as_str());
            }
            BlockStmtKind::For(name, _, body) => {
                names.insert(name.as_str());
                collect_block_bindings(body, names);
            }
            BlockStmtKind::While(_, body) => collect_block_bindings(body, names),
            BlockStmtKind::If(_, yes, no) => {
                collect_block_bindings(yes, names);
                collect_block_bindings(no, names);
            }
            _ => {}
        }
    }
}

fn rewrite_block_references(steps: &mut [BlockStmt], calls: &HashMap<&str, &str>) {
    for step in steps {
        match &mut step.kind {
            BlockStmtKind::Let(_, annotation, expr) | BlockStmtKind::Var(_, annotation, expr) => {
                rewrite_type_reference(annotation, calls);
                rewrite_import_references(expr, calls);
            }
            BlockStmtKind::Assign(_, expr)
            | BlockStmtKind::Print(expr)
            | BlockStmtKind::Impact(expr)
            | BlockStmtKind::Return(expr) => rewrite_import_references(expr, calls),
            BlockStmtKind::Break | BlockStmtKind::Continue => {}
            BlockStmtKind::For(_, expr, body) | BlockStmtKind::While(expr, body) => {
                rewrite_import_references(expr, calls);
                rewrite_block_references(body, calls);
            }
            BlockStmtKind::If(expr, yes, no) => {
                rewrite_import_references(expr, calls);
                rewrite_block_references(yes, calls);
                rewrite_block_references(no, calls);
            }
        }
    }
}

fn rewrite_import_references(expr: &mut Expr, calls: &HashMap<&str, &str>) {
    match &mut expr.kind {
        ExprKind::Call(name, args) => {
            if let Some(qualified) = calls.get(name.as_str()) {
                *name = (*qualified).to_string();
            }
            for arg in args {
                rewrite_import_references(arg, calls);
            }
        }
        ExprKind::MethodCall(receiver, _, args) => {
            rewrite_import_references(receiver, calls);
            for arg in args {
                rewrite_import_references(arg, calls);
            }
        }
        ExprKind::Neg(inner)
        | ExprKind::BitNot(inner)
        | ExprKind::Not(inner)
        | ExprKind::Try(inner) => rewrite_import_references(inner, calls),
        ExprKind::Binary(left, _, right) => {
            rewrite_import_references(left, calls);
            rewrite_import_references(right, calls);
        }
        ExprKind::If(condition, yes, no) => {
            rewrite_import_references(condition, calls);
            rewrite_import_references(yes, calls);
            rewrite_import_references(no, calls);
        }
        ExprKind::Match(subject, arms, default) => {
            rewrite_import_references(subject, calls);
            for (_, value) in arms {
                rewrite_import_references(value, calls);
            }
            rewrite_import_references(default, calls);
        }
        ExprKind::List(items) => {
            for item in items {
                rewrite_import_references(item, calls);
            }
        }
        ExprKind::Field(value, _) => rewrite_import_references(value, calls),
        ExprKind::Index(list, index) => {
            rewrite_import_references(list, calls);
            rewrite_import_references(index, calls);
        }
        ExprKind::Var(name) => {
            if let Some(qualified) = calls.get(name.as_str()) {
                *name = (*qualified).to_string();
            }
        }
        ExprKind::Int(_) | ExprKind::UInt(_) | ExprKind::Bool(_) | ExprKind::Str(_) => {}
    }
}

fn rewrite_type_reference(annotation: &mut Option<String>, calls: &HashMap<&str, &str>) {
    let Some(name) = annotation.as_mut() else {
        return;
    };
    if let Some(qualified) = calls.get(name.as_str()) {
        *name = (*qualified).to_string();
        return;
    }
    for wrapper in ["List", "Result"] {
        if let Some(inner) = name
            .strip_prefix(wrapper)
            .and_then(|rest| rest.strip_prefix('<'))
            .and_then(|rest| rest.strip_suffix('>'))
        {
            if let Some(qualified) = calls.get(inner) {
                *name = format!("{wrapper}<{qualified}>");
            }
            return;
        }
    }
}

fn default_import_alias(target: &str) -> Option<String> {
    let target = target.strip_prefix("py:").unwrap_or(target);
    let basename = target.rsplit(['/', '\\']).next()?;
    let basename = basename
        .strip_suffix(".gak")
        .or_else(|| basename.strip_suffix(".gaks"))
        .or_else(|| basename.strip_suffix(".py"))
        .unwrap_or(basename);
    let alias = basename.rsplit('.').next()?;
    let mut chars = alias.chars();
    let first = chars.next()?;
    if (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        && valid_binding_name(alias)
    {
        Some(alias.to_string())
    } else {
        None
    }
}

pub fn class_method_key(class: &str, method: &str) -> String {
    format!("__galeikan_method_{}_{}_{}", class.len(), class, method)
}

fn valid_binding_name(name: &str) -> bool {
    !name.contains('.')
        && !name.starts_with("__galeikan_")
        && !matches!(
            name,
            "requires"
                | "import"
                | "from"
                | "as"
                | "let"
                | "var"
                | "struct"
                | "class"
                | "fn"
                | "return"
                | "break"
                | "continue"
                | "for"
                | "while"
                | "in"
                | "if"
                | "match"
                | "else"
                | "and"
                | "or"
                | "not"
                | "true"
                | "false"
                | "print"
                | "impact"
        )
}
