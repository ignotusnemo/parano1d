// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use crate::Error;

pub(crate) const MAX_SOURCE_BYTES: usize = 64 * 1024;
const MAX_TOKENS: usize = 8192;
const MAX_DEPTH: usize = 64;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Span {
    pub line: usize,
    pub column: usize,
}

impl Span {
    pub fn error(self, message: impl Into<String>) -> Error {
        Error {
            line: self.line,
            column: self.column,
            message: message.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Type {
    U64,
    Bool,
    Address,
}

#[derive(Clone, Debug)]
pub(crate) enum Value {
    U64(u64),
    Bool(bool),
    Address(String),
}

impl Value {
    pub fn ty(&self) -> Type {
        match self {
            Self::U64(_) => Type::U64,
            Self::Bool(_) => Type::Bool,
            Self::Address(_) => Type::Address,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Op {
    Add,
    Subtract,
    Min,
    Max,
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
}

#[derive(Clone, Debug)]
pub(crate) struct Expr {
    pub kind: ExprKind,
    pub span: Span,
    depth: usize,
}

impl Expr {
    fn new(kind: ExprKind, span: Span) -> Result<Self, Error> {
        let depth = 1 + match &kind {
            ExprKind::Not(inner) => inner.depth,
            ExprKind::Binary(_, left, right) => left.depth.max(right.depth),
            _ => 0,
        };
        if depth > MAX_DEPTH {
            return Err(span.error("expression nesting exceeds 64 levels"));
        }
        Ok(Self { kind, span, depth })
    }
}

#[derive(Clone, Debug)]
pub(crate) enum ExprKind {
    Value(Value),
    Name(String),
    Old(String),
    Not(Box<Expr>),
    Binary(Op, Box<Expr>, Box<Expr>),
}

#[derive(Clone, Debug)]
pub(crate) enum Statement {
    Assign(String, Expr, Span),
    Require(Expr),
    When(Expr, Vec<Statement>),
}

#[derive(Clone, Debug)]
pub(crate) struct Declaration {
    pub name: String,
    pub ty: Type,
    pub value: Option<Expr>,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub(crate) struct Source {
    pub name: String,
    pub params: Vec<Declaration>,
    pub constants: Vec<Declaration>,
    pub states: Vec<Declaration>,
    pub policy: Vec<(String, Expr, Span)>,
    pub body: Vec<Statement>,
    pub ensures: Vec<Expr>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TokenKind {
    Name(String),
    Number(u64),
    Text(String),
    Symbol(&'static str),
    End,
}

#[derive(Clone, Debug)]
struct Token {
    kind: TokenKind,
    span: Span,
}

fn tokens(source: &str) -> Result<Vec<Token>, Error> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err(Error::plain("source exceeds 64 KiB"));
    }
    let bytes = source.as_bytes();
    let (mut at, mut line, mut column) = (0, 1, 1);
    let mut result = Vec::new();
    while at < bytes.len() {
        if result.len() >= MAX_TOKENS {
            return Err(Span { line, column }.error("source exceeds 8192 tokens"));
        }
        if bytes[at].is_ascii_whitespace() {
            if bytes[at] == b'\n' || bytes[at] == b'\r' {
                if bytes[at] == b'\r' && bytes.get(at + 1) == Some(&b'\n') {
                    at += 1;
                }
                line += 1;
                column = 1;
            } else {
                column += 1;
            }
            at += 1;
            continue;
        }
        if bytes[at..].starts_with(b"//") {
            while at < bytes.len() && bytes[at] != b'\n' && bytes[at] != b'\r' {
                at += 1;
                column += 1;
            }
            continue;
        }
        let start = at;
        let span = Span { line, column };
        let kind = if bytes[at].is_ascii_alphabetic() || bytes[at] == b'_' {
            at += 1;
            while at < bytes.len() && (bytes[at].is_ascii_alphanumeric() || bytes[at] == b'_') {
                at += 1;
            }
            TokenKind::Name(source[start..at].to_owned())
        } else if bytes[at].is_ascii_digit() {
            at += 1;
            while at < bytes.len() && bytes[at].is_ascii_digit() {
                at += 1;
            }
            let text = &source[start..at];
            if text.len() > 1 && text.starts_with('0') {
                return Err(span.error("use canonical decimal integers without leading zeroes"));
            }
            TokenKind::Number(
                text.parse()
                    .map_err(|_| span.error("integer exceeds u64"))?,
            )
        } else if bytes[at] == b'"' {
            at += 1;
            let mut escaped = false;
            while at < bytes.len() {
                let byte = bytes[at];
                at += 1;
                if byte == b'\n' || byte == b'\r' {
                    return Err(span.error("string literals cannot span lines"));
                }
                if byte == b'"' && !escaped {
                    break;
                }
                escaped = byte == b'\\' && !escaped;
            }
            let text = serde_json::from_str(&source[start..at])
                .map_err(|_| span.error("invalid string literal"))?;
            TokenKind::Text(text)
        } else {
            let double = ["==", "!=", "<=", ">=", "+=", "-="]
                .into_iter()
                .find(|symbol| source[start..].starts_with(symbol));
            if let Some(symbol) = double {
                at += 2;
                TokenKind::Symbol(symbol)
            } else {
                let symbol = match bytes[at] {
                    b'{' => "{",
                    b'}' => "}",
                    b'(' => "(",
                    b')' => ")",
                    b':' => ":",
                    b';' => ";",
                    b'=' => "=",
                    b',' => ",",
                    b'+' => "+",
                    b'-' => "-",
                    b'!' => "!",
                    b'<' => "<",
                    b'>' => ">",
                    _ => return Err(span.error("unexpected character")),
                };
                at += 1;
                TokenKind::Symbol(symbol)
            }
        };
        column += at - start;
        result.push(Token { kind, span });
    }
    result.push(Token {
        kind: TokenKind::End,
        span: Span { line, column },
    });
    Ok(result)
}

struct Parser {
    tokens: Vec<Token>,
    at: usize,
    depth: usize,
}

impl Parser {
    fn token(&self) -> &Token {
        &self.tokens[self.at]
    }

    fn take(&mut self, text: &str) -> bool {
        let matches = match &self.token().kind {
            TokenKind::Name(name) => name == text,
            TokenKind::Symbol(symbol) => *symbol == text,
            _ => false,
        };
        if matches {
            self.at += 1;
        }
        matches
    }

    fn expect(&mut self, text: &str) -> Result<(), Error> {
        if self.take(text) {
            Ok(())
        } else {
            Err(self.token().span.error(format!("expected '{text}'")))
        }
    }

    fn name(&mut self) -> Result<(String, Span), Error> {
        let token = self.token().clone();
        if let TokenKind::Name(name) = token.kind {
            self.at += 1;
            Ok((name, token.span))
        } else {
            Err(token.span.error("expected a name"))
        }
    }

    fn ty(&mut self) -> Result<Type, Error> {
        let (name, span) = self.name()?;
        match name.as_str() {
            "u64" => Ok(Type::U64),
            "bool" => Ok(Type::Bool),
            "address" => Ok(Type::Address),
            _ => Err(span.error("expected u64, bool or address")),
        }
    }

    fn declaration(&mut self, value: bool) -> Result<Declaration, Error> {
        let (name, span) = self.name()?;
        self.expect(":")?;
        let ty = self.ty()?;
        let value = if value {
            self.expect("=")?;
            Some(self.expr(0)?)
        } else {
            None
        };
        self.expect(";")?;
        Ok(Declaration {
            name,
            ty,
            value,
            span,
        })
    }

    fn nested<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T, Error>) -> Result<T, Error> {
        if self.depth >= MAX_DEPTH {
            return Err(self.token().span.error("syntax nesting exceeds 64 levels"));
        }
        self.depth += 1;
        let result = f(self);
        self.depth -= 1;
        result
    }

    fn atom(&mut self) -> Result<Expr, Error> {
        self.nested(|parser| {
            let token = parser.token().clone();
            let span = token.span;
            if parser.take("!") {
                return Expr::new(ExprKind::Not(Box::new(parser.atom()?)), span);
            }
            if parser.take("(") {
                let expr = parser.expr(0)?;
                parser.expect(")")?;
                return Ok(expr);
            }
            parser.at += 1;
            let kind = match token.kind {
                TokenKind::Number(value) => ExprKind::Value(Value::U64(value)),
                TokenKind::Text(value) => ExprKind::Value(Value::Address(value)),
                TokenKind::Name(name) if name == "true" || name == "false" => {
                    ExprKind::Value(Value::Bool(name == "true"))
                }
                TokenKind::Name(name) if name == "old" => {
                    parser.expect("(")?;
                    let (name, _) = parser.name()?;
                    parser.expect(")")?;
                    ExprKind::Old(name)
                }
                TokenKind::Name(name) if name == "min" || name == "max" => {
                    parser.expect("(")?;
                    let left = parser.expr(0)?;
                    parser.expect(",")?;
                    let right = parser.expr(0)?;
                    parser.expect(")")?;
                    ExprKind::Binary(
                        if name == "min" { Op::Min } else { Op::Max },
                        Box::new(left),
                        Box::new(right),
                    )
                }
                TokenKind::Name(name) => ExprKind::Name(name),
                _ => return Err(span.error("expected an expression")),
            };
            Expr::new(kind, span)
        })
    }

    fn expr(&mut self, minimum: u8) -> Result<Expr, Error> {
        let mut left = self.atom()?;
        loop {
            let (op, precedence) = match &self.token().kind {
                TokenKind::Symbol("+") => (Op::Add, 2),
                TokenKind::Symbol("-") => (Op::Subtract, 2),
                TokenKind::Symbol("==") => (Op::Equal, 1),
                TokenKind::Symbol("!=") => (Op::NotEqual, 1),
                TokenKind::Symbol("<") => (Op::Less, 1),
                TokenKind::Symbol("<=") => (Op::LessEqual, 1),
                TokenKind::Symbol(">") => (Op::Greater, 1),
                TokenKind::Symbol(">=") => (Op::GreaterEqual, 1),
                _ => break,
            };
            if precedence < minimum {
                break;
            }
            self.at += 1;
            let right = self.expr(precedence + 1)?;
            let span = left.span;
            left = Expr::new(ExprKind::Binary(op, Box::new(left), Box::new(right)), span)?;
        }
        Ok(left)
    }

    fn block(&mut self) -> Result<Vec<Statement>, Error> {
        self.nested(|parser| {
            parser.expect("{")?;
            let mut statements = Vec::new();
            while !parser.take("}") {
                if parser.take("when") {
                    let condition = parser.expr(0)?;
                    statements.push(Statement::When(condition, parser.block()?));
                } else if parser.take("require") {
                    let condition = parser.expr(0)?;
                    parser.expect(";")?;
                    statements.push(Statement::Require(condition));
                } else {
                    let (name, span) = parser.name()?;
                    let compound = if parser.take("+=") {
                        Some(Op::Add)
                    } else if parser.take("-=") {
                        Some(Op::Subtract)
                    } else {
                        parser.expect("=")?;
                        None
                    };
                    let mut expr = parser.expr(0)?;
                    if let Some(op) = compound {
                        expr = Expr::new(
                            ExprKind::Binary(
                                op,
                                Box::new(Expr::new(ExprKind::Name(name.clone()), span)?),
                                Box::new(expr),
                            ),
                            span,
                        )?;
                    }
                    parser.expect(";")?;
                    statements.push(Statement::Assign(name, expr, span));
                }
            }
            Ok(statements)
        })
    }

    fn source(&mut self) -> Result<Source, Error> {
        self.expect("contract")?;
        let (name, _) = self.name()?;
        self.expect("{")?;
        let mut result = Source {
            name,
            params: Vec::new(),
            constants: Vec::new(),
            states: Vec::new(),
            policy: Vec::new(),
            body: Vec::new(),
            ensures: Vec::new(),
        };
        let (mut policy, mut call) = (false, false);
        while !self.take("}") {
            if self.take("param") {
                result.params.push(self.declaration(false)?);
            } else if self.take("const") {
                result.constants.push(self.declaration(true)?);
            } else if self.take("state") {
                result.states.push(self.declaration(true)?);
            } else if self.take("policy") {
                if policy {
                    return Err(self.token().span.error("duplicate policy block"));
                }
                policy = true;
                self.expect("{")?;
                while !self.take("}") {
                    let (name, span) = self.name()?;
                    self.expect("=")?;
                    let value = self.expr(0)?;
                    self.expect(";")?;
                    result.policy.push((name, value, span));
                }
            } else if self.take("call") {
                if call {
                    return Err(self.token().span.error("duplicate call block"));
                }
                call = true;
                result.body = self.block()?;
            } else if self.take("ensures") {
                result.ensures.push(self.expr(0)?);
                self.expect(";")?;
            } else {
                return Err(self
                    .token()
                    .span
                    .error("expected param, const, state, policy, call or ensures"));
            }
        }
        if self.token().kind != TokenKind::End {
            return Err(self.token().span.error("unexpected text after contract"));
        }
        if !policy || !call {
            return Err(self
                .token()
                .span
                .error("contract requires one policy block and one call block"));
        }
        Ok(result)
    }
}

pub(crate) fn parse(source: &str) -> Result<Source, Error> {
    Parser {
        tokens: tokens(source)?,
        at: 0,
        depth: 0,
    }
    .source()
}
