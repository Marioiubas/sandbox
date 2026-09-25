//! A strict parser for GraphQL executable documents (the GitHub GraphQL
//! API's request language; GraphQL spec, "Executable Definitions"). It
//! accepts operations and fragments only; type-system definitions, stray
//! tokens, excessive nesting and anything else are errors, and the adapter
//! denies on any error. Directives are parsed and dropped: the adapter
//! counts every field whether or not `@skip`/`@include` would drop it,
//! which only makes it stricter.

pub mod lex;

use lex::Tok;

/// Deepest nesting of selection sets, lists, objects and types.
pub const MAX_DEPTH: usize = 48;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Document {
    pub operations: Vec<Operation>,
    pub fragments: Vec<Fragment>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpType {
    Query,
    Mutation,
    Subscription,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operation {
    pub ty: OpType,
    pub name: Option<String>,
    /// Variable definitions: name and default value.
    pub vars: Vec<(String, Option<Value>)>,
    pub selection: Vec<Selection>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fragment {
    pub name: String,
    pub on: String,
    pub selection: Vec<Selection>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Selection {
    Field(Field),
    /// `...Name`
    Spread(String),
    /// `... on Type { … }` or `... { … }`
    Inline(Option<String>, Vec<Selection>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    pub alias: Option<String>,
    pub name: String,
    pub args: Vec<(String, Value)>,
    pub selection: Option<Vec<Selection>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Var(String),
    Int(String),
    Float(String),
    Str(String),
    /// Block strings stay raw; the adapter never takes a value from one.
    Block(String),
    Bool(bool),
    Null,
    Enum(String),
    List(Vec<Value>),
    Object(Vec<(String, Value)>),
}

pub fn parse(src: &str) -> Result<Document, &'static str> {
    let toks = lex::tokens(src)?;
    let mut p = P { t: &toks, i: 0, depth: 0 };
    let mut doc = Document { operations: vec![], fragments: vec![] };
    if toks.is_empty() {
        return Err("empty document");
    }
    while p.i < toks.len() {
        match p.peek() {
            Some(Tok::Punct(b'{')) => {
                let selection = p.selection_set()?;
                doc.operations.push(Operation { ty: OpType::Query, name: None, vars: vec![], selection });
            }
            Some(Tok::Name("query" | "mutation" | "subscription")) => doc.operations.push(p.operation()?),
            Some(Tok::Name("fragment")) => doc.fragments.push(p.fragment()?),
            _ => return Err("not an operation or fragment definition"),
        }
    }
    Ok(doc)
}

struct P<'t, 'a> {
    t: &'t [Tok<'a>],
    i: usize,
    depth: usize,
}

impl<'a> P<'_, 'a> {
    fn peek(&self) -> Option<&Tok<'a>> {
        self.t.get(self.i)
    }

    fn next(&mut self) -> Option<&Tok<'a>> {
        let t = self.t.get(self.i);
        self.i += 1;
        t
    }

    fn is(&self, c: u8) -> bool {
        self.peek() == Some(&Tok::Punct(c))
    }

    fn expect(&mut self, c: u8) -> Result<(), &'static str> {
        if self.next() == Some(&Tok::Punct(c)) { Ok(()) } else { Err("unexpected token") }
    }

    fn name(&mut self) -> Result<String, &'static str> {
        match self.next() {
            Some(Tok::Name(n)) => Ok(n.to_string()),
            _ => Err("expected a name"),
        }
    }

    fn enter(&mut self) -> Result<(), &'static str> {
        self.depth += 1;
        if self.depth > MAX_DEPTH { Err("nested too deeply") } else { Ok(()) }
    }

    fn operation(&mut self) -> Result<Operation, &'static str> {
        let ty = match self.next() {
            Some(Tok::Name("query")) => OpType::Query,
            Some(Tok::Name("mutation")) => OpType::Mutation,
            Some(Tok::Name("subscription")) => OpType::Subscription,
            _ => return Err("expected an operation type"),
        };
        let name = match self.peek() {
            Some(Tok::Name(_)) => Some(self.name()?),
            _ => None,
        };
        let mut vars = Vec::new();
        if self.is(b'(') {
            self.i += 1;
            loop {
                self.expect(b'$')?;
                let v = self.name()?;
                self.expect(b':')?;
                self.ty()?;
                let default = if self.is(b'=') {
                    self.i += 1;
                    Some(self.value(true)?)
                } else {
                    None
                };
                self.directives(true)?;
                vars.push((v, default));
                if self.is(b')') {
                    self.i += 1;
                    break;
                }
            }
        }
        self.directives(false)?;
        let selection = self.selection_set()?;
        Ok(Operation { ty, name, vars, selection })
    }

    fn fragment(&mut self) -> Result<Fragment, &'static str> {
        self.i += 1; // `fragment`
        let name = self.name()?;
        if name == "on" {
            return Err("a fragment cannot be named 'on'");
        }
        if self.next() != Some(&Tok::Name("on")) {
            return Err("expected a type condition");
        }
        let on = self.name()?;
        self.directives(false)?;
        let selection = self.selection_set()?;
        Ok(Fragment { name, on, selection })
    }

    /// A type reference: `Name`, `[Type]`, either followed by `!`.
    fn ty(&mut self) -> Result<(), &'static str> {
        self.enter()?;
        if self.is(b'[') {
            self.i += 1;
            self.ty()?;
            self.expect(b']')?;
        } else {
            self.name()?;
        }
        if self.is(b'!') {
            self.i += 1;
        }
        self.depth -= 1;
        Ok(())
    }

    fn directives(&mut self, konst: bool) -> Result<(), &'static str> {
        while self.is(b'@') {
            self.i += 1;
            self.name()?;
            if self.is(b'(') {
                self.arguments(konst)?;
            }
        }
        Ok(())
    }

    fn arguments(&mut self, konst: bool) -> Result<Vec<(String, Value)>, &'static str> {
        self.expect(b'(')?;
        let mut out = Vec::new();
        loop {
            let n = self.name()?;
            self.expect(b':')?;
            out.push((n, self.value(konst)?));
            if self.is(b')') {
                self.i += 1;
                return Ok(out);
            }
        }
    }

    fn selection_set(&mut self) -> Result<Vec<Selection>, &'static str> {
        self.enter()?;
        self.expect(b'{')?;
        let mut out = Vec::new();
        loop {
            out.push(self.selection()?);
            if self.is(b'}') {
                self.i += 1;
                self.depth -= 1;
                return Ok(out);
            }
        }
    }

    fn selection(&mut self) -> Result<Selection, &'static str> {
        if self.peek() == Some(&Tok::Spread) {
            self.i += 1;
            return match self.peek() {
                Some(Tok::Name("on")) => {
                    self.i += 1;
                    let on = self.name()?;
                    self.directives(false)?;
                    Ok(Selection::Inline(Some(on), self.selection_set()?))
                }
                Some(Tok::Name(_)) => {
                    let n = self.name()?;
                    self.directives(false)?;
                    Ok(Selection::Spread(n))
                }
                _ => {
                    self.directives(false)?;
                    Ok(Selection::Inline(None, self.selection_set()?))
                }
            };
        }
        let first = self.name()?;
        let (alias, name) = if self.is(b':') {
            self.i += 1;
            (Some(first), self.name()?)
        } else {
            (None, first)
        };
        let args = if self.is(b'(') { self.arguments(false)? } else { vec![] };
        self.directives(false)?;
        let selection = if self.is(b'{') { Some(self.selection_set()?) } else { None };
        Ok(Selection::Field(Field { alias, name, args, selection }))
    }

    /// A value; `konst` forbids variables (defaults, directive arguments
    /// on variable definitions).
    fn value(&mut self, konst: bool) -> Result<Value, &'static str> {
        self.enter()?;
        let v = match self.next().cloned() {
            Some(Tok::Punct(b'$')) if !konst => Value::Var(self.name()?),
            Some(Tok::Int(s)) => Value::Int(s.to_string()),
            Some(Tok::Float(s)) => Value::Float(s.to_string()),
            Some(Tok::Str(s)) => Value::Str(s),
            Some(Tok::Block(s)) => Value::Block(s.to_string()),
            Some(Tok::Name("true")) => Value::Bool(true),
            Some(Tok::Name("false")) => Value::Bool(false),
            Some(Tok::Name("null")) => Value::Null,
            Some(Tok::Name(n)) => Value::Enum(n.to_string()),
            Some(Tok::Punct(b'[')) => {
                let mut items = Vec::new();
                while !self.is(b']') {
                    if self.peek().is_none() {
                        return Err("unterminated list");
                    }
                    items.push(self.value(konst)?);
                }
                self.i += 1;
                Value::List(items)
            }
            Some(Tok::Punct(b'{')) => {
                let mut fields = Vec::new();
                while !self.is(b'}') {
                    let n = self.name()?;
                    self.expect(b':')?;
                    fields.push((n, self.value(konst)?));
                }
                self.i += 1;
                Value::Object(fields)
            }
            _ => return Err("expected a value"),
        };
        self.depth -= 1;
        Ok(v)
    }
}

#[cfg(test)]
mod tests;
