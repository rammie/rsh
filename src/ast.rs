/// AST types for the restricted shell grammar.

#[derive(Debug, Clone, PartialEq)]
pub struct Program {
    pub pipelines: Vec<Pipeline>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Pipeline {
    pub commands: Vec<Command>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Command {
    pub name: String,
    pub args: Vec<Arg>,
    pub redirects: Vec<Redirect>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Arg {
    /// A bare word or unquoted string (may contain glob characters)
    Bare(String),
    /// A single-quoted string (no interpolation)
    SingleQuoted(String),
    /// A double-quoted string (variable interpolation allowed)
    DoubleQuoted(String),
    /// An environment variable reference: $VAR or ${VAR}
    Var(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Redirect {
    pub kind: RedirectKind,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RedirectKind {
    /// >
    Overwrite,
    /// >>
    Append,
}
