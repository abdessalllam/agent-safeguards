use std::mem::take;

const WORDCHARS_BASE: &str = "abcdfeghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
const WORDCHARS_POSIX: &str = "ßàáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖØÙÚÛÜÝÞ";
const WORDCHARS_PUNCT: &str = "~-./*?=";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShlexError {
    pub message: &'static str,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Eof,
    Whitespace,
    Word,
    Punct,
    Quote(char),
    Escape,
}

pub struct Lexer {
    chars: Vec<char>,
    pos: usize,
    posix: bool,
    punctuation: String,
    punctuation_on: bool,
    whitespace: String,
    whitespace_split: bool,
    commenters: String,
    wordchars: String,
    mode: Mode,
    token: String,
    char_pushback: Vec<char>,
    token_pushback: Vec<String>,
}

impl Lexer {
    pub fn new(text: &str) -> Self {
        Self {
            chars: text.chars().collect(),
            pos: 0,
            posix: false,
            punctuation: String::new(),
            punctuation_on: false,
            whitespace: " \t\r\n".to_string(),
            whitespace_split: false,
            commenters: "#".to_string(),
            wordchars: WORDCHARS_BASE.to_string(),
            mode: Mode::Whitespace,
            token: String::new(),
            char_pushback: Vec::new(),
            token_pushback: Vec::new(),
        }
    }

    pub fn posix(mut self, enabled: bool) -> Self {
        self.posix = enabled;
        self.rebuild_wordchars();
        self
    }

    pub fn punctuation_chars(mut self, chars: &str) -> Self {
        self.punctuation = chars.to_string();
        self.punctuation_on = !chars.is_empty();
        self.rebuild_wordchars();
        self
    }

    pub fn whitespace(mut self, chars: &str) -> Self {
        self.whitespace = chars.to_string();
        self
    }

    pub fn whitespace_split(mut self, enabled: bool) -> Self {
        self.whitespace_split = enabled;
        self
    }

    pub fn commenters(mut self, chars: &str) -> Self {
        self.commenters = chars.to_string();
        self
    }

    pub fn tokens(mut self) -> Result<Vec<String>, ShlexError> {
        let mut out = Vec::new();
        loop {
            match self.get_token()? {
                None => break,
                Some(token) => out.push(token),
            }
        }
        Ok(out)
    }

    fn rebuild_wordchars(&mut self) {
        let mut word = String::from(WORDCHARS_BASE);
        if self.posix {
            word.push_str(WORDCHARS_POSIX);
        }
        if self.punctuation_on {
            word.push_str(WORDCHARS_PUNCT);
            let punctuation = self.punctuation.clone();
            word = word.chars().filter(|c| !punctuation.contains(*c)).collect();
        }
        self.wordchars = word;
    }

    fn get_token(&mut self) -> Result<Option<String>, ShlexError> {
        if let Some(token) = self.token_pushback.pop() {
            return Ok(Some(token));
        }
        self.read_token()
    }

    fn next_char(&mut self) -> Option<char> {
        if self.punctuation_on {
            if let Some(ch) = self.char_pushback.pop() {
                return Some(ch);
            }
        }
        let ch = self.chars.get(self.pos).copied()?;
        self.pos = self.pos.saturating_add(1);
        Some(ch)
    }

    fn readline(&mut self) {
        while let Some(ch) = self.chars.get(self.pos).copied() {
            self.pos = self.pos.saturating_add(1);
            if ch == '\n' {
                break;
            }
        }
    }

    fn read_token(&mut self) -> Result<Option<String>, ShlexError> {
        let mut quoted = false;
        let mut escaped_mode = Mode::Whitespace;
        loop {
            let next = self.next_char();
            match self.mode {
                Mode::Eof => {
                    self.token.clear();
                    break;
                }
                Mode::Whitespace => {
                    let Some(ch) = next else {
                        self.mode = Mode::Eof;
                        break;
                    };
                    if self.whitespace.contains(ch) {
                        if !self.token.is_empty() || (self.posix && quoted) {
                            break;
                        }
                    } else if self.commenters.contains(ch) {
                        self.readline();
                    } else if self.posix && ch == '\\' {
                        escaped_mode = Mode::Word;
                        self.mode = Mode::Escape;
                    } else if self.wordchars.contains(ch) {
                        self.token.push(ch);
                        self.mode = Mode::Word;
                    } else if self.punctuation_on && self.punctuation.contains(ch) {
                        self.token.push(ch);
                        self.mode = Mode::Punct;
                    } else if ch == '\'' || ch == '"' {
                        if !self.posix {
                            self.token.push(ch);
                        }
                        self.mode = Mode::Quote(ch);
                    } else if self.whitespace_split {
                        self.token.push(ch);
                        self.mode = Mode::Word;
                    } else {
                        self.token.push(ch);
                        if !self.token.is_empty() || (self.posix && quoted) {
                            break;
                        }
                    }
                }
                Mode::Quote(quote) => {
                    quoted = true;
                    let Some(ch) = next else {
                        return Err(ShlexError {
                            message: "No closing quotation",
                        });
                    };
                    if ch == quote {
                        if !self.posix {
                            self.token.push(ch);
                            self.mode = Mode::Whitespace;
                            break;
                        }
                        self.mode = Mode::Word;
                    } else if self.posix && ch == '\\' && quote == '"' {
                        escaped_mode = Mode::Quote(quote);
                        self.mode = Mode::Escape;
                    } else {
                        self.token.push(ch);
                    }
                }
                Mode::Escape => {
                    let Some(ch) = next else {
                        return Err(ShlexError {
                            message: "No escaped character",
                        });
                    };
                    if let Mode::Quote(quote) = escaped_mode {
                        if ch != '\\' && ch != quote {
                            self.token.push('\\');
                        }
                    }
                    self.token.push(ch);
                    self.mode = escaped_mode;
                }
                Mode::Word | Mode::Punct => {
                    let Some(ch) = next else {
                        self.mode = Mode::Eof;
                        break;
                    };
                    if self.whitespace.contains(ch) {
                        self.mode = Mode::Whitespace;
                        if !self.token.is_empty() || (self.posix && quoted) {
                            break;
                        }
                    } else if self.commenters.contains(ch) {
                        self.readline();
                        if self.posix {
                            self.mode = Mode::Whitespace;
                            if !self.token.is_empty() || quoted {
                                break;
                            }
                        }
                    } else if self.mode == Mode::Punct {
                        if self.punctuation.contains(ch) {
                            self.token.push(ch);
                        } else {
                            if !self.whitespace.contains(ch) {
                                self.char_pushback.push(ch);
                            }
                            self.mode = Mode::Whitespace;
                            break;
                        }
                    } else if self.posix && (ch == '\'' || ch == '"') {
                        self.mode = Mode::Quote(ch);
                    } else if self.posix && ch == '\\' {
                        escaped_mode = Mode::Word;
                        self.mode = Mode::Escape;
                    } else if self.wordchars.contains(ch)
                        || ch == '\''
                        || ch == '"'
                        || (self.whitespace_split && !(self.punctuation_on && self.punctuation.contains(ch)))
                    {
                        self.token.push(ch);
                    } else {
                        if self.punctuation_on {
                            self.char_pushback.push(ch);
                        } else {
                            self.token_pushback.push(ch.to_string());
                        }
                        self.mode = Mode::Whitespace;
                        if !self.token.is_empty() || (self.posix && quoted) {
                            break;
                        }
                    }
                }
            }
        }
        let result = take(&mut self.token);
        if result.is_empty() && !(self.posix && quoted) {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }
}

pub fn split(text: &str) -> Result<Vec<String>, ShlexError> {
    Lexer::new(text)
        .posix(true)
        .whitespace_split(true)
        .commenters("")
        .tokens()
}

pub fn quote(word: &str) -> String {
    if word.is_empty() {
        return "''".to_string();
    }
    if word.chars().all(quote_char_is_safe) {
        return word.to_string();
    }
    let mut out = String::from("'");
    out.push_str(&word.replace('\'', "'\"'\"'"));
    out.push('\'');
    out
}

fn quote_char_is_safe(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_' || "@%+=:,./-".contains(ch)
}

#[cfg(test)]
mod tests {
    use super::{quote, split, Lexer};

    fn guard_tokens(text: &str, punctuation: &str) -> Result<Vec<String>, super::ShlexError> {
        Lexer::new(text)
            .posix(true)
            .punctuation_chars(punctuation)
            .whitespace(" \t\r")
            .whitespace_split(true)
            .commenters("")
            .tokens()
    }

    #[test]
    fn posix_quoting_escapes_and_punctuation_runs() {
        let punct = ";&|()\n";
        assert_eq!(guard_tokens("a && b", punct).unwrap(), vec!["a", "&&", "b"]);
        assert_eq!(guard_tokens("a||b", punct).unwrap(), vec!["a", "||", "b"]);
        assert_eq!(guard_tokens("a;;b", punct).unwrap(), vec!["a", ";;", "b"]);
        assert_eq!(guard_tokens("((a))", punct).unwrap(), vec!["((", "a", "))"]);
        assert_eq!(guard_tokens("a\n\nb", punct).unwrap(), vec!["a", "\n\n", "b"]);
        assert_eq!(guard_tokens("a\\\nb", punct).unwrap(), vec!["a\nb"]);
        assert_eq!(guard_tokens("a\\ b", punct).unwrap(), vec!["a b"]);
        assert_eq!(guard_tokens("a >&2", punct).unwrap(), vec!["a", ">", "&", "2"]);
        assert_eq!(guard_tokens("a 2>&1", punct).unwrap(), vec!["a", "2>", "&", "1"]);
        assert_eq!(guard_tokens("a '' \"\"", punct).unwrap(), vec!["a", "", ""]);
        assert_eq!(
            guard_tokens("echo \"a\\\"b\"", punct).unwrap(),
            vec!["echo", "a\"b"]
        );
    }

    #[test]
    fn unterminated_quote_and_escape_fail_the_whole_call() {
        let punct = ";&|()\n";
        assert_eq!(
            guard_tokens("\"unterminated", punct).unwrap_err().message,
            "No closing quotation"
        );
        assert_eq!(guard_tokens("\\", punct).unwrap_err().message, "No escaped character");
        assert!(guard_tokens("echo 'a\\'b'", punct).is_err());
    }

    #[test]
    fn split_and_quote_follow_posix_defaults() {
        assert_eq!(split("a 'b c'").unwrap(), vec!["a", "b c"]);
        assert_eq!(split("a\\ b").unwrap(), vec!["a b"]);
        assert_eq!(split("#c\nd").unwrap(), vec!["#c", "d"]);
        assert_eq!(split("''").unwrap(), vec![""]);
        assert_eq!(split("").unwrap(), Vec::<String>::new());
        assert_eq!(quote(""), "''");
        assert_eq!(quote("a"), "a");
        assert_eq!(quote("-n"), "-n");
        assert_eq!(quote("a b"), "'a b'");
        assert_eq!(quote("a'b"), "'a'\"'\"'b'");
        assert_eq!(quote("café"), "'café'");
        assert_eq!(quote("a$b"), "'a$b'");
    }
}
