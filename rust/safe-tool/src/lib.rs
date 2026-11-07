#![forbid(unsafe_code)]

pub mod chunk;
pub mod cli;
pub mod command;
pub mod commit;
pub mod consts;
pub mod git;
pub mod git_rules;
pub mod hooks;
pub mod inline_env;
pub mod keys;
pub mod local_only;
pub mod output;
pub mod paths;
pub mod process;
pub mod protected;
pub mod redact;
pub mod remote;
pub mod selftest;
pub mod startup;
pub mod startup_values;
pub mod words;
