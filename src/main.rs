#![feature(ascii_char)]

use std::fs::File;

use clap::{Command, arg};

fn cli() -> Command {
    clap::Command::new("yksignify")
        .subcommand_required(true)
        .subcommand(
            Command::new("dump")
                .about("Try to read a gzip-style signature")
                .arg(arg!(<FILE> "The file to inspect"))
        )
}

fn main() {
    let cmd = cli().get_matches();
    match cmd.subcommand() {
        Some(("dump", matches)) => {
            dump(matches.get_one::<String>("FILE").unwrap())
        },
        _ => unreachable!()
    }
}

fn dump(file: &String) {
    let header = gzip_header::read_gz_header(&mut File::open(file).expect("Can't open file")).expect("Can't read gzip header");
    if let Some(comment) = header.comment() && comment.is_ascii() && let Some(arr) = comment.as_ascii() {
        println!("{}", arr.as_str());
    }
}
