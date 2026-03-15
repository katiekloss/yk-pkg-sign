#![feature(ascii_char)]

use std::fs::File;

use clap::{Command, arg};
use cryptoki::{context::{CInitializeArgs, CInitializeFlags}, object::{Attribute, AttributeType, ObjectClass}};

fn cli() -> Command {
    clap::Command::new("yksignify")
        .subcommand_required(true)
        .subcommand(
            Command::new("dump")
                .about("Try to read a gzip-style signature")
                .arg(arg!(<FILE> "The file to inspect"))
        )
        .subcommand(
            Command::new("token")
                .about("Show information about the connected hardware token")
        )
}

fn main() {
    let cmd = cli().get_matches();
    match cmd.subcommand() {
        Some(("dump", matches)) => {
            dump(matches.get_one::<String>("FILE").unwrap())
        },
        Some(("token", _)) => {
            show_token()
        }
        _ => unreachable!()
    }
}

fn dump(file: &String) {
    let header = gzip_header::read_gz_header(&mut File::open(file).expect("Can't open file")).expect("Can't read gzip header");
    if let Some(comment) = header.comment() && comment.is_ascii() && let Some(arr) = comment.as_ascii() {
        println!("{}", arr.as_str());
    }
}

fn show_token() {
    let ctx = cryptoki::context::Pkcs11::new("/usr/local/lib/libykcs11.dylib").expect("Cannot load PKCS impl");
    ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)).expect("Cannot initialize PKCS");

    let slots = ctx.get_slots_with_token().expect("Can't get slots");
    if slots.len() == 0 {
        panic!("No slots found");
    }

    let slot = slots[0];
    println!("{:?}", slot);
    let info = ctx.get_slot_info(slot).expect("Can't get slot info");
    println!("{:?}", info);
    
    let session = ctx.open_rw_session(slot).expect("Can't start session");
    let objs = session.find_objects(&[Attribute::Class(ObjectClass::PUBLIC_KEY)]).expect("");
    for obj in objs {
        print!("{:?}", obj);
        let result = session.get_attributes(obj, &[AttributeType::KeyType]).expect("Can't get attrs");

        if result.len() == 0 {
            println!();
            continue;
        }

        println!("{:?}", result);
    }
}
