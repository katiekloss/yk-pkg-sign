#![feature(ascii_char)]

use std::{fs::File, io::{BufReader, Read, Seek}};

use base64::{Engine, prelude::BASE64_STANDARD};
use clap::{Command, arg};
use cryptoki::{context::{CInitializeArgs, CInitializeFlags}, object::{Attribute, AttributeType, ObjectClass}};
use sha2::{Digest, Sha512};

fn cli() -> Command {
    clap::Command::new("yksignify")
        .subcommand_required(true)
        .subcommand(
            Command::new("dump")
                .about("Try to read a gzip-style signature")
                .arg(arg!(<FILE> "The file to inspect"))
        )
        .subcommand(
            Command::new("sign")
                .about("Sign a gzip archive")
                .arg(arg!(<FILE> "The file to sign"))
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
        },
        Some(("sign", matches)) => {
            sign(matches.get_one::<String>("FILE").unwrap())
        }
        _ => unreachable!()
    }
}

fn dump(file: &String) {
    let header = gzip_header::read_gz_header(&mut File::open(file).expect("Can't open file")).expect("Can't read gzip header");
    let comment;
    if let Some(c) = header.comment() && c.is_ascii() && let Some(arr) = c.as_ascii() {
        comment = arr.as_str();
    } else {
        panic!("gzip comment missing or out of range");
    }

    println!("{}", comment);

    let mut parts = comment.split("\n");
    let signature = BASE64_STANDARD.decode(parts.nth(1).unwrap()).expect("Signature isn't valid base64");
    let keytype = signature[0..2].as_ascii().unwrap().as_str(); // always Ed for EdDSA
    let keynum = &signature[2..10]; // I guess this is like the key fingerprint
    let real_signature = &signature[10..];
    println!("{} key {}, signature: {}", keytype, hex::encode(keynum), hex::encode(real_signature));
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
    
    let session = ctx.open_ro_session(slot).expect("Can't start session");
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

fn sign(file: &String) {
    let mut f = File::open(file).expect("Can't open archive");
    let header = gzip_header::read_gz_header(&mut f).unwrap();

    let header_size = 10 // fixed length preamble
        + header.comment().map_or(0, |c| c.len() + 1) // null terminated
        + header.extra().map_or(0, |e| e.len() + 2) // 2 bytes containing length of the field(s)
        + header.filename().map_or(0, |f| f.len() + 1); // null terminated

    f.seek(std::io::SeekFrom::Start(header_size.try_into().unwrap())).expect("Can't seek to end of gzip header");
    let mut reader = BufReader::new(f);

    // maintain a hash of the entire file for the actual signature
    let mut file_hasher = Sha512::new();
    let mut n = 0;
    loop {
        let mut buf = [0; 65536];
        let i = reader.read(&mut buf).expect("Read failed");
        print!("Read block {} ({} bytes): ", n, i);
        n += 1;

        file_hasher.update(&buf[0..i]);

        let block_hash = sha2::Sha512_256::digest(&buf[0..i]);
        println!("{}", hex::encode(block_hash));

        if i < buf.len() {
            break;
        }
    }

    let file_hash = file_hasher.finalize();
    println!("Data SHA512 hash: {}", hex::encode(file_hash));
}