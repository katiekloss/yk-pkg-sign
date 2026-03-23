#![feature(ascii_char)]

use std::{env, fs::{File, OpenOptions}, io::{BufReader, Read, Seek, Write}};

use base64::{Engine, prelude::{BASE64_STANDARD, BASE64_STANDARD_NO_PAD}};
use clap::{Command, arg};
use cryptoki::{context::{CInitializeArgs, CInitializeFlags}, mechanism::{Mechanism, eddsa::{EddsaParams, EddsaSignatureScheme}}, object::{Attribute, AttributeType, ObjectClass}, session::{Session, UserType}, types::AuthPin};
use gzip_header::{ExtraFlags, FileSystemType, GzBuilder};
use secrecy::SecretString;
use sha2::{Digest, Sha512};
use yk_pkg_sign::{ALL_ATTRS, SLOTS, SigningRequest};

fn cli() -> Command {
    clap::Command::new("yk-pkg-sign")
        .subcommand_required(true)
        .subcommand(
            Command::new("dump")
                .about("Try to read a gzip-style signature")
                .arg(arg!(<FILE> "The file to inspect")
                    .required(true))
        )
        .subcommand(
            Command::new("sign")
                .about("Sign a gzip archive")
                .arg(arg!(-f --file <FILE> "The file to sign")
                    .required(true))
                .arg(arg!(-k --keyname <KEYNAME> "The freeform key name to sign with")
                    .required(true))
                .arg(arg!(-s --slot <SLOT> "The key slot to sign with")
                    .required(true))
        )
        .subcommand(
            Command::new("token")
                .about("Show information about the connected hardware token")
        )
        .subcommand(
            Command::new("test-sign")
                .about("Sign test data using the connected YubiKey")
        )
        .subcommand(
            Command::new("export")
                .about("Export a public key from a slot on the HSM")
                .arg(arg!(-s --slot <SLOT> "The key slot to export").required(true))
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
            sign_package(matches.into())
        },
        Some(("test-sign", _)) => {
            sign("01234567".as_bytes(), &SigningRequest { package_file: "test".to_string(), key_name: "test".to_string(), slot: "9C".to_string() });
        },
        Some(("export", matches)) => {
            export(matches.get_one::<String>("slot").unwrap())
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
    let session = connect();

    println!("Available keys:\n");

    for key in session.find_objects(&[Attribute::Class(ObjectClass::PUBLIC_KEY)]).expect("Failed to get keys") {
        let attrs = session.get_attributes(key, &ALL_ATTRS).expect("Failed to get key attributes");

        let label = 'get: {
            for attr in &attrs {
                if let Attribute::Label(l) = attr {
                    break 'get l;
                }
            }
            panic!("Cannot find label")
        };
        println!("Key: {}", label.as_ascii().unwrap().as_str());

        for attr in attrs {
            println!("\t{:?}", attr);
        }
    }
}

fn connect() -> Session {
    //let ctx = cryptoki::context::Pkcs11::new("/usr/local/lib/libykcs11.dylib").expect("Cannot load PKCS impl");
    let ctx = cryptoki::context::Pkcs11::new("/usr/local/lib/softhsm/libsofthsm2.so").unwrap();
    ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)).expect("Cannot initialize PKCS");

    let slots = ctx.get_slots_with_token().expect("Can't get slots");
    if slots.len() == 0 {
        panic!("No slots found");
    }

    let slot = slots[0];
    eprintln!("{:?}", slot);

    let info = ctx.get_slot_info(slot).expect("Can't get slot info");
    eprintln!("{:?}", info);

    ctx.open_ro_session(slots[0]).expect("Can't create session")
}

fn get_pin() -> SecretString {
    AuthPin::new(env::var("TOKEN_PIN").or_else(|_| rpassword::prompt_password("Enter HSM PIN: ")).expect("Cannot get PIN").into())
}

fn sign(data: &[u8], req: &SigningRequest) -> Vec<u8> {
    let session = connect();
    session.login(UserType::User, Some(&get_pin())).expect("Login failed");

    let slot = SLOTS.get(&req.slot.to_lowercase()).expect("Unknown slot").clone();
    let keys = session.find_objects(&[Attribute::Sign(true), Attribute::Id(vec![slot])]).expect("Cannot find signing key");
    match keys.len() {
        0 => panic!("No key in slot {}", &req.slot),
        2.. => panic!("Too many keys in slot {} (?!)", &req.slot),
        _ => ()
    }

    let signature = session.sign(&Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Ed25519)), keys[0], data).expect("Signing failed");
    let (mut keynum, _) = get_public_key(&session, &req.slot);

    let mut full_signature: Vec<u8> = "Ed".as_bytes().to_vec();
    full_signature.append(&mut keynum);
    full_signature.append(&mut signature.to_vec());

    full_signature
}

fn sign_package(req: SigningRequest /* and more! */) {
    let mut f = File::open(&req.package_file).expect("Can't open archive");
    let header = gzip_header::read_gz_header(&mut f).unwrap();

    let header_size = 10 // fixed length preamble
        + header.comment().map_or(0, |c| c.len() + 1) // null terminated
        + header.extra().map_or(0, |e| e.len() + 2) // 2 bytes containing length of the field(s)
        + header.filename().map_or(0, |f| f.len() + 1); // null terminated

    f.seek(std::io::SeekFrom::Start(header_size.try_into().unwrap())).expect("Can't seek to end of gzip header");
    let mut reader = BufReader::new(f);

    // maintain a hash of the entire file for the actual signature
    let mut file_hasher = Sha512::new();
    let mut block_hashes = vec![];
    loop {
        let mut buf = [0; 65536];
        let i = reader.read(&mut buf).expect("Read failed");
        file_hasher.update(&buf[0..i]);

        let block_hash = sha2::Sha512_256::digest(&buf[0..i]).to_vec();
        block_hashes.push(block_hash);

        if i < buf.len() {
            break;
        }
    }
    
    let signature = sign(&file_hasher.finalize(), &req);

    let comment = format!(
"untrusted comment: verify with {}
{}
date={}
key={}
algorithm=SHA512/256
blocksize=65536

{}",
        req.key_name,
        BASE64_STANDARD.encode(signature),
        chrono::Utc::now().to_rfc3339(),
        req.key_name.replace(".pub", ".sec"),
        block_hashes.into_iter().map(|h| hex::encode(h)).collect::<Vec<String>>().join("\n"));

    // recreate the header from the old one, with the new comment
    let mut new_header = GzBuilder::new()
        .os(FileSystemType::from_u8(header.os()))
        .xfl(ExtraFlags::from_u8(header.xfl()))
        .mtime(header.mtime())
        .comment(comment);

    if let Some(extra) = header.extra() {
        new_header = new_header.extra(extra);
    }

    if let Some(filename) = header.filename() {
        new_header = new_header.filename(filename);
    }

    let header_bytes = new_header.into_header();

    let mut signed_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(req.package_file + ".s")
        .expect("Can't open new archive for write");

    signed_file.write(&header_bytes).expect("Can't write new header");

    // first byte of compressed data
    reader.seek(std::io::SeekFrom::Start(header_size.try_into().unwrap())).unwrap();
    loop {
        let mut buf = [0; 65536];
        let i = reader.read(&mut buf).expect("Read failed");

        signed_file.write(&buf[0..i]).expect("Write failed");

        if i < buf.len() {
            break;
        }
    }
}


fn get_public_key(session: &Session, slot: &String) -> (Vec<u8>, Vec<u8>) {
    let slot = SLOTS.get(&slot.to_lowercase()).expect("Unknown slot").clone();
    let keys = session.find_objects(&[Attribute::Class(ObjectClass::PUBLIC_KEY), Attribute::Id(vec![slot])]).expect("Cannot find key");

    let key = match keys.len() {
        0 => panic!("No key in slot {}", slot),
        1 => keys[0],
        _ => panic!("Too many keys in slot {} (?!)", slot)
    };

    let attrs = session.get_attributes(key, &[AttributeType::EcPoint]).expect("Can't get key attributes");

    let mut point = 'get: {
        for attr in &attrs {
            if let Attribute::EcPoint(m) = attr {
                break 'get m.clone();
            }
        }
        panic!("Can't get key point");
    };

    // YubiKeys export 0x04 0x20 at the start of their curve point attribute
    // I am completely serious
    if point[0] == 4 && point[1] == 32 {
        point = point[2..].to_vec();
    }

    let crc = crc::Crc::<u64>::new(&crc::CRC_64_ECMA_182);
    let keynum = crc.checksum(&point).to_le_bytes();

    (keynum.to_vec(), point.to_vec())
}

fn export(slot: &String) {
    let session = connect();

    let (keynum, mut point) = get_public_key(&session, slot);

    let mut key: Vec<u8> = vec![];
    key.append(&mut "Ed".as_bytes().to_vec());
    key.append(&mut keynum.to_vec());
    key.append(&mut point);

    println!("untrusted comment: yk-pkg-sign public key");
    println!("{}", BASE64_STANDARD.encode(key));
}