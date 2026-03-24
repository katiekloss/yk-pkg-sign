use std::env;

use base64::{Engine, prelude::BASE64_STANDARD};
use cryptoki::{context::{CInitializeArgs, CInitializeFlags}, mechanism::{Mechanism, eddsa::{EddsaParams, EddsaSignatureScheme}}, object::{Attribute, AttributeType, ObjectClass}, session::{Session, UserType}, types::AuthPin};
use secrecy::SecretString;
use yk_pkg_sign::{ALL_ATTRS, SLOTS, SigningRequest};

fn connect() -> Session {
    let ctx = cryptoki::context::Pkcs11::new("/usr/local/lib/libykcs11.dylib").expect("Cannot load PKCS impl");
    //let ctx = cryptoki::context::Pkcs11::new("/usr/local/lib/softhsm/libsofthsm2.so").unwrap();
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

pub fn sign(data: &[u8], req: &SigningRequest) -> Vec<u8> {
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

pub fn export(slot: &String) {
    let session = connect();

    let (keynum, mut point) = get_public_key(&session, slot);

    let mut key: Vec<u8> = vec![];
    key.append(&mut "Ed".as_bytes().to_vec());
    key.append(&mut keynum.to_vec());
    key.append(&mut point);

    println!("untrusted comment: yk-pkg-sign public key");
    println!("{}", BASE64_STANDARD.encode(key));
}

pub fn show_token() {
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
