use cryptoki::context::{CInitializeArgs, CInitializeFlags};

fn main() {
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
}
