use pos_client::{
    salted_hardware_id_hash,
    PosClient,
    RegisterRequest,
    UreqTransport,
};

fn main() {
    let mut args = std::env::args().skip(1);

    let register_url = args.next().expect(
        "usage: register_cli <register-url> <redeem-url> <invite-code> <opaque-id> <salt>"
    );

    let redeem_url = args.next().expect("missing redeem-url");
    let invite_code = args.next().expect("missing invite-code");
    let opaque_hardware_id = args.next().expect("missing opaque-hardware-id");
    let salt = args.next().expect("missing salt");

    let client = PosClient::new(
        UreqTransport,
        register_url,
        redeem_url,
    )
    .expect("endpoints must be HTTPS");

    let request = RegisterRequest {
        invite_code,
        hardware_id_hash: salted_hardware_id_hash(
            salt.as_bytes(),
            opaque_hardware_id.as_bytes(),
        ),
    };

    match client.register(&request) {
        Ok(response) => {
            println!("registered device_id={}", response.device_id);
        }
        Err(error) => {
            eprintln!("registration failed: {error}");
        }
    }
}
