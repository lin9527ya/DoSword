use dosword_sdk::encoder::{session_handler_code, CharEncoder};
use dosword_sdk::PayloadEncoder;

#[test]
fn dump() {
    let stub = CharEncoder.stub_session("php", "secret").unwrap();
    std::fs::write("/tmp/opencode/cs2.php", &stub).unwrap();
    let enc = CharEncoder.encode(session_handler_code(), "secret");
    std::fs::write("/tmp/opencode/char_init.txt", &enc).unwrap();
}
