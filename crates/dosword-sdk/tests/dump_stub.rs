use dosword_sdk::encoder::NativeEncoder;
use dosword_sdk::PayloadEncoder;

#[test]
fn dump() {
    std::fs::write("/tmp/opencode/nv_jsp.jsp", NativeEncoder { crypto: "xor" }.stub("jsp", "secret").unwrap()).unwrap();
    std::fs::write("/tmp/opencode/nv_aspx.aspx", NativeEncoder { crypto: "xor" }.stub("aspx", "secret").unwrap()).unwrap();
}
