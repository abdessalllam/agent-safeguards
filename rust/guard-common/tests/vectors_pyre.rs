use guard_common::pyre;
use serde_json::Value;

#[test]
fn classes_match_python_for_every_code_point() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/pyre_classes.json");
    let text = std::fs::read_to_string(path).expect("run python3 tests/gen_pyre.py first");
    let document: Value = serde_json::from_str(&text).expect("json");
    for (name, source) in [("s", r"\A\s\z"), ("w", r"\A\w\z"), ("d", r"\A\d\z")] {
        let matcher = pyre::new(source).expect("pattern");
        let mut expected = vec![false; 0x110000];
        for range in document[name].as_array().expect("ranges") {
            let (low, high) = (range[0].as_u64().expect("low") as usize, range[1].as_u64().expect("high") as usize);
            for slot in expected.iter_mut().take(high + 1).skip(low) {
                *slot = true;
            }
        }
        let mut unassigned = vec![false; 0x110000];
        for range in document["unassigned"].as_array().expect("ranges") {
            let (low, high) = (range[0].as_u64().expect("low") as usize, range[1].as_u64().expect("high") as usize);
            for slot in unassigned.iter_mut().take(high + 1).skip(low) {
                *slot = true;
            }
        }
        let mut wrong = Vec::new();
        for code in 0..0x110000u32 {
            let Some(character) = char::from_u32(code) else { continue };
            let mut buffer = [0u8; 4];
            if !unassigned[code as usize] && matcher.is_match(character.encode_utf8(&mut buffer)) != expected[code as usize] {
                wrong.push(format!("U+{code:04X}"));
            }
        }
        assert!(wrong.is_empty(), "class {name}: {} code points differ, first {:?}", wrong.len(), &wrong[..wrong.len().min(20)]);
    }
}
