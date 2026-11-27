// Tests for multi-key parameter parsing

use rsacracker::{Attack, CommonModulusAttack, HastadBroadcastAttack, Parameters};
use rug::Integer;

#[test]
fn multi_key_from_raw() {
    // Test parsing multi-key parameters from raw text
    let raw = r#"
# Multi-key example
n1 = 166162630914502531310583922419891282066165820974633135604215723500594369488785155668770814942798477925368262423257419073645831352835527789101770856835355683177962166057699839663569971312562086050531058716298108813024798653596850452010850976880829077654912494652271256054564920903881745267063001869548202922099
e1 = 65537
c1 = 123

n2 = 148455898656074447797752378503069279028991863906908832057033693077681993859745690328279867444062926638337203683279627319119630089306918893030699950731547426066997479055479829293964341682216330844958953722765260947532634616964944677851975839768164255655099799121904635086103339949975609477039895462111764318783
e2 = 65537
c2 = 456
"#;

    let params = Parameters::from_raw(raw);

    // The first indexed key becomes the main key so single-key and multi-key attacks
    // see the same parameters.
    assert!(params.n.is_some());
    assert_ne!(params.n, params.keys[0].n.clone());
    assert_eq!(params.e, Integer::from(65537));
    assert_eq!(params.c, Some(Integer::from(123)));
    assert_eq!(params.keys.len(), 1);

    let key2 = &params.keys[0];
    assert!(key2.n.is_some());
    assert_eq!(key2.e, Integer::from(65537));
    assert_eq!(key2.c, Some(Integer::from(456)));
}

#[test]
fn multi_key_mixed_indexed_from_raw() {
    // Test parsing multi-key parameters with mixed indexed and non-indexed notation
    let raw = r#"
# Mixed indexed and non-indexed keys
n = 123456789
e = 65537
c = 100

n2 = 987654321
e2 = 3
c2 = 200
"#;

    let params = Parameters::from_raw(raw);

    // Main key from non-indexed parameters
    assert_eq!(params.n, Some(Integer::from(123456789)));
    assert_eq!(params.e, Integer::from(65537));
    assert_eq!(params.c, Some(Integer::from(100)));

    // Additional key at index 2
    assert_eq!(params.keys.len(), 1);
    let key2 = &params.keys[0];
    assert_eq!(key2.n, Some(Integer::from(987654321)));
    assert_eq!(key2.e, Integer::from(3));
    assert_eq!(key2.c, Some(Integer::from(200)));
}

#[test]
fn multi_key_multi_digit_indices() {
    // Test parsing keys with multi-digit indices (n10, e15, c20, etc.)
    let raw = r#"
# Test multi-digit indices
n10 = 111111111
e10 = 3
c10 = 100

n15 = 222222222
e15 = 5
c15 = 200

n20 = 333333333
e20 = 7
c20 = 300
"#;

    let params = Parameters::from_raw(raw);

    // The lowest indexed key becomes the main key; the remaining keys stay sorted.
    assert_eq!(params.n, Some(Integer::from(111111111)));
    assert_eq!(params.e, Integer::from(3));
    assert_eq!(params.c, Some(Integer::from(100)));
    assert_eq!(params.keys.len(), 2);

    let key1 = &params.keys[0];
    assert_eq!(key1.n, Some(Integer::from(222222222)));
    assert_eq!(key1.e, Integer::from(5));
    assert_eq!(key1.c, Some(Integer::from(200)));

    let key2 = &params.keys[1];
    assert_eq!(key2.n, Some(Integer::from(333333333)));
    assert_eq!(key2.e, Integer::from(7));
    assert_eq!(key2.c, Some(Integer::from(300)));
}

#[test]
fn raw_common_modulus_input_runs_attack() {
    let n = Integer::from(61) * 53;
    let e1 = Integer::from(17);
    let e2 = Integer::from(65539);
    let m = Integer::from(42);
    let c1 = m.clone().pow_mod(&e1, &n).unwrap();
    let c2 = m.clone().pow_mod(&e2, &n).unwrap();
    let raw = format!("n1 = {n}\ne1 = {e1}\nc1 = {c1}\nn2 = {n}\ne2 = {e2}\nc2 = {c2}\n");

    let params = Parameters::from_raw(&raw);
    let solution = CommonModulusAttack.run(&params, None).unwrap();
    assert_eq!(solution.m, Some(m));
}

#[test]
fn raw_hastad_input_runs_attack() {
    let raw = "n1 = 11\ne1 = 3\nc1 = 8\nn2 = 13\ne2 = 3\nc2 = 8\nn3 = 17\ne3 = 3\nc3 = 8\n";

    let params = Parameters::from_raw(raw);
    let solution = HastadBroadcastAttack.run(&params, None).unwrap();
    assert_eq!(solution.m, Some(Integer::from(2)));
}
