use kevi::api::{EntryLabel, OtpName, ProfileName, VaultPath};
use std::path::PathBuf;

#[test]
fn entry_label_conversions_and_display() {
    let lbl = EntryLabel::from("github");

    // as_str and Display
    assert_eq!(lbl.as_str(), "github");
    assert_eq!(lbl.to_string(), "github");

    // Into<String> and back
    let s: String = String::from(lbl.clone());
    assert_eq!(s, "github");

    let lbl2 = EntryLabel::from(s);
    assert_eq!(lbl2, lbl);
}

#[test]
fn entry_label_equality_with_string_and_str_refs() {
    let lbl = EntryLabel::from("alpha");
    let owned = "alpha".to_string();
    let borrowed: &str = "alpha";

    // Owned String comparisons
    assert_eq!(lbl, owned);
    assert_eq!(String::from(lbl.clone()), "alpha");

    // &str and &&str comparisons (both directions)
    assert_eq!(lbl, borrowed);
    assert_eq!(borrowed, lbl);
}

#[test]
fn entry_label_inequality_for_different_values() {
    let lbl = EntryLabel::from("one");

    assert_ne!(lbl, "two");
    assert_ne!(lbl, "two".to_string());
}

#[test]
fn entry_label_double_ref_equality_and_as_ref() {
    let lbl = EntryLabel::from("delta");
    let double_ref: &&str = &"delta";

    assert_eq!(lbl, *double_ref);
    assert_eq!(*double_ref, lbl);

    let sref: &str = lbl.as_ref();
    assert_eq!(sref, "delta");
}

#[test]
fn profile_name_conversions_display_and_equality() {
    let pn = ProfileName::from("work");
    assert_eq!(pn.as_str(), "work");
    assert_eq!(pn.to_string(), "work");

    let as_string: String = pn.clone().into();
    assert_eq!(as_string, "work");

    let pn2 = ProfileName::from(as_string.clone());
    assert_eq!(pn2, pn);
    assert_eq!(pn, as_string);
    assert_eq!(String::from(pn2.clone()), "work");
    assert_eq!("work".to_string(), pn2);

    let aref: &str = pn2.as_ref();
    assert_eq!(aref, "work");
}

#[test]
fn vault_path_conversions_display_and_equality() {
    let pb = PathBuf::from("/tmp/vault.ron");
    let vp = VaultPath::from(pb.clone());

    assert_eq!(vp.to_string(), pb.to_string_lossy());
    assert_eq!(vp.as_path(), pb.as_path());

    let back: PathBuf = vp.clone().into();
    assert_eq!(back, pb);

    // PartialEq implementations both directions
    assert_eq!(vp, pb);
    assert_eq!(pb, vp);

    // AsRef<Path>
    let as_ref: &std::path::Path = vp.as_ref();
    assert_eq!(as_ref, pb.as_path());
}

#[test]
fn otp_name_conversions_display_and_equality() {
    let on = OtpName::from("otp1");
    assert_eq!(on.as_str(), "otp1");
    assert_eq!(on.to_string(), "otp1");

    let as_string: String = on.clone().into();
    assert_eq!(as_string, "otp1");

    let on2 = OtpName::from(as_string.clone());
    assert_eq!(on2, on);
    assert_eq!(on, as_string);
    assert_eq!(String::from(on2.clone()), "otp1");
    assert_eq!("otp1".to_string(), on2);

    let aref: &str = on2.as_ref();
    assert_eq!(aref, "otp1");
}
