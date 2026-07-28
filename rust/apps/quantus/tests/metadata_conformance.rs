//! Audit H-2: confirm every SCALE encoding assumed by the parser's mirror types against the
//! runtime metadata the chain itself publishes, so a codec mismatch (e.g. compact vs fixed
//! u128 amounts) can never silently change what the device displays for the bytes it signs.
//!
//! The fixture is the live Planck V14 metadata (spec 136). Regenerate with:
//!   curl -s -H "Content-Type: application/json" \
//!     -d '{"jsonrpc":"2.0","id":1,"method":"state_getMetadata","params":[]}' \
//!     https://a1-planck.quantus.cat | jq -r .result | cut -c3- | xxd -r -p > planck_metadata.scale

use frame_metadata::v14::RuntimeMetadataV14;
use frame_metadata::{RuntimeMetadata, RuntimeMetadataPrefixed};
use parity_scale_codec::Decode;
use scale_info::{form::PortableForm, Type, TypeDef, TypeDefPrimitive, Variant};

const METADATA: &[u8] = include_bytes!("fixtures/planck_metadata_v14_spec136.scale");

fn planck_metadata() -> RuntimeMetadataV14 {
    let prefixed = RuntimeMetadataPrefixed::decode(&mut &METADATA[..]).expect("decode metadata");
    match prefixed.1 {
        RuntimeMetadata::V14(meta) => meta,
        other => panic!("expected V14 metadata, got {:?}", other),
    }
}

fn resolve(meta: &RuntimeMetadataV14, id: u32) -> &Type<PortableForm> {
    meta.types.resolve(id).unwrap_or_else(|| panic!("type {} not in registry", id))
}

/// Returns the call variants of the pallet, asserting the pallet index the parser hardcodes.
fn pallet_calls<'a>(
    meta: &'a RuntimeMetadataV14,
    name: &str,
    expected_index: u8,
) -> &'a [Variant<PortableForm>] {
    let pallet = meta
        .pallets
        .iter()
        .find(|p| p.name == name)
        .unwrap_or_else(|| panic!("pallet {} not found", name));
    assert_eq!(pallet.index, expected_index, "{} pallet index", name);
    let calls = pallet.calls.as_ref().unwrap_or_else(|| panic!("{} has no calls", name));
    match &resolve(meta, calls.ty.id).type_def {
        TypeDef::Variant(v) => &v.variants,
        other => panic!("{} calls not a variant: {:?}", name, other),
    }
}

fn call<'a>(
    variants: &'a [Variant<PortableForm>],
    index: u8,
    name: &str,
) -> &'a Variant<PortableForm> {
    let v = variants
        .iter()
        .find(|v| v.index == index)
        .unwrap_or_else(|| panic!("no call at index {}", index));
    assert_eq!(v.name, name, "call name at index {}", index);
    v
}

/// The mirror types decode every field in declaration order, so a field added, removed, or
/// reordered on-chain is a break even when the fields the mirror knows about still resolve.
fn assert_field_names(variant: &Variant<PortableForm>, expected: &[&str]) {
    let names: Vec<&str> = variant.fields.iter().filter_map(|f| f.name.as_deref()).collect();
    assert_eq!(names, expected, "{} fields", variant.name);
}

fn field_ty(variant: &Variant<PortableForm>, name: &str) -> u32 {
    variant
        .fields
        .iter()
        .find(|f| f.name.as_deref() == Some(name))
        .unwrap_or_else(|| panic!("call {} has no field {}", variant.name, name))
        .ty
        .id
}

fn assert_primitive(meta: &RuntimeMetadataV14, id: u32, expected: TypeDefPrimitive, what: &str) {
    match &resolve(meta, id).type_def {
        TypeDef::Primitive(p) if *p == expected => {}
        other => panic!("{}: expected {:?}, got {:?}", what, expected, other),
    }
}

fn assert_compact(meta: &RuntimeMetadataV14, id: u32, inner: TypeDefPrimitive, what: &str) {
    match &resolve(meta, id).type_def {
        TypeDef::Compact(c) => assert_primitive(meta, c.type_param.id, inner, what),
        other => panic!("{}: expected Compact, got {:?}", what, other),
    }
}

/// A newtype composite (AccountId32, H256, BoundedVec) — returns its single field's type id.
fn newtype_inner(meta: &RuntimeMetadataV14, id: u32, what: &str) -> u32 {
    match &resolve(meta, id).type_def {
        TypeDef::Composite(c) if c.fields.len() == 1 => c.fields[0].ty.id,
        other => panic!("{}: expected single-field composite, got {:?}", what, other),
    }
}

/// BoundedVec<u8> encodes exactly like Vec<u8>: newtype around a u8 sequence.
fn assert_call_bytes(meta: &RuntimeMetadataV14, id: u32, what: &str) {
    match &resolve(meta, newtype_inner(meta, id, what)).type_def {
        TypeDef::Sequence(s) => assert_primitive(meta, s.type_param.id, TypeDefPrimitive::U8, what),
        other => panic!("{}: expected byte sequence, got {:?}", what, other),
    }
}

fn assert_32_byte_newtype(meta: &RuntimeMetadataV14, id: u32, path_end: &str, what: &str) {
    let ty = resolve(meta, id);
    assert_eq!(ty.path.segments.last().map(String::as_str), Some(path_end), "{}", what);
    match &resolve(meta, newtype_inner(meta, id, what)).type_def {
        TypeDef::Array(a) if a.len == 32 => {
            assert_primitive(meta, a.type_param.id, TypeDefPrimitive::U8, what)
        }
        other => panic!("{}: expected [u8; 32], got {:?}", what, other),
    }
}

/// The parser's `MultiAddress` mirror only decodes variant 0 (`Id(AccountId32)`); anything else
/// must be a decode failure, so variant 0 being `Id` is load-bearing.
fn assert_multi_address(meta: &RuntimeMetadataV14, id: u32, what: &str) {
    let ty = resolve(meta, id);
    assert_eq!(ty.path.segments.last().map(String::as_str), Some("MultiAddress"), "{}", what);
    let TypeDef::Variant(v) = &ty.type_def else {
        panic!("{}: MultiAddress not a variant", what)
    };
    let id_variant = call(&v.variants, 0, "Id");
    assert_32_byte_newtype(meta, id_variant.fields[0].ty.id, "AccountId32", what);
}

fn assert_unit(meta: &RuntimeMetadataV14, id: u32, what: &str) {
    match &resolve(meta, id).type_def {
        TypeDef::Composite(c) if c.fields.is_empty() => {}
        TypeDef::Tuple(t) if t.fields.is_empty() => {}
        other => panic!("{}: expected zero-byte encoding, got {:?}", what, other),
    }
}

#[test]
fn balances_transfer_amounts_are_compact_u128() {
    let meta = planck_metadata();
    let calls = pallet_calls(&meta, "Balances", 2);
    for (index, name) in [(0, "transfer_allow_death"), (3, "transfer_keep_alive")] {
        let c = call(calls, index, name);
        assert_field_names(c, &["dest", "value"]);
        assert_multi_address(&meta, field_ty(c, "dest"), name);
        assert_compact(&meta, field_ty(c, "value"), TypeDefPrimitive::U128, name);
    }
}

#[test]
fn reversible_transfer_amounts_are_plain_u128() {
    let meta = planck_metadata();
    let calls = pallet_calls(&meta, "ReversibleTransfers", 11);
    for (index, name, fields) in [
        (3, "schedule_transfer", &["dest", "amount"][..]),
        (4, "schedule_transfer_with_delay", &["dest", "amount", "delay"][..]),
    ] {
        let c = call(calls, index, name);
        assert_field_names(c, fields);
        assert_multi_address(&meta, field_ty(c, "dest"), name);
        // The heart of H-2: fixed-width u128, NOT compact like Balances.
        assert_primitive(&meta, field_ty(c, "amount"), TypeDefPrimitive::U128, name);
    }

    let delay_ty = field_ty(call(calls, 4, "schedule_transfer_with_delay"), "delay");
    let TypeDef::Variant(v) = &resolve(&meta, delay_ty).type_def else {
        panic!("delay not a variant")
    };
    let block_number = call(&v.variants, 0, "BlockNumber");
    assert_primitive(&meta, block_number.fields[0].ty.id, TypeDefPrimitive::U32, "delay block");
    let timestamp = call(&v.variants, 1, "Timestamp");
    assert_primitive(&meta, timestamp.fields[0].ty.id, TypeDefPrimitive::U64, "delay timestamp");
}

#[test]
fn multisig_calls_match_mirror_types() {
    let meta = planck_metadata();
    let calls = pallet_calls(&meta, "Multisig", 19);

    let create = call(calls, 0, "create_multisig");
    assert_field_names(create, &["signers", "threshold", "nonce"]);
    match &resolve(&meta, field_ty(create, "signers")).type_def {
        TypeDef::Sequence(s) => {
            assert_32_byte_newtype(&meta, s.type_param.id, "AccountId32", "signers")
        }
        other => panic!("signers: expected Vec, got {:?}", other),
    }
    assert_primitive(&meta, field_ty(create, "threshold"), TypeDefPrimitive::U32, "threshold");
    assert_primitive(&meta, field_ty(create, "nonce"), TypeDefPrimitive::U64, "nonce");

    let propose = call(calls, 1, "propose");
    assert_field_names(propose, &["multisig_address", "call", "expiry"]);
    assert_32_byte_newtype(&meta, field_ty(propose, "multisig_address"), "AccountId32", "propose");
    assert_call_bytes(&meta, field_ty(propose, "call"), "propose call");
    assert_primitive(&meta, field_ty(propose, "expiry"), TypeDefPrimitive::U32, "expiry");

    // The chain binds approvals to the proposal's exact call bytes (audit H-2); the mirror
    // decodes them, so their presence and encoding are load-bearing.
    let approve = call(calls, 2, "approve");
    assert_field_names(approve, &["multisig_address", "proposal_id", "call"]);
    assert_32_byte_newtype(&meta, field_ty(approve, "multisig_address"), "AccountId32", "approve");
    assert_primitive(&meta, field_ty(approve, "proposal_id"), TypeDefPrimitive::U32, "approve");
    assert_call_bytes(&meta, field_ty(approve, "call"), "approve call");

    let execute = call(calls, 6, "execute");
    assert_field_names(execute, &["multisig_address", "proposal_id"]);
    assert_32_byte_newtype(&meta, field_ty(execute, "multisig_address"), "AccountId32", "execute");
    assert_primitive(&meta, field_ty(execute, "proposal_id"), TypeDefPrimitive::U32, "execute");
}

/// The parser's `SignedExtensions` struct assumes an exact extension order and codec for each
/// entry. Verify identifier order, explicit (`ty`) encodings, and implicit (`additional_signed`)
/// encodings against the metadata.
#[test]
fn signed_extension_order_and_codecs_match_mirror() {
    let meta = planck_metadata();
    assert_eq!(meta.extrinsic.version, 4);

    let identifiers: Vec<&str> = meta
        .extrinsic
        .signed_extensions
        .iter()
        .map(|e| e.identifier.as_str())
        .collect();
    assert_eq!(
        identifiers,
        [
            "CheckNonZeroSender",
            "CheckSpecVersion",
            "CheckTxVersion",
            "CheckGenesis",
            "CheckMortality",
            "CheckNonce",
            "CheckWeight",
            "ChargeTransactionPayment",
            "CheckMetadataHash",
            "ReversibleTransactionExtension",
            "WormholeProofRecorderExtension",
        ]
    );

    for ext in &meta.extrinsic.signed_extensions {
        let what = ext.identifier.as_str();
        match what {
            "CheckMortality" => {
                let era = newtype_inner(&meta, ext.ty.id, what);
                let era_ty = resolve(&meta, era);
                assert_eq!(era_ty.path.segments.last().map(String::as_str), Some("Era"));
                match &era_ty.type_def {
                    // Immortal + Mortal1..=Mortal255, matching the parser's custom Era decoder.
                    TypeDef::Variant(v) => assert_eq!(v.variants.len(), 256),
                    other => panic!("Era not a variant: {:?}", other),
                }
                assert_32_byte_newtype(&meta, ext.additional_signed.id, "H256", what);
            }
            "CheckNonce" => {
                let nonce = newtype_inner(&meta, ext.ty.id, what);
                assert_compact(&meta, nonce, TypeDefPrimitive::U32, what);
                assert_unit(&meta, ext.additional_signed.id, what);
            }
            "ChargeTransactionPayment" => {
                let tip = newtype_inner(&meta, ext.ty.id, what);
                assert_compact(&meta, tip, TypeDefPrimitive::U128, what);
                assert_unit(&meta, ext.additional_signed.id, what);
            }
            "CheckMetadataHash" => {
                let mode = newtype_inner(&meta, ext.ty.id, what);
                let TypeDef::Variant(v) = &resolve(&meta, mode).type_def else {
                    panic!("Mode not a variant")
                };
                assert!(call(&v.variants, 0, "Disabled").fields.is_empty());
                assert!(call(&v.variants, 1, "Enabled").fields.is_empty());
                // additional_signed: Option<[u8; 32]>
                let TypeDef::Variant(opt) = &resolve(&meta, ext.additional_signed.id).type_def
                else {
                    panic!("metadata hash additional not an Option")
                };
                assert!(call(&opt.variants, 0, "None").fields.is_empty());
                let some = call(&opt.variants, 1, "Some");
                match &resolve(&meta, some.fields[0].ty.id).type_def {
                    TypeDef::Array(a) if a.len == 32 => {}
                    other => panic!("metadata hash: expected [u8; 32], got {:?}", other),
                }
            }
            "CheckSpecVersion" | "CheckTxVersion" => {
                assert_unit(&meta, ext.ty.id, what);
                assert_primitive(&meta, ext.additional_signed.id, TypeDefPrimitive::U32, what);
            }
            "CheckGenesis" => {
                assert_unit(&meta, ext.ty.id, what);
                assert_32_byte_newtype(&meta, ext.additional_signed.id, "H256", what);
            }
            _ => {
                // CheckNonZeroSender, CheckWeight, Reversible, Wormhole: no signed bytes at all.
                assert_unit(&meta, ext.ty.id, what);
                assert_unit(&meta, ext.additional_signed.id, what);
            }
        }
    }
}
