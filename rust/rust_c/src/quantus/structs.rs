use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use crate::common::{
    ffi::VecFFI,
    free::Free,
    types::{PtrString, PtrT},
    utils::convert_c_char,
};
use crate::free_str_ptr;
use app_quantus::structs::ParsedQuantusTx;

#[repr(C)]
pub struct DisplayQuantusTx {
    pub tx_type: PtrString,
    pub is_multisig: bool,
    pub signer: PtrString,
    pub to: PtrString,
    pub to_checkphrase: PtrString,
    pub amount: PtrString,
    pub nonce: PtrString,
    pub tip: PtrString,
    pub is_reversible: bool,
    pub reversible_timeframe: PtrString,
    pub network: PtrString,
    pub era: PtrString,
    pub detail_labels: PtrT<VecFFI<PtrString>>,
    pub detail_values: PtrT<VecFFI<PtrString>>,
}

fn string_vec_to_ffi(items: Vec<String>) -> PtrT<VecFFI<PtrString>> {
    VecFFI::from(items.into_iter().map(convert_c_char).collect::<Vec<PtrString>>()).c_ptr()
}

unsafe fn free_string_vec_ffi(ptr: PtrT<VecFFI<PtrString>>) {
    if ptr.is_null() {
        return;
    }
    let x = Box::from_raw(ptr);
    let ve = Vec::from_raw_parts(x.data, x.size, x.cap);
    ve.iter().for_each(|v| {
        free_str_ptr!(*v);
    });
}

impl From<&ParsedQuantusTx> for DisplayQuantusTx {
    fn from(tx: &ParsedQuantusTx) -> Self {
        Self {
            tx_type: convert_c_char(tx.get_tx_type()),
            is_multisig: tx.get_is_multisig(),
            signer: convert_c_char(tx.get_signer()),
            to: convert_c_char(tx.get_to()),
            to_checkphrase: convert_c_char(tx.get_to_checkphrase()),
            amount: convert_c_char(tx.get_amount()),
            nonce: convert_c_char(tx.get_nonce()),
            tip: convert_c_char(tx.get_tip()),
            is_reversible: tx.get_is_reversible(),
            reversible_timeframe: convert_c_char(tx.get_reversible_timeframe()),
            network: convert_c_char(tx.get_network()),
            era: convert_c_char(tx.get_era()),
            detail_labels: string_vec_to_ffi(tx.get_detail_labels()),
            detail_values: string_vec_to_ffi(tx.get_detail_values()),
        }
    }
}

impl Free for DisplayQuantusTx {
    unsafe fn free(&self) {
        free_str_ptr!(self.tx_type);
        free_str_ptr!(self.signer);
        free_str_ptr!(self.to);
        free_str_ptr!(self.to_checkphrase);
        free_str_ptr!(self.amount);
        free_str_ptr!(self.nonce);
        free_str_ptr!(self.tip);
        free_str_ptr!(self.reversible_timeframe);
        free_str_ptr!(self.network);
        free_str_ptr!(self.era);
        free_string_vec_ffi(self.detail_labels);
        free_string_vec_ffi(self.detail_values);
    }
}
