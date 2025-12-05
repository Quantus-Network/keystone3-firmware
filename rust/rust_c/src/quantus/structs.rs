use core::ptr::null_mut;
use crate::common::{
    free::Free,
    types::{PtrString},
    utils::convert_c_char,
};
use crate::{free_str_ptr};
use app_quantus::structs::ParsedQuantusTx;

#[repr(C)]
pub struct DisplayQuantusTx {
    pub to: PtrString,
    pub amount: PtrString,
    pub nonce: PtrString,
    pub fee: PtrString,
}

impl From<&ParsedQuantusTx> for DisplayQuantusTx {
    fn from(tx: &ParsedQuantusTx) -> Self {
        Self {
            to: convert_c_char(tx.get_to()),
            amount: convert_c_char(tx.get_amount()),
            nonce: convert_c_char(tx.get_nonce()),
            fee: convert_c_char(tx.get_fee()),
        }
    }
}

impl Free for DisplayQuantusTx {
    unsafe fn free(&self) {
        free_str_ptr!(self.to);
        free_str_ptr!(self.amount);
        free_str_ptr!(self.nonce);
        free_str_ptr!(self.fee);
    }
}

