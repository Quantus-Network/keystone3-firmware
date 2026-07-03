#ifndef _GUI_QUANTUS_H
#define _GUI_QUANTUS_H

#include "rust.h"
#include "lvgl.h"

// Single source of truth for the Quantus HD path template (coin type 189189, %u = account
// index). Receive and signing must derive from the same template so they can never diverge;
// signing uses index 0, matching the only index the receive UI exposes (audit M-2).
#define QUANTUS_HD_PATH_FMT "m/44'/189189'/%u'/0'/0'"

void GuiSetQuantusUrData(URParseResult *urResult, URParseMultiResult *urMultiResult, bool multi);
void *GuiGetQuantusData(void);
PtrT_TransactionCheckResult GuiGetQuantusCheckResult(void);
void GetQuantusValue(void *indata, void *param, uint32_t maxLen);
void (*GuiQuantusTextFuncGet(char *type))(void *indata, void *param, uint32_t maxLen);
UREncodeResult *GuiGetQuantusSignQrCodeData(void);
void GuiQuantusOverview(lv_obj_t *parent, void *totalData);
bool GetQuantusIsTransfer(void *indata, void *param);
bool GetQuantusIsMultisig(void *indata, void *param);
void GuiQuantusMultisigDetails(lv_obj_t *parent, void *totalData);
void FreeQuantusMemory(void);

// Run `fn(ctx)` on a dedicated, PSRAM-backed stack large enough for ML-DSA-87 keygen/signing,
// blocking until it completes. ML-DSA needs ~110 KB of stack (far more than the UI/sensitive
// task stacks), so it must not run on the caller's stack. On the simulator this runs inline.
typedef void (*QuantusCryptoFunc_t)(void *ctx);
void QuantusRunCrypto(QuantusCryptoFunc_t fn, void *ctx);

// Reconstruct the current account's BIP39 mnemonic from stored entropy (SRAM-allocated). Returns
// NULL on any failure (fail loud, no fallback). The caller MUST hand the result to
// QuantusWipeAndFreeMnemonic as soon as it is done, so the secret is zeroized the moment it is no
// longer needed. Shared by the signing and address-derivation paths.
char *QuantusReconstructMnemonic(void);
void QuantusWipeAndFreeMnemonic(char *mnemonic);

#endif /* _GUI_QUANTUS_H */
