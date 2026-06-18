#ifndef _GUI_QUANTUS_H
#define _GUI_QUANTUS_H

#include "rust.h"
#include "lvgl.h"

void GuiSetQuantusUrData(URParseResult *urResult, URParseMultiResult *urMultiResult, bool multi);
void *GuiGetQuantusData(void);
PtrT_TransactionCheckResult GuiGetQuantusCheckResult(void);
void GetQuantusValue(void *indata, void *param, uint32_t maxLen);
void (*GuiQuantusTextFuncGet(char *type))(void *indata, void *param, uint32_t maxLen);
UREncodeResult *GuiGetQuantusSignQrCodeData(void);
void GuiQuantusOverview(lv_obj_t *parent, void *totalData);
void FreeQuantusMemory(void);

// Run `fn(ctx)` on a dedicated, PSRAM-backed stack large enough for ML-DSA-87 keygen/signing,
// blocking until it completes. ML-DSA needs ~110 KB of stack (far more than the UI/sensitive
// task stacks), so it must not run on the caller's stack. On the simulator this runs inline.
typedef void (*QuantusCryptoFunc_t)(void *ctx);
void QuantusRunCrypto(QuantusCryptoFunc_t fn, void *ctx);

#endif /* _GUI_QUANTUS_H */
