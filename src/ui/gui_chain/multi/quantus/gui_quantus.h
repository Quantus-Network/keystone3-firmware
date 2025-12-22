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

#endif /* _GUI_QUANTUS_H */
