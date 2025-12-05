#ifndef _GUI_QUANTUS_H
#define _GUI_QUANTUS_H

#include "gui_analyze.h"
#include "rust.h"

void GuiSetQuantusUrData(URParseResult *urResult, URParseMultiResult *urMultiResult, bool multi);
void *GuiGetQuantusData(void);
PtrT_TransactionCheckResult GuiGetQuantusCheckResult(void);
void GetQuantusValue(void *indata, void *param, uint32_t maxLen);
GetLabelDataFunc GuiQuantusTextFuncGet(char *type);
UREncodeResult *GuiGetQuantusSignQrCodeData(void);
void GuiQuantusOverview(lv_obj_t *parent, void *totalData);
void FreeQuantusMemory(void);

#endif /* _GUI_QUANTUS_H */
