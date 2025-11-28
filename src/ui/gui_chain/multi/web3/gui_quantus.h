#include "gui_chain.h"
#include "gui_eth.h"

void GuiSetQuantusUrData(URParseResult *urResult, URParseMultiResult *urMultiResult, bool multi);
void *GuiGetQuantusData(void);
PtrT_TransactionCheckResult GuiGetQuantusCheckResult(void);
void GetQuantusValue(void *indata, void *param, uint32_t maxLen);
UREncodeResult *GuiGetQuantusSignQrCodeData(void);

