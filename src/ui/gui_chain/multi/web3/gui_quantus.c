#include "gui_quantus.h"
#include "gui_analyze.h"
#include "keystore.h"
#include "gui_model.h"
#include "gui_qr_hintbox.h"
#include "screen_manager.h"
#include "device_setting.h"
#include "gui_views.h"
#include "librust_c.h"
#include "secret_cache.h"
#include "bip39.h"
#include "user_utils.h"
#include "gui_chain.h"
#include "account_manager.h"
#include "gui_chain_components.h"

static URParseResult *g_urResult = NULL;
static URParseMultiResult *g_urMultiResult = NULL;
static bool g_isMulti = false;
static void *g_parseResult = NULL;
static DisplayQuantusTx *g_quantusData = NULL;

#define CHECK_FREE_PARSE_RESULT(result)                                                             \
    if (result != NULL)                                                                             \
    {                                                                                               \
        free_TransactionParseResult_DisplayQuantusTx((PtrT_TransactionParseResult_DisplayQuantusTx)result);   \
        result = NULL;                                                                              \
    }

void GuiSetQuantusUrData(URParseResult *urResult, URParseMultiResult *urMultiResult, bool multi)
{
    g_urResult = urResult;
    g_urMultiResult = urMultiResult;
    g_isMulti = multi;
}

void *GuiGetQuantusData(void)
{
    CHECK_FREE_PARSE_RESULT(g_parseResult);
    void *data = g_isMulti ? g_urMultiResult->data : g_urResult->data;
    
    // Parse
    PtrT_TransactionParseResult_DisplayQuantusTx result = quantus_parse_tx(data);
    if (result->code != 0) {
        // handle error
        return NULL; 
    }
    g_parseResult = (void *)result;
    g_quantusData = (DisplayQuantusTx *)result->data;
    return g_parseResult;
}

PtrT_TransactionCheckResult GuiGetQuantusCheckResult(void)
{
    void *data = g_isMulti ? g_urMultiResult->data : g_urResult->data;
    uint8_t mfp[4];
    GetMasterFingerPrint(mfp);
    return quantus_check_tx(data, mfp, 4);
}

void GuiQuantusOverview(lv_obj_t *parent, void *totalData)
{
    lv_obj_set_size(parent, 408, 480);
    lv_obj_add_flag(parent, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(parent, LV_OBJ_FLAG_CLICKABLE);

    lv_obj_t* container = GuiCreateContainerWithParent(parent, 408, 480);
    lv_obj_add_flag(container, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(container, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_set_scrollbar_mode(container, LV_SCROLLBAR_MODE_OFF);

    lv_obj_t* last_view = NULL;

    if (g_quantusData) {
        last_view = CreateTransactionItemView(container, _("To"), g_quantusData->to, last_view);
        last_view = CreateTransactionItemView(container, _("Amount"), g_quantusData->amount, last_view);
        last_view = CreateTransactionItemView(container, _("Fee"), g_quantusData->fee, last_view);
        last_view = CreateTransactionItemView(container, _("Nonce"), g_quantusData->nonce, last_view);
    }
    
    lv_obj_set_height(container, lv_obj_get_scroll_height(container));
}

void GetQuantusValue(void *indata, void *param, uint32_t maxLen)
{
    if (g_quantusData) {
         snprintf((char *)indata, maxLen, "%s", g_quantusData->amount);
    } else {
         snprintf((char *)indata, maxLen, "Quantus Transaction");
    }
}

GetLabelDataFunc GuiQuantusTextFuncGet(char *type)
{
    if (!strcmp(type, "GetQuantusValue")) {
        return GetQuantusValue;
    }
    return NULL;
}

UREncodeResult *GuiGetQuantusSignQrCodeData(void)
{
    bool enable = IsPreviousLockScreenEnable();
    SetLockScreen(false);
    UREncodeResult *encodeResult = NULL;
    void *data = g_isMulti ? g_urMultiResult->data : g_urResult->data;
    
    do {
        uint8_t seed[64];
        int len = GetMnemonicType() == MNEMONIC_TYPE_BIP39 ? sizeof(seed) : GetCurrentAccountEntropyLen();
        GetAccountSeed(GetCurrentAccountIndex(), seed, SecretCacheGetPassword());
        
        uint8_t mfp[4];
        GetMasterFingerPrint(mfp);
        
        encodeResult = quantus_sign_tx(data, seed, len, mfp, sizeof(mfp));
        
        ClearSecretCache();
        CHECK_CHAIN_BREAK(encodeResult);
    } while (0);
    
    SetLockScreen(enable);
    return encodeResult;
}

void FreeQuantusMemory(void)
{
    CHECK_FREE_UR_RESULT(g_urResult, false);
    CHECK_FREE_UR_RESULT(g_urMultiResult, true);
    CHECK_FREE_PARSE_RESULT(g_parseResult);
    g_quantusData = NULL;
}
