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
#include "stdio.h"

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
    printf("Quantus: GuiSetQuantusUrData called (multi=%d)\r\n", multi ? 1 : 0);
    g_urResult = urResult;
    g_urMultiResult = urMultiResult;
    g_isMulti = multi;
    if (urResult) {
        printf("Quantus: UR result type: %d\r\n", urResult->t);
    }
}

void *GuiGetQuantusData(void)
{
    printf("Quantus: GuiGetQuantusData called\r\n");
    CHECK_FREE_PARSE_RESULT(g_parseResult);
    void *data = g_isMulti ? g_urMultiResult->data : g_urResult->data;
    
    printf("Quantus: Calling quantus_parse_tx with data pointer: %p\r\n", data);
    
    PtrT_TransactionParseResult_DisplayQuantusTx result = quantus_parse_tx(data);
    if (result->error_code != 0) {
        printf("Quantus: Parse failed with error_code: %d\r\n", result->error_code);
        if (result->error_message) {
            printf("Quantus: Error message: %s\r\n", result->error_message);
        }
        return NULL; 
    }
    g_parseResult = (void *)result;
    g_quantusData = (DisplayQuantusTx *)result->data;
    
    if (g_quantusData) {
        printf("Quantus: Parse successful, displaying transaction:\r\n");
        printf("Quantus:   To: %s\r\n", g_quantusData->to ? g_quantusData->to : "(null)");
        printf("Quantus:   Amount: %s\r\n", g_quantusData->amount ? g_quantusData->amount : "(null)");
        printf("Quantus:   Fee: %s\r\n", g_quantusData->fee ? g_quantusData->fee : "(null)");
        printf("Quantus:   Nonce: %s\r\n", g_quantusData->nonce ? g_quantusData->nonce : "(null)");
    } else {
        printf("Quantus: Warning: g_quantusData is NULL after parse\r\n");
    }
    
    return g_parseResult;
}

PtrT_TransactionCheckResult GuiGetQuantusCheckResult(void)
{
    void *data = g_isMulti ? g_urMultiResult->data : g_urResult->data;
    uint8_t mfp[4];
    GetMasterFingerPrint(mfp);
    return quantus_check_tx(data, mfp, 4);
}


void GetQuantusValue(void *indata, void *param, uint32_t maxLen)
{
    if (g_quantusData) {
         snprintf_s((char *)indata, maxLen, "%s QTS", g_quantusData->amount ? g_quantusData->amount : "0");
    } else {
         snprintf_s((char *)indata, maxLen, "Quantus Transaction");
    }
}

void GetQuantusFee(void *indata, void *param, uint32_t maxLen)
{
    if (g_quantusData && g_quantusData->fee) {
         snprintf_s((char *)indata, maxLen, "%s QTS", g_quantusData->fee);
    } else {
         snprintf_s((char *)indata, maxLen, "0 QTS");
    }
}

void GetQuantusToAddress(void *indata, void *param, uint32_t maxLen)
{
    if (g_quantusData && g_quantusData->to) {
         strcpy_s((char *)indata, maxLen, g_quantusData->to);
    } else {
         strcpy_s((char *)indata, maxLen, "");
    }
}

void GetQuantusFromAddress(void *indata, void *param, uint32_t maxLen)
{
    // Quantus doesn't have from address in current data structure
    strcpy_s((char *)indata, maxLen, "Quantus Account");
}

void GetQuantusNonce(void *indata, void *param, uint32_t maxLen)
{
    if (g_quantusData && g_quantusData->nonce) {
         strcpy_s((char *)indata, maxLen, g_quantusData->nonce);
    } else {
         strcpy_s((char *)indata, maxLen, "0");
    }
}

void GetQuantusNetwork(void *indata, void *param, uint32_t maxLen)
{
    strcpy_s((char *)indata, maxLen, "Quantus Network");
}

GetLabelDataFunc GuiQuantusTextFuncGet(char *type)
{
    if (!strcmp(type, "GetQuantusValue")) {
        return GetQuantusValue;
    } else if (!strcmp(type, "GetQuantusFee")) {
        return GetQuantusFee;
    } else if (!strcmp(type, "GetQuantusToAddress")) {
        return GetQuantusToAddress;
    } else if (!strcmp(type, "GetQuantusFromAddress")) {
        return GetQuantusFromAddress;
    } else if (!strcmp(type, "GetQuantusNonce")) {
        return GetQuantusNonce;
    } else if (!strcmp(type, "GetQuantusNetwork")) {
        return GetQuantusNetwork;
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
