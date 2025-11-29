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

// Reuse ETH logic for now since we just want basic functionality
// We can expand this later with custom logic if needed

void GuiSetQuantusUrData(URParseResult *urResult, URParseMultiResult *urMultiResult, bool multi)
{
    // Quantus specific setup if needed
}

void *GuiGetQuantusData(void)
{
    // For now just return something dummy or reuse ETH data
    return NULL;
}

PtrT_TransactionCheckResult GuiGetQuantusCheckResult(void)
{
    // Return valid check result for testing
    return NULL;
}

void GetQuantusValue(void *indata, void *param, uint32_t maxLen)
{
    snprintf((char *)indata, maxLen, "100 QNT");
}

UREncodeResult *GuiGetQuantusSignQrCodeData(void)
{
    // Call Rust C binding
    void *urResult = NULL;
    char *password = SecretCacheGetPassword();
    uint8_t entropy[ENTROPY_MAX_LEN];
    uint8_t entropyLen;
    char *mnemonic = NULL;
    
    int32_t ret = GetAccountEntropy(GetCurrentAccountIndex(), entropy, &entropyLen, password);
    if (ret != SUCCESS_CODE) {
        return NULL;
    }
    
    ret = bip39_mnemonic_from_bytes(NULL, entropy, entropyLen, &mnemonic);
    memset_s(entropy, sizeof(entropy), 0, sizeof(entropy));
    
    if (ret != SUCCESS_CODE || mnemonic == NULL) {
        return NULL;
    }

    char *json_str = "{\"amount\":100,\"to\":\"quantus_address\",\"from\":\"my_address\"}"; // Dummy JSON
    char hdPath[BUFFER_SIZE_128];
    snprintf(hdPath, BUFFER_SIZE_128, "m/44'/189189'/0'/0/0"); // Dummy path for signing

    char *pass = password ? password : "";
    urResult = quantus_sign_tx(json_str, mnemonic, pass, hdPath);
    
    SRAM_FREE(mnemonic);
    
    return (UREncodeResult *)urResult;
}
