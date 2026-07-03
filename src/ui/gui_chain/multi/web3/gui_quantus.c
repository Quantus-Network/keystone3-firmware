#ifdef WEB3_VERSION
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
#ifndef COMPILE_SIMULATOR
#include "cmsis_os.h"
#include "FreeRTOS.h"
#include "task.h"
#include "user_memory.h"
#include "assert.h"
#endif

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
    // g_quantusData aliased into the result freed above; clear it so a parse failure below
    // cannot leave the display getters reading freed memory (audit M-4).
    g_quantusData = NULL;
    void *data = g_isMulti ? g_urMultiResult->data : g_urResult->data;
    
    printf("Quantus: Calling quantus_parse_tx with data pointer: %p\r\n", data);
    
    PtrT_TransactionParseResult_DisplayQuantusTx result = quantus_parse_tx(data);
    if (result->error_code != 0) {
        printf("Quantus: Parse failed with error_code: %d\r\n", result->error_code);
        if (result->error_message) {
            printf("Quantus: Error message: %s\r\n", result->error_message);
        }
        free_TransactionParseResult_DisplayQuantusTx(result);
        return NULL; 
    }
    g_parseResult = (void *)result;
    g_quantusData = (DisplayQuantusTx *)result->data;
    
    if (g_quantusData) {
        printf("Quantus: Parse successful, displaying transaction:\r\n");
        printf("Quantus:   To: %s\r\n", g_quantusData->to ? g_quantusData->to : "(null)");
        printf("Quantus:   Amount: %s\r\n", g_quantusData->amount ? g_quantusData->amount : "(null)");
        printf("Quantus:   Tip: %s\r\n", g_quantusData->tip ? g_quantusData->tip : "(null)");
        printf("Quantus:   Nonce: %s\r\n", g_quantusData->nonce ? g_quantusData->nonce : "(null)");
        printf("Quantus:   Network: %s\r\n", g_quantusData->network ? g_quantusData->network : "(null)");
        printf("Quantus:   Era: %s\r\n", g_quantusData->era ? g_quantusData->era : "(null)");
        printf("Quantus:   Reversible: %s\r\n", g_quantusData->is_reversible ? "true" : "false");
        printf("Quantus:   Timeframe: %s\r\n", g_quantusData->reversible_timeframe ? g_quantusData->reversible_timeframe : "(null)");
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
         snprintf_s((char *)indata, maxLen, "%s QUAN", g_quantusData->amount ? g_quantusData->amount : "0");
    } else {
         snprintf_s((char *)indata, maxLen, "Quantus Transaction");
    }
}

void GetQuantusTip(void *indata, void *param, uint32_t maxLen)
{
    if (g_quantusData && g_quantusData->tip) {
         snprintf_s((char *)indata, maxLen, "%s QUAN", g_quantusData->tip);
    } else {
         snprintf_s((char *)indata, maxLen, "unknown");
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

void GetQuantusEra(void *indata, void *param, uint32_t maxLen)
{
    if (g_quantusData && g_quantusData->era) {
        strcpy_s((char *)indata, maxLen, g_quantusData->era);
    } else {
        strcpy_s((char *)indata, maxLen, "unknown");
    }
}

void GetQuantusNonce(void *indata, void *param, uint32_t maxLen)
{
    if (g_quantusData && g_quantusData->nonce) {
         strcpy_s((char *)indata, maxLen, g_quantusData->nonce);
    } else {
         strcpy_s((char *)indata, maxLen, "0");
    }
}

void GetQuantusReversibleTimeframe(void *indata, void *param, uint32_t maxLen)
{
    if (g_quantusData && g_quantusData->is_reversible && g_quantusData->reversible_timeframe) {
         snprintf_s((char *)indata, maxLen, "%s", g_quantusData->reversible_timeframe);
    } else {
         snprintf_s((char *)indata, maxLen, "");
    }
}

void GetQuantusIsReversible(void *indata, void *param, uint32_t maxLen)
{
    if (g_quantusData && g_quantusData->is_reversible) {
        strcpy_s((char *)indata, maxLen, "true");
    } else {
        strcpy_s((char *)indata, maxLen, "false");
    }
}

void GetQuantusNetwork(void *indata, void *param, uint32_t maxLen)
{
    if (g_quantusData && g_quantusData->network) {
        strcpy_s((char *)indata, maxLen, g_quantusData->network);
    } else {
        strcpy_s((char *)indata, maxLen, "unknown");
    }
}

GetLabelDataFunc GuiQuantusTextFuncGet(char *type)
{
    if (!strcmp(type, "GetQuantusValue")) {
        return GetQuantusValue;
    } else if (!strcmp(type, "GetQuantusTip")) {
        return GetQuantusTip;
    } else if (!strcmp(type, "GetQuantusToAddress")) {
        return GetQuantusToAddress;
    } else if (!strcmp(type, "GetQuantusEra")) {
        return GetQuantusEra;
    } else if (!strcmp(type, "GetQuantusNonce")) {
        return GetQuantusNonce;
    } else if (!strcmp(type, "GetQuantusReversibleTimeframe")) {
        return GetQuantusReversibleTimeframe;
    } else if (!strcmp(type, "GetQuantusIsReversible")) {
        return GetQuantusIsReversible;
    } else if (!strcmp(type, "GetQuantusNetwork")) {
        return GetQuantusNetwork;
    }
    return NULL;
}

// Plain transfers keep the curated card template; every other call type (multisig) renders through
// GuiQuantusMultisigDetails instead. These gate the two layouts via the template "exist_func".
bool GetQuantusIsTransfer(void *indata, void *param)
{
    DisplayQuantusTx *tx = (DisplayQuantusTx *)param;
    return tx != NULL && !tx->is_multisig;
}

bool GetQuantusIsMultisig(void *indata, void *param)
{
    DisplayQuantusTx *tx = (DisplayQuantusTx *)param;
    return tx != NULL && tx->is_multisig;
}

// Generic per-type view: a "Type" title followed by the ordered (label, value) rows the parser
// produced. Used for multisig create/propose/approve/execute (display only, never blind-signed).
void GuiQuantusMultisigDetails(lv_obj_t *parent, void *totalData)
{
    DisplayQuantusTx *tx = (DisplayQuantusTx *)totalData;
    lv_obj_set_size(parent, 408, 514);
    lv_obj_add_flag(parent, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(parent, LV_OBJ_FLAG_CLICKABLE);

    lv_obj_t *lastView = NULL;
    if (tx->tx_type != NULL) {
        lastView = CreateTransactionItemView(parent, "Type", tx->tx_type, lastView);
    }

    PtrT_VecFFI_PtrString labels = tx->detail_labels;
    PtrT_VecFFI_PtrString values = tx->detail_values;
    if (labels != NULL && values != NULL) {
        uint32_t count = labels->size < values->size ? labels->size : values->size;
        for (uint32_t i = 0; i < count; i++) {
            lastView = CreateTransactionItemView(parent, labels->data[i], values->data[i], lastView);
        }
    }
}

#ifndef COMPILE_SIMULATOR
// ~192 KB PSRAM-backed stack: ML-DSA-87 signing needs ~110 KB, keygen ~50 KB, plus FFI/UR
// framing margin. Sized off the thumbv7em stack-frame measurement (see qp-rusty-crystals
// stack-check.sh); trim once the on-device high-water mark below confirms real usage.
#define QUANTUS_CRYPTO_STACK_BYTES   (1024 * 192)

typedef struct {
    QuantusCryptoFunc_t fn;
    void *ctx;
    osSemaphoreId_t done;
} QuantusCryptoJob_t;

static osThreadId_t g_quantusCryptoTask = NULL;
static osMessageQueueId_t g_quantusCryptoQueue = NULL;

static void QuantusCryptoThread(void *arg)
{
    (void)arg;
    QuantusCryptoJob_t job;
    while (1) {
        if (osMessageQueueGet(g_quantusCryptoQueue, &job, NULL, osWaitForever) != osOK) {
            continue;
        }
        if (job.fn) {
            job.fn(job.ctx);
        }
        UBaseType_t freeWords = uxTaskGetStackHighWaterMark(NULL);
        printf("Quantus crypto stack high-water: %lu/%d bytes used\r\n",
               (unsigned long)(QUANTUS_CRYPTO_STACK_BYTES - freeWords * sizeof(StackType_t)),
               QUANTUS_CRYPTO_STACK_BYTES);
        if (job.done) {
            osSemaphoreRelease(job.done);
        }
    }
}

static void QuantusCryptoTaskEnsure(void)
{
    if (g_quantusCryptoTask != NULL) {
        return;
    }
    g_quantusCryptoQueue = osMessageQueueNew(2, sizeof(QuantusCryptoJob_t), NULL);
    StaticTask_t *tcb = (StaticTask_t *)SRAM_MALLOC(sizeof(StaticTask_t));
    void *stack = ExtMalloc(QUANTUS_CRYPTO_STACK_BYTES);
    const osThreadAttr_t attr = {
        .name = "QuantusCrypto",
        .cb_mem = tcb,
        .cb_size = sizeof(StaticTask_t),
        .stack_mem = stack,
        .stack_size = QUANTUS_CRYPTO_STACK_BYTES,
        .priority = osPriorityBelowNormal,
    };
    g_quantusCryptoTask = osThreadNew(QuantusCryptoThread, NULL, &attr);
    ASSERT(g_quantusCryptoTask != NULL);
}
#endif

void QuantusRunCrypto(QuantusCryptoFunc_t fn, void *ctx)
{
#ifdef COMPILE_SIMULATOR
    if (fn) {
        fn(ctx);
    }
#else
    QuantusCryptoTaskEnsure();
    osSemaphoreId_t done = osSemaphoreNew(1, 0, NULL);
    QuantusCryptoJob_t job = { .fn = fn, .ctx = ctx, .done = done };
    osMessageQueuePut(g_quantusCryptoQueue, &job, 0, osWaitForever);
    osSemaphoreAcquire(done, osWaitForever);
    osSemaphoreDelete(done);
#endif
}

typedef struct {
    void *data;
    char *mnemonic;
    char *passphrase;
    char *path;
    uint8_t *mfp;
    uint32_t mfpLen;
    UREncodeResult *result;
} QuantusSignJobCtx;

static void QuantusSignJob(void *p)
{
    QuantusSignJobCtx *c = (QuantusSignJobCtx *)p;
    c->result = quantus_sign_tx(c->data, c->mnemonic, c->passphrase, c->path, c->mfp, c->mfpLen);
}

char *QuantusReconstructMnemonic(void)
{
    if (GetMnemonicType() != MNEMONIC_TYPE_BIP39) {
        printf("Quantus: only BIP39 mnemonics are supported\r\n");
        return NULL;
    }
    char *password = SecretCacheGetPassword();
    uint8_t entropy[ENTROPY_MAX_LEN];
    uint8_t entropyLen = 0;
    char *mnemonic = NULL;
    int32_t ret = GetAccountEntropy(GetCurrentAccountIndex(), entropy, &entropyLen, password);
    if (ret != SUCCESS_CODE || entropyLen == 0) {
        printf("Quantus: GetAccountEntropy failed ret=%d entropyLen=%u\r\n", ret, entropyLen);
        memset_s(entropy, sizeof(entropy), 0, sizeof(entropy));
        return NULL;
    }
    if (entropyLen != 16 && entropyLen != 20 && entropyLen != 24 && entropyLen != 28 && entropyLen != 32) {
        printf("Quantus: invalid entropy length %u\r\n", entropyLen);
        memset_s(entropy, sizeof(entropy), 0, sizeof(entropy));
        return NULL;
    }
    ret = bip39_mnemonic_from_bytes(NULL, entropy, entropyLen, &mnemonic);
    memset_s(entropy, sizeof(entropy), 0, sizeof(entropy));
    if (ret != SUCCESS_CODE || mnemonic == NULL) {
        printf("Quantus: bip39_mnemonic_from_bytes failed ret=%d\r\n", ret);
        return NULL;
    }
    return mnemonic;
}

void QuantusWipeAndFreeMnemonic(char *mnemonic)
{
    if (mnemonic == NULL) {
        return;
    }
    size_t len = strlen(mnemonic);
    memset_s(mnemonic, len, 0, len);
    SRAM_FREE(mnemonic);
}

UREncodeResult *GuiGetQuantusSignQrCodeData(void)
{
    bool enable = IsPreviousLockScreenEnable();
    SetLockScreen(false);
    UREncodeResult *encodeResult = NULL;
    void *data = g_isMulti ? g_urMultiResult->data : g_urResult->data;
    
    do {
        char *passphrase = GetPassphrase(GetCurrentAccountIndex());
        char path[BUFFER_SIZE_64];
        snprintf_s(path, sizeof(path), QUANTUS_HD_PATH_FMT, 0);

        char *mnemonic = QuantusReconstructMnemonic();
        if (mnemonic == NULL) {
            break;
        }

        uint8_t mfp[4];
        GetMasterFingerPrint(mfp);

        QuantusSignJobCtx ctx = {
            .data = data, .mnemonic = mnemonic, .passphrase = passphrase,
            .path = path, .mfp = mfp, .mfpLen = sizeof(mfp), .result = NULL,
        };
        QuantusRunCrypto(QuantusSignJob, &ctx);
        encodeResult = ctx.result;
        // Zeroize the mnemonic the moment signing is done.
        QuantusWipeAndFreeMnemonic(mnemonic);
        
        if (encodeResult && encodeResult->error_code == 0) {
            if (encodeResult->is_multi_part) {
                uint32_t fragment_count = get_fragment_count(encodeResult->encoder);
                printf("Quantus: QR code has %u parts\r\n", fragment_count);
            } else {
                printf("Quantus: QR code has 1 part (single)\r\n");
            }
        }
        
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
#endif
