#ifdef WEB3_VERSION
#include "gui_quantus.h"
#include "gui_analyze.h"
#include "gui_api.h"
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
#include "fetch_sensitive_data_task.h"
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

// Async checkphrase state for the transaction-signing screen. The screen is rendered with empty
// checkphrase placeholders, then background jobs fill them in and emit SIG_QUANTUS_TX_CHECKPHRASE_READY.
// Keep only the five most recently registered transaction checkphrases. New registrations evict
// the oldest cached entry before background dispatch begins.
#define QUANTUS_TX_CHECKPHRASE_CACHE_SIZE 5
// At most this many checkphrase jobs are queued on the sensitive-data task at once; each
// completed job dispatches the next pending one (audit M-1). Too many simultaneous jobs
// would exhaust the device.
#define QUANTUS_TX_CHECKPHRASE_MAX_IN_FLIGHT 2
// Quantus addresses are SS58 (prefix 189): 36 payload bytes -> ~51 base58 chars, so 64 is ample.
// Keeping this well under the generic ADDRESS_MAX_LEN (256) saves 960 bytes across five slots.
#define QUANTUS_ADDRESS_MAX_LEN 64
typedef struct {
    char address[QUANTUS_ADDRESS_MAX_LEN];
    uint32_t labelIndex;
    uint32_t session;
} QuantusTxCheckphraseJobCtx_t;

static lv_obj_t *g_quantusTxCheckphraseLabels[QUANTUS_TX_CHECKPHRASE_CACHE_SIZE];
static char g_quantusTxCheckphraseAddrs[QUANTUS_TX_CHECKPHRASE_CACHE_SIZE][QUANTUS_ADDRESS_MAX_LEN];
static uint32_t g_quantusTxCheckphraseCacheCount = 0;
static uint32_t g_quantusTxCheckphraseFifoHead = 0;
static uint32_t g_quantusTxCheckphraseNextDispatch = 0;
static uint32_t g_quantusTxCheckphraseJobsInFlight = 0;
static uint32_t g_quantusTxCheckphraseSession = 0;

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
    g_quantusTxCheckphraseCacheCount = 0;
    g_quantusTxCheckphraseFifoHead = 0;
    g_quantusTxCheckphraseNextDispatch = 0;
    g_quantusTxCheckphraseJobsInFlight = 0;
    g_quantusTxCheckphraseSession++;
    void *data = g_isMulti ? g_urMultiResult->data : g_urResult->data;
    
    printf("Quantus: Calling quantus_parse_tx_light with data pointer: %p\r\n", data);

    PtrT_TransactionParseResult_DisplayQuantusTx result = quantus_parse_tx_light(data);
    if (result == NULL) {
        // Defensive: the FFI contract never returns NULL, but guard so an allocation failure
        // surfaces as "no data" instead of a NULL dereference below (audit L-4).
        printf("Quantus: quantus_parse_tx_light returned NULL\r\n");
        return NULL;
    }
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

// Payload delivered by SIG_QUANTUS_TX_CHECKPHRASE_READY. Carrying the phrase and label index in
// the signal avoids a race where a later background job overwrites globals before the UI thread
// processes an earlier signal. The session rebinds the result to the transaction that requested
// it: a job can pass the emit-time session check and still be handled after a newer transaction
// reused the same label slot, so the consumer revalidates (audit H-4).
typedef struct {
    uint32_t labelIndex;
    uint32_t session;
    char phrase[96];
} QuantusTxCheckphraseReady_t;

static int32_t QuantusTxCheckphraseBgFunc(const void *inData, uint32_t inDataLen);

// Register a placeholder label and the address whose checkphrase will fill it.
static bool QuantusTxCheckphraseRegister(lv_obj_t *label, const char *address)
{
    if (label == NULL || address == NULL || address[0] == '\0') {
        printf("ERROR: Quantus transaction checkphrase registration has invalid input\r\n");
        return false;
    }
    if (g_quantusTxCheckphraseNextDispatch != 0 || g_quantusTxCheckphraseJobsInFlight != 0) {
        printf("ERROR: Quantus transaction checkphrase registered after dispatch started\r\n");
        return false;
    }

    uint32_t idx;
    if (g_quantusTxCheckphraseCacheCount < QUANTUS_TX_CHECKPHRASE_CACHE_SIZE) {
        idx = (g_quantusTxCheckphraseFifoHead + g_quantusTxCheckphraseCacheCount) %
              QUANTUS_TX_CHECKPHRASE_CACHE_SIZE;
        g_quantusTxCheckphraseCacheCount++;
    } else {
        idx = g_quantusTxCheckphraseFifoHead;
        g_quantusTxCheckphraseFifoHead =
            (g_quantusTxCheckphraseFifoHead + 1) % QUANTUS_TX_CHECKPHRASE_CACHE_SIZE;
        printf("Quantus: evicting oldest transaction checkphrase cache entry (slot=%u)\r\n", idx);
    }
    g_quantusTxCheckphraseLabels[idx] = label;
    strcpy_s(g_quantusTxCheckphraseAddrs[idx], sizeof(g_quantusTxCheckphraseAddrs[idx]), address);
    return true;
}

// Queue pending checkphrase jobs, at most QUANTUS_TX_CHECKPHRASE_MAX_IN_FLIGHT at a time.
// Called by the UI thread after registering labels and by the background task when a job
// completes, which sequences the remaining jobs one after another (audit M-1).
static void QuantusTxCheckphraseDispatchNext(void)
{
    while (g_quantusTxCheckphraseJobsInFlight < QUANTUS_TX_CHECKPHRASE_MAX_IN_FLIGHT &&
            g_quantusTxCheckphraseNextDispatch < g_quantusTxCheckphraseCacheCount) {
        uint32_t idx = (g_quantusTxCheckphraseFifoHead + g_quantusTxCheckphraseNextDispatch) %
                       QUANTUS_TX_CHECKPHRASE_CACHE_SIZE;
        QuantusTxCheckphraseJobCtx_t ctx;
        strcpy_s(ctx.address, sizeof(ctx.address), g_quantusTxCheckphraseAddrs[idx]);
        ctx.labelIndex = idx;
        ctx.session = g_quantusTxCheckphraseSession;
        g_quantusTxCheckphraseJobsInFlight++;
        g_quantusTxCheckphraseNextDispatch++;
        if (AsyncExecute(QuantusTxCheckphraseBgFunc, &ctx, sizeof(ctx)) != SUCCESS_CODE) {
            // Queue full: the slot stays empty and the job is counted as done (audit M-3).
            printf("ERROR: Quantus checkphrase job dispatch failed (idx=%u)\r\n", idx);
            g_quantusTxCheckphraseJobsInFlight--;
        }
    }
}

// Runs on the background task. Computes one checkphrase and emits SIG_QUANTUS_TX_CHECKPHRASE_READY
// when done. The label index and session are carried in the job context so stale results from a
// previous transaction are ignored.
static int32_t QuantusTxCheckphraseBgFunc(const void *inData, uint32_t inDataLen)
{
    printf("Quantus: QuantusTxCheckphraseBgFunc started\r\n");
    (void)inDataLen;
    const QuantusTxCheckphraseJobCtx_t *ctx = (const QuantusTxCheckphraseJobCtx_t *)inData;
    SimpleResponse_c_char *phrase = quantus_get_checkphrase((char *)ctx->address);
    bool ok = (phrase && phrase->error_code == 0 && phrase->data);
    QuantusTxCheckphraseReady_t ready = {0};
    ready.labelIndex = ctx->labelIndex;
    ready.session = ctx->session;
    if (ok && phrase->data) {
        strcpy_s(ready.phrase, sizeof(ready.phrase), phrase->data);
    }
    if (phrase) {
        free_simple_response_c_char(phrase);
    }
    // Only emit a signal for the current transaction session; old jobs from a replaced transaction
    // are silently dropped.
    if (ctx->session == g_quantusTxCheckphraseSession) {
        printf("Quantus: emitting SIG_QUANTUS_TX_CHECKPHRASE_READY idx=%u phrase='%s'\r\n", ready.labelIndex, ready.phrase);
        GuiApiEmitSignal(SIG_QUANTUS_TX_CHECKPHRASE_READY, &ready, sizeof(ready));
        if (g_quantusTxCheckphraseJobsInFlight > 0) {
            g_quantusTxCheckphraseJobsInFlight--;
        }
        QuantusTxCheckphraseDispatchNext();
    } else {
        // Stale job: the counters were reset with the new session, so leave them alone.
        printf("Quantus: dropping stale checkphrase signal (session mismatch)\r\n");
    }
    return SUCCESS_CODE;
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

void GetQuantusToCheckphrase(void *indata, void *param, uint32_t maxLen)
{
    if (g_quantusData && g_quantusData->to_checkphrase) {
         strcpy_s((char *)indata, maxLen, g_quantusData->to_checkphrase);
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
    } else if (!strcmp(type, "GetQuantusToCheckphrase")) {
        return GetQuantusToCheckphrase;
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

// Custom container that replaces the transfer-screen checkphrase label. It creates an empty label
// placeholder and kicks off a background job to compute the real checkphrase.
void GuiQuantusCheckphraseContainer(lv_obj_t *parent, void *totalData)
{
    printf("Quantus: GuiQuantusCheckphraseContainer called\r\n");
    (void)totalData;
    lv_obj_set_size(parent, 360, LV_SIZE_CONTENT);
    lv_obj_t *label = GuiCreateIllustrateLabel(parent, "");
    lv_obj_set_width(label, 360);
    lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
    lv_obj_set_style_text_color(label, lv_color_hex(0x58E6DA), LV_PART_MAIN);
    lv_obj_align(label, LV_ALIGN_TOP_LEFT, 0, 8);

    if (g_quantusData == NULL || g_quantusData->to == NULL || g_quantusData->to[0] == '\0') {
        return;
    }
    if (QuantusTxCheckphraseRegister(label, g_quantusData->to)) {
        QuantusTxCheckphraseDispatchNext();
    }
}

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
            if (strcmp(labels->data[i], "Checkphrase") == 0 && lastView != NULL && i > 0) {
                uint32_t childCount = lv_obj_get_child_cnt(lastView);
                lv_obj_t *prevChild = lv_obj_get_child(lastView, childCount - 1);
                lv_obj_t *cpLabel = GuiCreateIllustrateLabel(lastView, "");
                lv_obj_set_width(cpLabel, 360);
                lv_label_set_long_mode(cpLabel, LV_LABEL_LONG_WRAP);
                lv_obj_set_style_text_color(cpLabel, lv_color_hex(0x58E6DA), LV_PART_MAIN);
                lv_obj_align_to(cpLabel, prevChild, LV_ALIGN_OUT_BOTTOM_LEFT, 0, 12);
                lv_obj_update_layout(cpLabel);
                lv_obj_set_height(lastView, lv_obj_get_height(lastView) + 12 + lv_obj_get_height(cpLabel));

                QuantusTxCheckphraseRegister(cpLabel, values->data[i - 1]);
                continue;
            }
            lastView = CreateTransactionItemView(parent, labels->data[i], values->data[i], lastView);
        }
        QuantusTxCheckphraseDispatchNext();
    }
}

// Called when a background checkphrase job completes. Updates the matching placeholder label if
// the label is still alive. The phrase and index travel in the signal parameter so concurrent or
// back-to-back jobs cannot overwrite each other's data before the UI thread runs.
void GuiQuantusTxCheckphraseReady(void *param)
{
    printf("Quantus: GuiQuantusTxCheckphraseReady called\r\n");
    if (param == NULL) {
        return;
    }
    const QuantusTxCheckphraseReady_t *ready = (const QuantusTxCheckphraseReady_t *)param;
    if (ready->session != g_quantusTxCheckphraseSession) {
        // The emit-time session check passed but a newer transaction has since taken over
        // the label slots; never render a stale phrase into the current review (audit H-4).
        printf("Quantus: dropping stale checkphrase ready (session %u != %u)\r\n",
               ready->session, g_quantusTxCheckphraseSession);
        return;
    }
    if (ready->labelIndex >= QUANTUS_TX_CHECKPHRASE_CACHE_SIZE) {
        printf("ERROR: Quantus checkphrase ready slot %u out of range\r\n", ready->labelIndex);
        return;
    }
    if (ready->phrase[0] == '\0') {
        printf("ERROR: Quantus async tx checkphrase generation returned empty\n");
        return;
    }
    lv_obj_t *label = g_quantusTxCheckphraseLabels[ready->labelIndex];
    if (label == NULL || !lv_obj_is_valid(label)) {
        printf("Quantus: checkphrase label %u is NULL or invalid\r\n", ready->labelIndex);
        return;
    }
    printf("Quantus: setting checkphrase label %u to '%s'\r\n", ready->labelIndex, ready->phrase);
    lv_label_set_text(label, ready->phrase);
    lv_obj_update_layout(label);

    // The placeholder was created while the label was empty, so a wrapped checkphrase can
    // overflow the parent card once the real text arrives. Grow the parent to fit.
    lv_obj_t *parent = lv_obj_get_parent(label);
    if (parent != NULL) {
        int32_t labelBottom = lv_obj_get_y(label) + lv_obj_get_height(label);
        int32_t parentHeight = lv_obj_get_height(parent);
        if (labelBottom + 16 > parentHeight) {
            lv_obj_set_height(parent, labelBottom + 16);
        }
    }
}

#ifndef COMPILE_SIMULATOR
// ~192 KB PSRAM-backed stack: ML-DSA-87 signing needs ~110 KB, keygen ~50 KB, plus FFI/UR
// framing margin. Sized off the thumbv7em stack-frame measurement (see qp-rusty-crystals
// stack-check.sh); trim once the on-device high-water mark below confirms real usage.
#define QUANTUS_CRYPTO_STACK_BYTES   (1024 * 192)
// Bytes left untouched below the live frame when wiping the stack after a crypto job.
#define QUANTUS_CRYPTO_STACK_WIPE_MARGIN 512

typedef struct {
    QuantusCryptoFunc_t fn;
    void *ctx;
    osSemaphoreId_t done;
} QuantusCryptoJob_t;

static osThreadId_t g_quantusCryptoTask = NULL;
static osMessageQueueId_t g_quantusCryptoQueue = NULL;
static uint8_t *g_quantusCryptoStack = NULL;

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
        // Wipe the deepest-used stack region so ML-DSA key material does not stay resident
        // in PSRAM after the job returns (audit H-3). The stack grows down: the stale bytes
        // lie between the high-water mark and the live frame; a margin below the live frame
        // (whose data is still needed) is left untouched.
        if (g_quantusCryptoStack != NULL) {
            uint8_t *wipeStart = g_quantusCryptoStack + freeWords * sizeof(StackType_t);
            uint8_t *wipeEnd = (uint8_t *)((uintptr_t)&job - QUANTUS_CRYPTO_STACK_WIPE_MARGIN);
            if (wipeEnd > wipeStart) {
                memset_s(wipeStart, wipeEnd - wipeStart, 0, wipeEnd - wipeStart);
            }
        }
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
    g_quantusCryptoStack = ExtMalloc(QUANTUS_CRYPTO_STACK_BYTES);
    const osThreadAttr_t attr = {
        .name = "QuantusCrypto",
        .cb_mem = tcb,
        .cb_size = sizeof(StaticTask_t),
        .stack_mem = g_quantusCryptoStack,
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
    // Copy the cached password before use: the global pointer can be freed by
    // ClearSecretCache() on another task while GetAccountEntropy is still reading it
    // (audit M-2). The local copy is zeroized on every exit path.
    char password[PASSWORD_MAX_LEN] = {0};
    const char *cachedPassword = SecretCacheGetPassword();
    if (cachedPassword != NULL) {
        strcpy_s(password, sizeof(password), cachedPassword);
    }
    uint8_t entropy[ENTROPY_MAX_LEN];
    uint8_t entropyLen = 0;
    char *mnemonic = NULL;
    int32_t ret = GetAccountEntropy(GetCurrentAccountIndex(), entropy, &entropyLen,
                                    cachedPassword != NULL ? password : NULL);
    memset_s(password, sizeof(password), 0, sizeof(password));
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
            // Wipe the cached PIN/passphrase even on this early-out, so a failed signing
            // attempt never leaves secrets resident in the cache (audit L-1).
            ClearSecretCache();
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
    g_quantusTxCheckphraseCacheCount = 0;
    g_quantusTxCheckphraseFifoHead = 0;
    g_quantusTxCheckphraseNextDispatch = 0;
    g_quantusTxCheckphraseJobsInFlight = 0;
    // Invalidate in-flight checkphrase jobs so a stale result is never rendered into the
    // next screen that reuses these label slots.
    g_quantusTxCheckphraseSession++;
}
#endif
