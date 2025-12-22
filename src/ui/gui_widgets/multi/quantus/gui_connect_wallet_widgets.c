#ifdef QUANTUS_VERSION
#include "gui_connect_wallet_widgets.h"
#include "gui.h"
#include "gui_views.h"
#include "gui_page.h"

// Minimal stub implementation for quantus
// Quantus doesn't support connect wallet functionality

void GuiConnectWalletInit(void)
{
    // Stub - no-op for quantus
}

int8_t GuiConnectWalletNextTile(void)
{
    return 0;
}

int8_t GuiConnectWalletPrevTile(void)
{
    return 0;
}

void GuiConnectWalletRefresh(void)
{
    // Stub - no-op for quantus
}

void GuiConnectWalletDeInit(void)
{
    // Stub - no-op for quantus
}

void GuiConnectWalletSetQrdata(WALLET_LIST_INDEX_ENUM index)
{
    // Stub - no-op for quantus
}

void GuiConnectWalletHandleURGenerate(char *data, uint16_t len)
{
    // Stub - no-op for quantus
}

void GuiConnectWalletHandleURUpdate(char *data, uint16_t len)
{
    // Stub - no-op for quantus
}

uint8_t GuiConnectWalletGetWalletIndex(void)
{
    return 0;
}
#endif

