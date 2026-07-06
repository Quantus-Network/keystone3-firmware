#ifndef _SCREEN_MANAGER_H
#define _SCREEN_MANAGER_H

#include "stdint.h"
#include "stdbool.h"
#include "err_code.h"

void ScreenManagerInit(void);
void SetLockScreen(bool enable);
void SetPageLockScreen(bool enable);
// Disable page auto-lock for a bounded grace period; it re-arms itself (and restarts the idle
// countdown) unless SetPageLockScreen is called sooner.
void SuspendPageLockScreen(void);
void SetLockTimeState(bool enable);
bool IsPreviousLockScreenEnable(void);
bool IsPageLockScreenEnable(void);
void ClearLockScreenTime(void);
void SetLockTimeOut(uint32_t timeOut);
void SetLockDeviceAlive(bool alive);

#endif
