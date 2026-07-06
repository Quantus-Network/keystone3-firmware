#include "gui_fullscreen_mode.h"
#include "screen_manager.h"

static lv_obj_t *fullscreen_container = NULL;
static lv_obj_t *fullscreen_object = NULL;
static bool g_lockSuppressed = false;

static void RestoreSuppressedLock(void)
{
    // Only undo a suppression this component itself made, so an owning screen that manages
    // auto-lock (e.g. the signed-tx QR with its bounded grace) is never overridden with a
    // stale state (audit M-3 follow-up).
    if (g_lockSuppressed) {
        SetPageLockScreen(true);
        g_lockSuppressed = false;
    }
}

void GuiFullscreenModeHandler(lv_event_t * e)
{
    if (lv_event_get_code(e) == LV_EVENT_CLICKED) {
        GuiFullscreenModeToggle();
    }
}

void GuiFullscreenContainerGenerate(uint16_t width, uint16_t height, lv_color_t bg_color)
{
    fullscreen_container = lv_obj_create(lv_scr_act());
    lv_obj_set_size(fullscreen_container, width, height);
    lv_obj_set_style_bg_color(fullscreen_container, bg_color, LV_PART_MAIN);
    lv_obj_add_flag(fullscreen_container, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(fullscreen_container, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(fullscreen_container, GuiFullscreenModeHandler, LV_EVENT_CLICKED, NULL);
}

void GuiFullscreenModeInit(uint16_t width, uint16_t height, lv_color_t bg_color)
{
    GuiFullscreenContainerGenerate(width, height, bg_color);
}

lv_obj_t *GuiFullscreenModeCreateObject(lv_obj_t* (*create_object_func)(lv_obj_t*, uint16_t, uint16_t), uint16_t w, uint16_t h)
{
    GUI_DEL_OBJ(fullscreen_object);
    fullscreen_object = create_object_func(fullscreen_container, w, h);
    lv_obj_align(fullscreen_object, LV_ALIGN_CENTER, 0, 0);

    return fullscreen_object;
}

void GuiEnterFullscreenMode()
{
    // Keep the device awake while the enlarged QR is being scanned, but only for a bounded
    // grace period. If the owning screen already suppressed auto-lock, its policy stays in
    // charge and is left untouched on exit.
    if (IsPageLockScreenEnable()) {
        SuspendPageLockScreen();
        g_lockSuppressed = true;
    }
    lv_obj_clear_flag(fullscreen_container, LV_OBJ_FLAG_HIDDEN);
}

void GuiExitFullscreenMode()
{
    RestoreSuppressedLock();
    lv_obj_add_flag(fullscreen_container, LV_OBJ_FLAG_HIDDEN);
}

void GuiFullscreenModeToggle()
{
    if (lv_obj_has_flag(fullscreen_container, LV_OBJ_FLAG_HIDDEN)) {
        GuiEnterFullscreenMode();
    } else {
        GuiExitFullscreenMode();
    }
}

void GuiFullscreenModeCleanUp()
{
    GUI_DEL_OBJ(fullscreen_object);
    GUI_DEL_OBJ(fullscreen_container);
    RestoreSuppressedLock();
}

lv_obj_t *GuiFullscreenModeGetCreatedObject()
{
    return fullscreen_object;
}

lv_obj_t* GuiFullscreenModeGetCreatedObjectWhenVisible(void)
{
    if (!lv_obj_has_flag(fullscreen_object, LV_OBJ_FLAG_HIDDEN)) {
        return fullscreen_object;
    }
    return NULL;
}