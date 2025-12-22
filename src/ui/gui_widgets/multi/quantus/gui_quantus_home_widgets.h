#ifdef QUANTUS_VERSION
#ifndef _GUI_QUANTUS_HOME_WIDGETS_H
#define _GUI_QUANTUS_HOME_WIDGETS_H

#define HOME_WIDGETS_SURPLUS_CARD_ENUM     HOME_WALLET_CARD_QUANTUS

#define HOME_WALLET_STATE_SURPLUS          {HOME_WALLET_CARD_QUANTUS, true, "QUAN", true}

#define HOME_WALLET_CARD_SURPLUS           { \
        .index = HOME_WALLET_CARD_QUANTUS, \
        .coin = "QUAN", \
        .chain = "Quantus", \
        .icon = &coinQuantus, \
    }

#endif
#endif

