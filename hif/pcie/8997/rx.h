/*
 * Copyright (C) 2006-2018, Marvell International Ltd.
 *
 * This software file (the "File") is distributed by Marvell International
 * Ltd. under the terms of the GNU General Public License Version 2, June 1991
 * (the "License").  You may use, redistribute and/or modify this File in
 * accordance with the terms and conditions of the License, a copy of which
 * is available by writing to the Free Software Foundation, Inc.
 *
 * THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE
 * ARE EXPRESSLY DISCLAIMED.  The License provides additional details about
 * this warranty disclaimer.
 */

/* Description:  This file defines receive related functions. */

#ifndef _8997_RX_H_
#define _8997_RX_H_

int pcie_8997_rx_init(struct ieee80211_hw *hw);
void pcie_8997_rx_deinit(struct ieee80211_hw *hw);
int pcie_8997_poll_napi(struct napi_struct *napi, int budget);

#endif /* _8997_RX_H_ */
