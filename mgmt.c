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

/* Description:  This file implements core layer related functions. */

#include <linux/etherdevice.h>
#include <linux/ieee80211.h>
#include <linux/ctype.h>

#include "sysadpt.h"
#include "mgmt.h"
#include "core.h"
#include "utils.h"
#include "mac80211.h"

void mgmt_beaconing(struct work_struct *work)
{
	struct mwl_priv *priv =
		container_of(work, struct mwl_priv, beaconing.work);
	struct ieee80211_hw *hw = priv->hw;
	struct mwl_vif *mwl_vif;
	struct ieee80211_vif *vif;
	struct sk_buff *skb;
	unsigned long  nexttbtt = -1;
	u8 counter = 0;

	if(unlikely(!priv->beaconing_started))
		return;


	spin_lock_bh(&priv->vif_lock);
	list_for_each_entry(mwl_vif, &priv->vif_list, list) {
		vif = container_of((void *)mwl_vif, struct ieee80211_vif,
				   drv_priv);

		vif = mwl_vif->vif;

		if (vif->type == NL80211_IFTYPE_STATION ||
		    vif->type == NL80211_IFTYPE_MONITOR)
			continue;


		/* refresh the beacon for AP or MESH mode */
		if (mwl_vif->nexttbtt <= jiffies && (
		    vif->type == NL80211_IFTYPE_AP ||
		    vif->type == NL80211_IFTYPE_MESH_POINT)) {
			skb = ieee80211_beacon_get(hw, vif);

			if (!skb)
				break;

			// mwl_vif->tx_seq_no = utils_tx_h_seq_no(skb, mwl_vif->tx_seq_no);
			/* TODO:
			* calcul tim => ath10k_wmi_update_tim(ar, arvif, bcn, tim_info);
			* calcul noa => ath10k_wmi_update_noa(ar, arvif, bcn, noa_info);
			*/

			mwl_mac80211_tx(hw, NULL, skb);

			mwl_vif->nexttbtt += usecs_to_jiffies(mwl_vif->bintval);
		}

		if(nexttbtt == -1)
			nexttbtt = mwl_vif->nexttbtt;

		nexttbtt = mwl_vif->nexttbtt < nexttbtt ? mwl_vif->nexttbtt : nexttbtt;

		while((long int) (nexttbtt - jiffies) < 0) {
			mwl_vif->nexttbtt += usecs_to_jiffies(mwl_vif->bintval);
			nexttbtt += usecs_to_jiffies(mwl_vif->bintval);
		}
		skb = ieee80211_get_buffered_bc(hw, vif);
		while (skb && counter++) {
			mwl_mac80211_tx(hw, NULL, skb);
			if(counter < SYSADPT_MAX_BC_BUFFER)
				break;
			skb = ieee80211_get_buffered_bc(hw, vif);
		}
	}
	priv->nexttbtt = nexttbtt;
	if((long int) nexttbtt - jiffies < 0)
		wiphy_warn(priv->hw->wiphy, "IEEE 802.11 jiffies = %lu, nexttbtt = %lu, remaining = %ld < 0!\n", jiffies, nexttbtt, (long int) nexttbtt - jiffies);

	ieee80211_queue_delayed_work(hw, &priv->beaconing, nexttbtt - jiffies);

	spin_unlock_bh(&priv->vif_lock);

}