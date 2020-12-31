/*!
 * @brief Managing the interface with pppd
 *
 * @file sstp-pppd.h
 *
 * @author Copyright (C) 2011 Eivind Naess, 
 *      All Rights Reserved
 *
 * @par License:
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef __SSTP_PPPD_H__
#define __SSTP_PPPD_H__


struct sstp_pppd;
typedef struct sstp_pppd sstp_pppd_st;


/*!
 * @brief Start the PPP negotiations
 */
status_t sstp_pppd_start(sstp_pppd_st *ctx, sstp_event_st *event, 
        sstp_option_st *opts);


/*!
 * @brief Forward data back to the pppd daemon from server
 */
status_t sstp_pppd_send(sstp_pppd_st *ctx, const char *buf, int len);


/*!
 * @brief Create the pppd context
 */
status_t sstp_pppd_create(sstp_pppd_st **ctx, sstp_stream_st *stream);


/*!
 * @brief Free the pppd context
 */
void sstp_pppd_free(sstp_pppd_st *ctx);


#endif /* #ifndef __SSTP_SSL_H__ */
