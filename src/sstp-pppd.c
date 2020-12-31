/*!
 * @brief Managing the interface with pppd
 *
 * @file sstp-pppd.c
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sstp-private.h"



/*!
 * @brief Context for the PPPd operations
 */
struct sstp_pppd
{
    /*< Task structure */
    sstp_task_st *task;

    /*< A buffer we can receive data with */
    sstp_buff_st *rx_buf;

    /*< A buffer we can send data with */
    sstp_buff_st *tx_buf;

    /*< The SSL stream context */
    sstp_stream_st *stream;

    /*< Listener for retrieving data from pppd */
    event_st recv;

    /*< The socket to pppd */
    int sock;

};


static status_t ppp_process_data(sstp_pppd_st *ctx);


/*!
 * @brief Throttle receive operation, previous send incomplete.
 *
 * @par Function:
 *  If the send operation was blocked, we'll receive a complete event.
 *  1) Continue sending the remainding data in rx-buffer to server
 *  2) If send() blocks again, we'll re-enter at this point
 *  3) When complete, re-add the sstp_pppd_recv event function here.
 */
static void ppp_send_complete(sstp_stream_st *stream, sstp_buff_st *buf,
    sstp_pppd_st *ctx, status_t status)
{
    if (SSTP_OKAY != status)
    {
        log_err("TODO: Handle shutdown here");
    }

    /* Continue processing input */
    status = ppp_process_data(ctx);
    switch (status)
    {
    case SSTP_INPROG:
        /* Will invoke this function again */
        break;

    case SSTP_OKAY:
        /* We had to trottle the recevie operation, re-start */
        event_add(&ctx->recv, NULL);
        break;

    case SSTP_FAIL:
    default:
        log_err("TODO: Handle processing failure");
        break;
    }
}


/*!
 * @brief Process any data in the input buffer and forward them to server
 */
static status_t ppp_process_data(sstp_pppd_st *ctx)
{
    sstp_buff_st *rx = ctx->rx_buf;
    sstp_buff_st *tx = ctx->tx_buf;
    status_t ret = SSTP_FAIL;

    /* Initialize TX-buffer */
    sstp_buff_reset(tx);

    /* Iterate over the frames received */
    while (rx->off < rx->len)
    {
        int max = 0;
        int off = 0;

        /* Initialize send buffer */
        ret = sstp_pkt_init(tx, SSTP_MSG_DATA);
        if (SSTP_OKAY != ret)
        {
            return SSTP_FAIL;
        }

        /* Copy a single frame to the tx-buffer */
        max = tx->max - tx->len;
        off = rx->len - rx->off;
        ret = sstp_frame_decode((unsigned char*) rx->data + rx->off, &off,
            (unsigned char*) tx->data + tx->len, &max);
        if (SSTP_OKAY != ret)
        {
            /* We needed to read more ... */
            if (SSTP_OVERFLOW == ret ||
               (rx->len == (rx->off + off))) // TODO: Why!?!
            {
                /* Move current packet to beginning of buffer */
                memmove(rx->data, rx->data + rx->off, rx->len - rx->off);
                rx->len = off;
                rx->off = 0;

                /* Need more data, re-add read event */
                return SSTP_OKAY;
            }

            /* Checksum Error!, drop this segment */
            rx->off += off;
            continue;
        }

        /* Update length */
        tx->len += max;
        rx->off += off;

        /* Update the final length of the packet */
        sstp_pkt_update(tx);

        /* Send a PPP frame */
        ret = sstp_stream_send(ctx->stream, tx, (sstp_complete_fn) 
                ppp_send_complete, ctx, 1);
        if (SSTP_OKAY != ret)
        {
            return SSTP_INPROG;
        }
    }
    
    /* Start over in an empty buffer */
    if (rx->off == rx->len)
    {
        sstp_buff_reset(rx);
    }

    return SSTP_OKAY;
}


/*!
 * @brief Receive the data from the pppd daemon, forwarding it to the
 *  sstp-server.
 */
static void sstp_pppd_recv(int fd, short event, sstp_pppd_st *ctx)
{
    sstp_buff_st *rx = ctx->rx_buf;
    status_t ret = SSTP_FAIL;

    /* Receive a chunk */
    rx->len += read(fd, rx->data + rx->len, rx->max - rx->len);
    if (rx->len <= 0)
    {
        log_err("PPPd Socket Closed");
        goto done;
    }

    /* Process the input */
    ret = ppp_process_data(ctx);
    switch (ret)
    {
    case SSTP_INPROG:
        /* Let the ppp_send_complete finish it */
        break;

    case SSTP_OKAY:
        /* Re-add the event to receive more */
        event_add(&ctx->recv, NULL);
        break;

    case SSTP_FAIL:
    default:
        log_err("TODO: Handle failure of processing");
        break;
    }

done:

    return;
}


/*!
 * @brief Send data received from the sstp peer back through pppd/pppX
 */
status_t sstp_pppd_send(sstp_pppd_st *ctx, const char *buf, int len)
{
    status_t status = SSTP_FAIL;
    unsigned char *frame = NULL;
    int flen = 0;
    int ret  = 0;

    /* Get the maximum size of the frame */
    flen = (len << 1) + 4;

    /* Allocate some stack space (do not free!) */
    frame = alloca(flen);
    if (!frame)
    {
        goto done;
    }

    /* Perform the HDLC encoding of the frame */
    ret = sstp_frame_encode((const unsigned char*) buf, len, frame, &flen);
    if (SSTP_OKAY != ret)
    {
        log_err("Could not encode frame");
        goto done;
    }

    /* Write the data back to the pppd */
    ret = write(ctx->sock, frame, flen);
    if (ret != flen)
    {
        log_err("Could not complete write of frame");
        goto done;
    }

    /* Success */
    status = SSTP_OKAY;

done:
    
    return status;
}


status_t sstp_pppd_start(sstp_pppd_st *ctx, sstp_event_st *event, 
        sstp_option_st *opts)
{
    status_t status  = SSTP_FAIL;
    status_t ret     = SSTP_FAIL;

    /* Launch PPPd, unless PPPd launched us */
    if (!(SSTP_OPT_NOLAUNCH & opts->enable))
    {
        const char *args[20];
        int i = 0;
        int j = 0;
 
        /* Create the task */
        ret = sstp_task_new(&ctx->task, SSTP_TASK_USEPTY);
        if (SSTP_OKAY != ret)
        {
            log_err("Could not create a new task for pppd");
            goto done;
        }

        /* Configure the command line */
        args[i++] = "/usr/sbin/pppd";
        args[i++] = sstp_task_ttydev(ctx->task);
        args[i++] = "38400";
        args[i++] = "plugin";
        args[i++] = "sstp-pppd-plugin.so";
        args[i++] = "sstp-sock";
        args[i++] = sstp_event_sockname(event);

        /* Copy all the arguments to pppd */
        for (j = 0; j < opts->pppdargc; j++)
        {
            args[i++] = opts->pppdargv[j];
        }

        /* Terminate the argument vector */
        args[i++] = NULL;

        /* Start the task */
        ret = sstp_task_start(ctx->task, args);
        if (SSTP_OKAY != ret)
        {
            goto done;
        }

        /* Get the socket to listen on */
        ctx->sock = sstp_task_stdout(ctx->task);
    }
    else
    {
        /* pppd is our parent, we communciate over a pty terminal */
        ctx->sock = STDIN_FILENO;
    }

    /* Add the event context */
    event_set(&ctx->recv, ctx->sock, EV_READ, (event_fn) 
            sstp_pppd_recv, ctx);

    /* Add the recieve event */
    event_add(&ctx->recv, NULL);

    /* Success! */
    status = SSTP_OKAY;

done:

    return (status);
}


status_t sstp_pppd_create(sstp_pppd_st **ctx, sstp_stream_st *stream)
{
    status_t ret    = SSTP_FAIL;
    status_t status = SSTP_FAIL;

    *ctx = calloc(1, sizeof(sstp_pppd_st));
    if (!*ctx)
    {
        goto done;
    }

    ret = sstp_buff_create(&(*ctx)->tx_buf, 16384);
    if (SSTP_OKAY != ret)
    {
        goto done;
    }

    ret = sstp_buff_create(&(*ctx)->rx_buf, 16384);
    if (SSTP_OKAY != ret)
    {
        goto done;
    }

    /* Save a reference to the stream handle */
    (*ctx)->stream = stream;


    /* Success */
    status = SSTP_OKAY;

done:
    
    if (SSTP_OKAY != status)
    {
        sstp_pppd_free(*ctx);
    }

    return status;
}


void sstp_pppd_free(sstp_pppd_st *ctx)
{
    if (!ctx)
    {
        return;
    }

    /* Cleanup the task */
    if (ctx->task)
    {
        /* Check if task is still running, then kill it */
        if (sstp_task_alive(ctx->task))
        {
            sstp_task_stop(ctx->task);
        }

        /* Wait for the task to terminate */
        sstp_task_wait(ctx->task, NULL, 0);

        /* Free resources */
        sstp_task_destroy(ctx->task);
    }

    /* Dispose send buffers */
    if (ctx->tx_buf)
    {
        sstp_buff_destroy(ctx->tx_buf);
        ctx->tx_buf = NULL;
    }

    /* Dispose receive buffers */
    if (ctx->rx_buf)
    {
        sstp_buff_destroy(ctx->rx_buf);
        ctx->rx_buf = NULL;
    }

    /* Dispose of receive event */
    event_del(&ctx->recv);

    /* Free pppd context */
    free(ctx);
}
