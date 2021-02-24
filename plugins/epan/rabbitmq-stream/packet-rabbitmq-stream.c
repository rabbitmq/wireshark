/* packet-rabbitmq-stream.c
 *
 * Routines for RabbiMQ Stream protocol packet dissection
 * By Jean-Sébastien Pédron <jean-sebastien@rabbitmq.com>
 * Copyright (C) 2021 VMware, Inc. or its affiliates.  All rights reserved.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Specification: TODO
 *
 */

#include "config.h"

#include <stdio.h> // FIXME

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/crc32-tvb.h>
#include <epan/dissectors/packet-tcp.h>

#define RMQSTREAM_TCP_PORT 5555 /* Not IANA registed */

static int proto_rmqstream = -1;

static int hf_rmqstream_frame_size = -1;
static int hf_rmqstream_frame_key = -1;
static int hf_rmqstream_frame_version = -1;
static int hf_rmqstream_correlation_id = -1;
static int hf_rmqstream_response_code = -1;

//static expert_field ei_rmqstream_invalid_chunk_type = EI_INIT;

static gint ett_rmqstream = -1;

enum frame_keys {
    F_DECLARE_PUBLISHER = 0,
    F_PUBLISH,
    F_PUBLISH_CONFIRM,
    F_PUBLISH_ERROR,
    F_QUERY_PUBLISHER_SEQ,
    F_DELETE_PUBLISHER,
    F_SUBSCRIBE,
    F_DELIVER,
    F_CREDIT,
    F_COMMIT_OFFSET,
    F_QUERY_OFFSET,
    F_UNSUBSCRIBE,
    F_CREATE,
    F_DELETE,
    F_METADATA,
    F_METADATA_UPDATE,
    F_PEER_PROPERTIES,
    F_SASL_HANDSHAKE,
    F_SASL_AUTHENTICATE,
    F_TUNE,
    F_OPEN,
    F_CLOSE,
    F_HEARTBEAT,
};

static const value_string frame_key_names[] = {
    { F_DECLARE_PUBLISHER, "DeclarePublisher" },
    { F_PUBLISH, "Publish" },
    { F_PUBLISH_CONFIRM, "PublishConfirm" },
    { F_PUBLISH_ERROR, "PublishError" },
    { F_QUERY_PUBLISHER_SEQ, "QueryPublisherSequence" },
    { F_DELETE_PUBLISHER, "DeletePublisher" },
    { F_SUBSCRIBE, "Subscribe" },
    { F_DELIVER, "Deliver" },
    { F_CREDIT, "Credit" },
    { F_COMMIT_OFFSET, "CommitOffset" },
    { F_QUERY_OFFSET, "QueryOffset" },
    { F_UNSUBSCRIBE, "Unsubscribe" },
    { F_CREATE, "Create" },
    { F_DELETE, "Delete" },
    { F_METADATA, "Metadata" },
    { F_METADATA_UPDATE, "MetadataUpdate" },
    { F_PEER_PROPERTIES, "PeerProperties" },
    { F_SASL_HANDSHAKE, "SaslHandshake" },
    { F_SASL_AUTHENTICATE, "SaslAuthenticate" },
    { F_TUNE, "Tune" },
    { F_OPEN, "Open" },
    { F_CLOSE, "Close" },
    { F_HEARTBEAT, "Heartbeat" },
};

#define F_FROM_CLIENT     0x01
#define F_FROM_SERVER     0x02
#define F_EXPECT_RESPONSE 0x04

/*   Key (int16_t)
 * + Version (int16_t)
 * + CorrelationId (int32_t)
 * + ResponseCode (int16_t) */
#define RESPONSE_MIN_SIZE 2 + 2 + 4 + 2

struct frame_properties {
    gint key;
    gint flags;
    gint response_size;
};

static const struct frame_properties frame_props[] = {
    {
        .key = F_DECLARE_PUBLISHER,
        .flags = F_FROM_CLIENT|F_EXPECT_RESPONSE,
        .response_size = RESPONSE_MIN_SIZE,
    },
    {
        .key = F_PUBLISH,
        .flags = F_FROM_CLIENT,
        .response_size = 0,
    },
    {
        .key = F_PUBLISH_CONFIRM,
        .flags = F_FROM_SERVER,
        .response_size = 0,
    },
    {
        .key = F_PUBLISH_ERROR,
        .flags = F_FROM_SERVER,
        .response_size = 0,
    },
    {
        .key = F_QUERY_PUBLISHER_SEQ,
        .flags = F_FROM_CLIENT|F_EXPECT_RESPONSE,
        .response_size = RESPONSE_MIN_SIZE + 2 + 8,
    },
    {
        .key = F_DELETE_PUBLISHER,
        .flags = F_FROM_CLIENT|F_EXPECT_RESPONSE,
        .response_size = RESPONSE_MIN_SIZE,
    },
    {
        .key = F_SUBSCRIBE,
        .flags = F_FROM_CLIENT|F_EXPECT_RESPONSE,
        .response_size = RESPONSE_MIN_SIZE,
    },
    {
        .key = F_DELIVER,
        .flags = F_FROM_SERVER,
        .response_size = 0,
    },
    {
        .key = F_CREDIT,
        .flags = F_FROM_CLIENT|F_EXPECT_RESPONSE,
        .response_size = RESPONSE_MIN_SIZE + 1,
    },
    {
        .key = F_COMMIT_OFFSET,
        .flags = F_FROM_CLIENT,
        .response_size = 0,
    },
    {
        .key = F_QUERY_OFFSET,
        .flags = F_FROM_CLIENT|F_EXPECT_RESPONSE,
        .response_size = RESPONSE_MIN_SIZE + 8,
    },
    {
        .key = F_UNSUBSCRIBE,
        .flags = F_FROM_CLIENT|F_EXPECT_RESPONSE,
        .response_size = RESPONSE_MIN_SIZE,
    },
    {
        .key = F_CREATE,
        .flags = F_FROM_CLIENT|F_EXPECT_RESPONSE,
        .response_size = RESPONSE_MIN_SIZE,
    },
    {
        .key = F_DELETE,
        .flags = F_FROM_CLIENT|F_EXPECT_RESPONSE,
        .response_size = RESPONSE_MIN_SIZE,
    },
    {
        .key = F_METADATA,
        .flags = F_FROM_CLIENT,
        .response_size = 0,
    },
    {
        .key = F_METADATA_UPDATE,
        .flags = F_FROM_SERVER,
        .response_size = 0,
    },
    {
        .key = F_PEER_PROPERTIES,
        .flags = F_FROM_CLIENT|F_EXPECT_RESPONSE,
        .response_size = 0,
    },
    {
        .key = F_SASL_HANDSHAKE,
        .flags = F_FROM_CLIENT|F_EXPECT_RESPONSE,
        .response_size = 0,
    },
    {
        .key = F_SASL_AUTHENTICATE,
        .flags = F_FROM_CLIENT|F_EXPECT_RESPONSE,
        .response_size = 0,
    },
    {
        .key = F_TUNE,
        .flags = F_FROM_CLIENT|F_FROM_SERVER,
        .response_size = 0,
    },
    {
        .key = F_OPEN,
        .flags = F_FROM_SERVER|F_EXPECT_RESPONSE,
        .response_size = RESPONSE_MIN_SIZE,
    },
    {
        .key = F_CLOSE,
        .flags = F_FROM_CLIENT|F_FROM_SERVER|F_EXPECT_RESPONSE,
        .response_size = RESPONSE_MIN_SIZE,
    },
    {
        .key = F_HEARTBEAT,
        .flags = F_FROM_CLIENT|F_FROM_SERVER,
        .response_size = 0,
    },
};

void proto_register_rmqstream(void);
void proto_reg_handoff_rmqstream(void);

static int
dissect_rmqstream_command(tvbuff_t *tvb _U_, packet_info *pinfo _U_,
    proto_tree *tree _U_, int offset _U_, gint frame_size _U_,
    enum frame_keys frame_key _U_, gint frame_version _U_)
{
    return offset;
}

static int
dissect_rmqstream_request(tvbuff_t *tvb _U_, packet_info *pinfo _U_,
    proto_tree *tree _U_, int offset _U_, gint frame_size _U_,
    enum frame_keys frame_key _U_, gint frame_version _U_)
{
    return offset;
}

static int
dissect_rmqstream_response(tvbuff_t *tvb _U_, packet_info *pinfo _U_,
    proto_tree *tree _U_, int offset _U_, gint frame_size _U_,
    enum frame_keys frame_key _U_, gint frame_version _U_)
{
    return offset;
}

static int
dissect_rmqstream_frame(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, int offset, gint frame_size,
    enum frame_keys frame_key, gint frame_version)
{
    if (frame_props[frame_key].flags & F_EXPECT_RESPONSE) {
        if (frame_size == RESPONSE_MIN_SIZE) {
            /* Response frame. */
            return dissect_rmqstream_response(tvb, pinfo, tree, offset,
                frame_size, frame_key, frame_version);
        } else {
            /* Request frame. */
            return dissect_rmqstream_request(tvb, pinfo, tree, offset,
                frame_size, frame_key, frame_version);
        }
    } else {
        /* Command frame. */
        return dissect_rmqstream_command(tvb, pinfo, tree, offset,
            frame_size, frame_key, frame_version);
    }
}

static int
dissect_rmqstream_message(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, void* data _U_)
{
    int ret;
    gint offset = 0, size, key, version;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RMQ Stream");
    col_clear(pinfo->cinfo, COL_INFO);

    size = tvb_get_ntohil(tvb, offset);
    proto_item *ti = proto_tree_add_item(tree, proto_rmqstream, tvb,
        offset, 4 + size, ENC_NA);

    proto_tree *rmqstream_tree = proto_item_add_subtree(ti, ett_rmqstream);

    proto_tree_add_item(rmqstream_tree,
        hf_rmqstream_frame_size, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item_ret_int(rmqstream_tree,
        hf_rmqstream_frame_key, tvb, offset, 2, ENC_BIG_ENDIAN,
        &key);
    offset += 2;

    proto_tree_add_item_ret_int(rmqstream_tree,
        hf_rmqstream_frame_version, tvb, offset, 2, ENC_BIG_ENDIAN,
        &version);
    offset += 4;

    ret = dissect_rmqstream_frame(tvb, pinfo, rmqstream_tree, offset,
        size, key, version);
    if (ret < 0) {
        return offset;
    }
    offset += ret;

    return offset;
}

static guint
get_rmqstream_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset,
    void *data _U_)
{
    gint size;

    size = tvb_get_ntohil(tvb, offset);

    return 4 + size;
}

static int
dissect_rmqstream(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    void* data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 4,
        get_rmqstream_message_len, dissect_rmqstream_message, data);
    return tvb_captured_length(tvb);
}

void
proto_register_rmqstream(void)
{
    expert_module_t *expert_rmqstream;

    static hf_register_info hf[] = {
        { &hf_rmqstream_frame_size,
            { "Frame size", "rmqstream.frame_size",
                FT_INT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },

        { &hf_rmqstream_frame_key,
            { "Frame key", "rmqstream.frame_key",
                FT_INT16, BASE_DEC,
                VALS(frame_key_names), 0x0,
                NULL, HFILL }
        },

        { &hf_rmqstream_frame_version,
            { "Frame version", "rmqstream.frame_version",
                FT_INT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },

        { &hf_rmqstream_correlation_id,
            { "Correlation ID", "rmqstream.correlation_id",
                FT_INT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },

        { &hf_rmqstream_response_code,
            { "Response code", "rmqstream.response_code",
                FT_INT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
    };

    static ei_register_info ei[] = {
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_rmqstream,
    };

    proto_rmqstream = proto_register_protocol(
        "RabbitMQ Stream Protocol",
        "RabbitMQ Stream",
        "rabbitmq-stream");

    proto_register_field_array(proto_rmqstream, hf, array_length(hf));
    expert_rmqstream = expert_register_protocol(proto_rmqstream);
    expert_register_field_array(expert_rmqstream, ei, array_length(ei));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_rmqstream(void)
{
    dissector_handle_t rmqstream_handle;

    rmqstream_handle = create_dissector_handle(dissect_rmqstream,
        proto_rmqstream);
    dissector_add_uint_with_preference(
        "tcp.port", RMQSTREAM_TCP_PORT, rmqstream_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
