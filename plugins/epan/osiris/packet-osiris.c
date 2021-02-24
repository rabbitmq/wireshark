/* packet-osiris.c
 *
 * Routines for Osiris protocol packet dissection
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

#include <stdio.h> // FIXME

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/crc32-tvb.h>
#include <epan/dissectors/packet-tcp.h>

#include <wsutil/str_util.h>

#define OSIRIS_TCP_PORT_RANGE "6000-6500" /* Not IANA registed */

#define OSIRIS_SEGMENT_FILE_HEADER_LENGTH 8
#define OSIRIS_CHUNK_HEADER_LENGTH 44

static int proto_osiris_chunk = -1;
static int proto_osiris_log_file = -1;

static int hf_osiris_magic = -1;
static int hf_osiris_version = -1;
static int hf_osiris_chunk_type = -1;
static int hf_osiris_num_entries = -1;
static int hf_osiris_num_records = -1;
static int hf_osiris_timestamp = -1;
static int hf_osiris_epoch = -1;
static int hf_osiris_chunk_first_offset = -1;
static int hf_osiris_chunk_crc = -1;
static int hf_osiris_data_length = -1;
static int hf_osiris_trailer_length = -1;

static int hf_osiris_entry_type = -1;
static int hf_osiris_entry_data_size = -1;
static int hf_osiris_entry_data = -1;
static int hf_osiris_tracking_entry_id_size = -1;
static int hf_osiris_tracking_entry_id = -1;
static int hf_osiris_tracking_entry_offset = -1;
static int hf_osiris_writer_snap_writer_id_size = -1;
static int hf_osiris_writer_snap_writer_id = -1;
static int hf_osiris_writer_snap_timestamp = -1;
static int hf_osiris_writer_snap_sequence = -1;
static int hf_osiris_subbatch_compression_type = -1;
static int hf_osiris_subbatch_reserved = -1;
static int hf_osiris_subbatch_num_records = -1;

static int hf_osiris_trailer_writer_id_size = -1;
static int hf_osiris_trailer_writer_id = -1;
static int hf_osiris_trailer_sequence = -1;

static int hf_osiris_log_magic = -1;
static int hf_osiris_log_version = -1;

static expert_field ei_osiris_invalid_chunk_type = EI_INIT;
static expert_field ei_osiris_invalid_entry_type = EI_INIT;
static expert_field ei_osiris_invalid_entry_type_for_chunk_type = EI_INIT;
static expert_field ei_osiris_chunk_content_overflow = EI_INIT;
static expert_field ei_osiris_crc_mismatch = EI_INIT;
static expert_field ei_osiris_unknown_entry_content = EI_INIT;
static expert_field ei_osiris_inconsistent_chunk_size = EI_INIT;

static gint ett_osiris = -1;
static gint ett_osiris_chunk_header = -1;
static gint ett_osiris_entries = -1;
static gint ett_osiris_entry = -1;
static gint ett_osiris_tracking_entry = -1;
static gint ett_osiris_trailer = -1;
static gint ett_osiris_trailer_entry = -1;

static gint ett_osiris_log = -1;

enum chunk_types {
    CHUNK_TYPE_USER = 0,
    CHUNK_TYPE_TRACKING_DELTA,
    CHUNK_TYPE_TRACKING_SNAPSHOT,
    CHUNK_TYPE_WRITERS_SNAPSHOT,
};

static const value_string chunk_type_names[] = {
    { CHUNK_TYPE_USER, "User" },
    { CHUNK_TYPE_TRACKING_DELTA, "Tracking delta" },
    { CHUNK_TYPE_TRACKING_SNAPSHOT, "Tracking snapshot" },
    { CHUNK_TYPE_WRITERS_SNAPSHOT, "Writers snapshot" },
};

enum entry_types {
    ENTRY_TYPE_SIMPLE = 0,
    ENTRY_TYPE_SUBBATCH,
};

static const value_string entry_type_names[] = {
    { ENTRY_TYPE_SIMPLE, "Simple entry" },
    { ENTRY_TYPE_SUBBATCH, "Sub-batch entry" },
};

struct osiris_chunk_header {
    guint starting_offset;
    guint version;
    enum chunk_types chunk_type;
    guint num_entries;
    guint num_records;
    guint data_length;
    guint trailer_length;
};

void proto_register_osiris(void);
void proto_reg_handoff_osiris(void);

static int
dissect_osiris_chunk_header(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, int offset)
{
    guint chunk_type, chunk_crc, actual_chunk_crc, data_length, trailer_length;
    guint64 timestamp;
    nstime_t tv;

    proto_tree *header_tree = proto_tree_add_subtree(tree, tvb, offset,
        OSIRIS_CHUNK_HEADER_LENGTH, ett_osiris_chunk_header, NULL, "Header");

    /*
     * Parsing header (44 bytes).
     * The header is followed by a variable number of "entries" and a
     * trailer.
     */
    proto_tree_add_bits_item(header_tree,
        hf_osiris_magic, tvb, offset * 8, 4, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(header_tree,
        hf_osiris_version, tvb, offset * 8 + 4, 4, ENC_BIG_ENDIAN);
    offset += 1;

    proto_item *chunk_type_item = proto_tree_add_item_ret_uint(header_tree,
        hf_osiris_chunk_type, tvb, offset, 1, ENC_BIG_ENDIAN, &chunk_type);
    switch (chunk_type) {
    case CHUNK_TYPE_USER:
    case CHUNK_TYPE_TRACKING_DELTA:
    case CHUNK_TYPE_TRACKING_SNAPSHOT:
    case CHUNK_TYPE_WRITERS_SNAPSHOT:
        offset += 1;
        break;
    default:
        expert_add_info(pinfo, chunk_type_item,
            &ei_osiris_invalid_chunk_type);
        return -1;
    }

    proto_tree_add_item(header_tree,
        hf_osiris_num_entries, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(header_tree,
        hf_osiris_num_records, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    timestamp = tvb_get_ntoh64(tvb, offset); // In milliseconds.
    tv.secs = timestamp / 1000;
    tv.nsecs = (timestamp % 1000) * 1000 * 1000;
    proto_tree_add_time(header_tree,
        hf_osiris_timestamp, tvb, offset, 8, &tv);
    offset += 8;

    proto_tree_add_item(header_tree,
        hf_osiris_epoch, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(header_tree,
        hf_osiris_chunk_first_offset, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_item *chunk_crc_item = proto_tree_add_item_ret_uint(header_tree,
        hf_osiris_chunk_crc, tvb, offset, 4, ENC_BIG_ENDIAN, &chunk_crc);
    offset += 4;

    proto_tree_add_item_ret_uint(header_tree,
        hf_osiris_data_length, tvb, offset, 4, ENC_BIG_ENDIAN, &data_length);
    offset += 4;

    proto_tree_add_item_ret_uint(header_tree,
        hf_osiris_trailer_length, tvb, offset, 4, ENC_BIG_ENDIAN, &trailer_length);
    offset += 4;

    actual_chunk_crc = crc32_ccitt_tvb_offset(tvb, offset, data_length);
    if (chunk_crc != actual_chunk_crc) {
        expert_add_info(pinfo, chunk_crc_item, &ei_osiris_crc_mismatch);
    }

    return offset;
}

static int
dissect_osiris_tracking_entry(tvbuff_t *tvb, packet_info *pinfo _U_,
    proto_tree *tree, int offset, struct osiris_chunk_header *header)
{
    guint32 id_size, entry_size, remaining_bytes;

    id_size = tvb_get_guint8(tvb, offset);
    entry_size = 1 + id_size + 8;
    remaining_bytes = header->starting_offset + OSIRIS_CHUNK_HEADER_LENGTH +
        header->data_length - offset;

    proto_tree *entry_tree = proto_tree_add_subtree_format(tree, tvb,
        offset, MIN(entry_size, remaining_bytes), ett_osiris_tracking_entry,
        NULL, "%s",
        val_to_str(header->chunk_type, chunk_type_names,
        "Unknown tracking entry (0x%02x)"));

    proto_item *entry_id_size_item = proto_tree_add_item(entry_tree,
        hf_osiris_tracking_entry_id_size, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (entry_size > remaining_bytes) {
        expert_add_info(pinfo, entry_id_size_item,
            &ei_osiris_chunk_content_overflow);
        return -1;
    }

    proto_tree_add_item(entry_tree,
        hf_osiris_tracking_entry_id, tvb, offset, id_size,
        ENC_BIG_ENDIAN);
    offset += id_size;

    proto_tree_add_item(entry_tree,
        hf_osiris_tracking_entry_offset, tvb, offset, 8,
        ENC_BIG_ENDIAN);
    offset += 8;

    return offset;
}

static int
dissect_osiris_writers_snapshot_entry(tvbuff_t *tvb, packet_info *pinfo _U_,
    proto_tree *tree, int offset, struct osiris_chunk_header *header)
{
    guint8 writer_id_size;
    guint32 entry_size, remaining_bytes;
    guint64 timestamp;
    nstime_t tv;

    writer_id_size = tvb_get_guint8(tvb, offset);
    entry_size = 1 + writer_id_size + 8 + 8;
    remaining_bytes = header->starting_offset + OSIRIS_CHUNK_HEADER_LENGTH +
        header->data_length - offset;

    proto_tree *entry_tree = proto_tree_add_subtree_format(tree, tvb,
        offset, entry_size, ett_osiris_tracking_entry, NULL,
        "%s",
        val_to_str(header->chunk_type, chunk_type_names,
        "Unknown tracking entry (0x%02x)"));

    proto_item *writer_id_size_item = proto_tree_add_item(entry_tree,
        hf_osiris_writer_snap_writer_id_size, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (entry_size > remaining_bytes) {
        expert_add_info(pinfo, writer_id_size_item,
            &ei_osiris_chunk_content_overflow);
        return -1;
    }

    proto_tree_add_item(entry_tree,
        hf_osiris_writer_snap_writer_id, tvb, offset, writer_id_size,
        ENC_BIG_ENDIAN);
    offset += writer_id_size;

    timestamp = tvb_get_ntoh64(tvb, offset); // In milliseconds.
    tv.secs = timestamp / 1000;
    tv.nsecs = (timestamp % 1000) * 1000 * 1000;
    proto_tree_add_time(entry_tree,
        hf_osiris_writer_snap_timestamp, tvb, offset, 8, &tv);
    offset += 8;

    proto_tree_add_item(entry_tree,
        hf_osiris_writer_snap_sequence, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    return offset;
}

static int
dissect_osiris_entry(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, int offset, struct osiris_chunk_header *header,
    guint entry_idx)
{
    enum entry_types entry_type;
    int ret, unknown_entry_type = 0;
    guint32 data_size, entry_size, remaining_bytes;
    proto_item *entry_data_item;

    entry_type = (enum entry_types)tvb_get_bits8(tvb, offset * 8, 1);
    remaining_bytes = header->starting_offset + OSIRIS_CHUNK_HEADER_LENGTH +
        header->data_length - offset;

    switch (entry_type) {
    case ENTRY_TYPE_SIMPLE:
        data_size = tvb_get_ntohl(tvb, offset) & 0x7fffffff;
        entry_size = 4 + data_size;
        break;
    case ENTRY_TYPE_SUBBATCH:
        data_size = tvb_get_ntohl(tvb, offset + 3);
        entry_size = 7 + data_size;
        break;
    default:
        data_size = 0;
        entry_size = 1;
        unknown_entry_type = 1;
        break;
    }

    proto_tree *entry_tree = proto_tree_add_subtree_format(tree, tvb,
        offset, entry_size, ett_osiris_entry, NULL,
        "Entry #%u, type %s, %u byte%s of data",
        entry_idx,
        val_to_str(entry_type, entry_type_names, "unknown (0x%02x)"),
        data_size, plurality(data_size, "", "s"));

    proto_item *entry_type_item = proto_tree_add_bits_item(entry_tree,
        hf_osiris_entry_type, tvb, offset * 8, 1, ENC_BIG_ENDIAN);

    if (unknown_entry_type) {
        expert_add_info(pinfo, entry_type_item,
            &ei_osiris_invalid_entry_type);
        return -1;
    } else if (entry_size > remaining_bytes) {
        expert_add_info(pinfo, entry_type_item,
            &ei_osiris_chunk_content_overflow);
        return -1;
    }

    switch (entry_type) {
    case ENTRY_TYPE_SIMPLE:
        proto_tree_add_bits_item(entry_tree,
            hf_osiris_entry_data_size, tvb, offset * 8 + 1, 31,
            ENC_BIG_ENDIAN);
        offset += 4;

        if (data_size > 0) {
            switch (header->chunk_type) {
            case CHUNK_TYPE_USER:
                proto_tree_add_item(entry_tree,
                    hf_osiris_entry_data, tvb, offset, data_size,
                    ENC_BIG_ENDIAN);
                offset += data_size;
                break;
            case CHUNK_TYPE_TRACKING_DELTA:
            case CHUNK_TYPE_TRACKING_SNAPSHOT:
                do {
                    ret = dissect_osiris_tracking_entry(tvb, pinfo,
                        entry_tree, offset, header);
                    if (ret < 0) {
                        return ret;
                    }

                    data_size -= (ret - offset);
                    offset = ret;
                } while (data_size > 0);
                break;
            case CHUNK_TYPE_WRITERS_SNAPSHOT:
                do {
                    ret = dissect_osiris_writers_snapshot_entry(tvb, pinfo,
                        entry_tree, offset, header);
                    if (ret < 0) {
                        return ret;
                    }

                    data_size -= (ret - offset);
                    offset = ret;
                } while (data_size > 0);
                break;
            default:
                entry_data_item = proto_tree_add_item(entry_tree,
                    hf_osiris_entry_data, tvb, offset, data_size,
                    ENC_BIG_ENDIAN);
                offset += data_size;

                expert_add_info(pinfo, entry_data_item,
                    &ei_osiris_unknown_entry_content);
            }
        }

        break;
    case ENTRY_TYPE_SUBBATCH:
        if (header->chunk_type != CHUNK_TYPE_USER) {
            expert_add_info(pinfo, entry_type_item,
                &ei_osiris_invalid_entry_type_for_chunk_type);
        }

        proto_tree_add_bits_item(entry_tree,
            hf_osiris_subbatch_compression_type, tvb, offset * 8 + 1, 3,
            ENC_BIG_ENDIAN);
        proto_tree_add_bits_item(entry_tree,
            hf_osiris_subbatch_reserved, tvb, offset * 8 + 4, 4,
            ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(entry_tree,
            hf_osiris_subbatch_num_records, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(entry_tree,
            hf_osiris_entry_data_size, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(entry_tree,
            hf_osiris_entry_data, tvb, offset, data_size,
            ENC_BIG_ENDIAN);
        offset += data_size;

        break;
    }

    return offset;
}

static int
dissect_osiris_entries(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, int offset, struct osiris_chunk_header *header)
{
    int ret = 0;
    guint data_length;

    proto_tree *entries_tree = proto_tree_add_subtree_format(tree, tvb,
        offset, header->data_length, ett_osiris_entries, NULL,
        "Entries (%u entr%s)", header->num_entries,
        plurality(header->num_entries, "y", "ies"));

    data_length = header->data_length;
    for (guint i = 0; i < header->num_entries; ++i) {
        ret = dissect_osiris_entry(tvb, pinfo, entries_tree,
            offset, header, i);
        if (ret < 0) {
            return ret;
        }

        data_length -= ret - offset;
        offset = ret;
    }

    return offset;
}

static int
dissect_osiris_trailer_entry(tvbuff_t *tvb, packet_info *pinfo _U_,
    proto_tree *tree, int offset, struct osiris_chunk_header *header)
{
    guint8 writer_id_size;
    guint32 entry_size, remaining_bytes;

    writer_id_size = tvb_get_guint8(tvb, offset);
    entry_size = 1 + writer_id_size + 8;
    remaining_bytes = header->starting_offset + OSIRIS_CHUNK_HEADER_LENGTH +
        header->data_length + header->trailer_length - offset;

    proto_tree *entry_tree = proto_tree_add_subtree(tree, tvb, offset,
        MIN(entry_size, remaining_bytes), ett_osiris_trailer_entry, NULL,
        "Trailer entry");

    proto_item *writer_id_size_item = proto_tree_add_item(entry_tree,
        hf_osiris_trailer_writer_id_size, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (entry_size > remaining_bytes) {
        expert_add_info(pinfo, writer_id_size_item,
            &ei_osiris_chunk_content_overflow);
        return -1;
    }

    proto_tree_add_item(entry_tree,
        hf_osiris_trailer_writer_id, tvb, offset, writer_id_size,
        ENC_BIG_ENDIAN);
    offset += writer_id_size;

    proto_tree_add_item(entry_tree,
        hf_osiris_trailer_sequence, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    return offset;
}

static int
dissect_osiris_trailer(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, int offset, struct osiris_chunk_header *header)
{
    int ret;
    guint32 remaining_bytes;

    proto_tree *trailer_tree = proto_tree_add_subtree(tree, tvb, offset,
        header->trailer_length, ett_osiris_trailer, NULL, "Trailer");

    remaining_bytes = header->trailer_length;
    do {
        ret = dissect_osiris_trailer_entry(tvb, pinfo,
            trailer_tree, offset, header);
        if (ret < 0) {
            return ret;
        }

        remaining_bytes -= (ret - offset);
        offset = ret;
    } while (remaining_bytes > 0);

    return offset;
}

static int
dissect_osiris_chunk(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, void* data _U_)
{
    int ret, offset = 0;
    struct osiris_chunk_header header;

    header.starting_offset = offset;
    header.version = tvb_get_guint8(tvb, offset) & 0x0f;
    header.chunk_type = tvb_get_guint8(tvb, offset + 1);
    header.num_entries = (guint)tvb_get_ntohs(tvb, offset + 2);
    header.num_records = (guint)tvb_get_ntohs(tvb, offset + 4);
    header.data_length = tvb_get_ntohl(tvb, offset + 36);
    header.trailer_length = tvb_get_ntohl(tvb, offset + 40);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Osiris");

    col_clear(pinfo->cinfo,COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Chunk type '%s', %u entr%s",
        val_to_str(header.chunk_type, chunk_type_names,
        "Unknown chunk type (0x%02x)"),
        header.num_entries, plurality(header.num_entries, "y", "ies"));

    proto_item *ti = proto_tree_add_item(tree, proto_osiris_chunk, tvb,
        offset, OSIRIS_CHUNK_HEADER_LENGTH + header.data_length +
        header.trailer_length, ENC_NA);
    proto_item_append_text(ti, ", chunk type '%s', %u entr%s",
        val_to_str(header.chunk_type, chunk_type_names,
        "unknown (0x%02x)"),
        header.num_entries, plurality(header.num_entries, "y", "ies"));

    proto_tree *osiris_tree = proto_item_add_subtree(ti, ett_osiris);
    ret = dissect_osiris_chunk_header(tvb, pinfo, osiris_tree, offset);
    if (ret < 0) {
        return offset + OSIRIS_CHUNK_HEADER_LENGTH + header.data_length +
            header.trailer_length;
    }
    offset = ret;

    if (header.data_length > 0) {
        ret = dissect_osiris_entries(tvb, pinfo, osiris_tree, offset,
            &header);
        offset = (ret >= 0) ? ret : offset + header.data_length;
    }

    if (header.trailer_length > 0) {
        ret = dissect_osiris_trailer(tvb, pinfo, osiris_tree, offset,
            &header);
        offset = (ret >= 0) ? ret : offset + header.trailer_length;
    }

    if (offset - header.starting_offset !=
        OSIRIS_CHUNK_HEADER_LENGTH +
        header.data_length +
        header.trailer_length) {
        expert_add_info(pinfo, ti,
            &ei_osiris_inconsistent_chunk_size);
    }

    return offset;
}

static guint
get_osiris_chunk_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset,
    void *data _U_)
{
    guint8 magic_and_version, magic, version;
    guint data_length, trailer_length;

    magic_and_version = tvb_get_guint8(tvb, offset);
    magic = magic_and_version >> 4 & 0x0f;
    version = magic_and_version & 0x0f;
    if (magic != 0x05) {
        fprintf(stderr, "Not an Osiris chunk header (magic: %02x)\n", magic);
        return 0;
    }
    if (version != 0) {
        fprintf(stderr, "Unsupported Osiris chunk version: %02x\n", version);
        return 0;
    }

    offset += 36;
    data_length = (guint)tvb_get_ntohl(tvb, offset);
    offset += 4;
    trailer_length = (guint)tvb_get_ntohl(tvb, offset);

    return OSIRIS_CHUNK_HEADER_LENGTH + data_length + trailer_length;
}

static int
dissect_osiris_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    void* data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, OSIRIS_CHUNK_HEADER_LENGTH,
        get_osiris_chunk_len, dissect_osiris_chunk, data);
    return tvb_captured_length(tvb);
}

static gboolean
dissect_osiris_heur_file(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, void *data)
{
    int ret, count, offset, tvb_len, chunk_len;
    guint32 log_version;

    offset = 0;

    tvb_len = tvb_reported_length(tvb);
    if (tvb_len < OSIRIS_SEGMENT_FILE_HEADER_LENGTH) {
        return FALSE;
    }

    if (tvb_memeql(tvb, offset, (const guint8*)"OSIL", 4) != 0) {
        return FALSE;
    }
    offset += 4;
    tvb_len -= 4;

    log_version = tvb_get_ntohl(tvb, offset);
    if (log_version != 1) {
        return FALSE;
    }
    offset += 4;
    tvb_len -= 4;

    proto_item *ti = proto_tree_add_item(tree, proto_osiris_log_file, tvb,
        0, -1, ENC_NA);
    proto_item_append_text(ti, ", version %d", log_version);

    proto_tree *osiris_log_tree = proto_item_add_subtree(ti, ett_osiris_log);
    proto_tree_add_item(osiris_log_tree, hf_osiris_log_magic, tvb, 0, 4,
        ENC_BIG_ENDIAN);
    proto_tree_add_item(osiris_log_tree, hf_osiris_log_version, tvb, 4, 4,
        ENC_BIG_ENDIAN);

    count = 0;
    if (tvb_len >= OSIRIS_CHUNK_HEADER_LENGTH &&
        get_osiris_chunk_len(pinfo, tvb, offset, data) > 0) {
        do {
            chunk_len = get_osiris_chunk_len(pinfo, tvb, offset, data);
            if (chunk_len == 0) {
                break;
            }

            tvbuff_t *subtvb = tvb_new_subset_length(tvb, offset, chunk_len);
            ret = dissect_osiris_chunk(subtvb, pinfo, tree, data);

            offset += chunk_len;
            ++count;
        } while (offset < tvb_len);
    }

    col_clear(pinfo->cinfo,COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Log file, %d chunk%s",
        count, plurality(count, "", "s"));

    return TRUE;
}

void
proto_register_osiris(void)
{
    expert_module_t *expert_osiris;

    static hf_register_info hf[] = {
        { &hf_osiris_magic,
            { "Chunk magic", "osiris.chunk.magic",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },

        { &hf_osiris_version,
            { "Chunk version", "osiris.chunk.version",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },

        { &hf_osiris_chunk_type,
            { "Chunk type", "osiris.chunk.type",
                FT_UINT8, BASE_HEX,
                VALS(chunk_type_names), 0x0,
                NULL, HFILL }
        },

        { &hf_osiris_num_entries,
            { "Number of entries", "osiris.chunk.num_entries",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },

        { &hf_osiris_num_records,
            { "Number of records", "osiris.chunk.num_records",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },

        { &hf_osiris_timestamp,
            { "Timestamp", "osiris.chunk.timestamp",
                FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC,
                NULL, 0x0,
                NULL, HFILL }
        },

        { &hf_osiris_epoch,
            { "Epoch", "osiris.chunk.epoch",
                FT_UINT64, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },

        { &hf_osiris_chunk_first_offset,
            { "Chunk first offset", "osiris.chunk.first_offset",
                FT_UINT64, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },

        { &hf_osiris_chunk_crc,
            { "Chunk CRC", "osiris.chunk.crc",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },

        { &hf_osiris_data_length,
            { "Data length", "osiris.chunk.data_length",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },

        { &hf_osiris_trailer_length,
            { "Trailer length", "osiris.chunk.trailer_length",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },

        { &hf_osiris_entry_type,
            { "Entry type", "osiris.chunk.entry.type",
                FT_UINT8, BASE_HEX,
                VALS(entry_type_names), 0x0,
                NULL, HFILL }
        },

        { &hf_osiris_entry_data_size,
            { "Entry data size", "osiris.chunk.entry.data_size",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },

        { &hf_osiris_entry_data,
            { "Entry data", "osiris.chunk.entry.data",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },

        { &hf_osiris_tracking_entry_id_size,
            { "Tracking entry ID size", "osiris.chunk.tracking_entry.id_size",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },

        { &hf_osiris_tracking_entry_id,
            { "Tracking entry ID", "osiris.chunk.tracking_entry.id",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },

        { &hf_osiris_tracking_entry_offset,
            { "Tracking entry offset", "osiris.chunk.tracking_entry.offset",
                FT_UINT64, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },

        { &hf_osiris_subbatch_compression_type,
            { "Sub-batch compression type",
                "osiris.chunk.subbatch.compression_type",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },

        { &hf_osiris_subbatch_reserved,
            { "Sub-batch reserved bytes",
                "osiris.chunk.subbatch.reserved_bytes",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },

        { &hf_osiris_subbatch_num_records,
            { "Sub-batch number of records",
                "osiris.chunk.subbatch.num_records",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },

        { &hf_osiris_trailer_writer_id_size,
            { "Trailer writer ID size", "osiris.chunk.trailer.writer_id_size",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },

        { &hf_osiris_trailer_writer_id,
            { "Trailer writer ID", "osiris.chunk.trailer.writer_id",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },

        { &hf_osiris_trailer_sequence,
            { "Trailer sequence", "osiris.chunk.trailer.sequence",
                FT_UINT64, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
    };

    static ei_register_info ei[] = {
        {
            &ei_osiris_invalid_chunk_type,
            { "osiris.chunk.invalid_chunk_type", PI_PROTOCOL, PI_WARN,
                "Chunk type is invalid", EXPFILL }
        },

        {
            &ei_osiris_invalid_entry_type,
            { "osiris.chunk.invalid_entry_type", PI_PROTOCOL, PI_WARN,
                "Entry type is invalid", EXPFILL }
        },

        {
            &ei_osiris_invalid_entry_type_for_chunk_type,
            { "osiris.chunk.invalid_entry_type_for_chunk_type", PI_PROTOCOL,
                PI_WARN,
                "Entry type is invalid for this chunk type", EXPFILL }
        },

        {
            &ei_osiris_chunk_content_overflow,
            { "osiris.chunk.content_overflow", PI_PROTOCOL, PI_WARN,
                "Chunk content overflows its length", EXPFILL }
        },

        {
            &ei_osiris_crc_mismatch,
            { "osiris.chunk.crc_mismatch", PI_CHECKSUM, PI_WARN,
                "CRC mismatch", EXPFILL }
        },

        {
            &ei_osiris_unknown_entry_content,
            { "osiris.chunk.unknown_entry_content", PI_PROTOCOL, PI_NOTE,
                "Unknown entry content", EXPFILL }
        },

        {
            &ei_osiris_inconsistent_chunk_size,
            { "osiris.chunk.inconsistent_chunk_size", PI_PROTOCOL, PI_WARN,
                "Inconsistent chunk size", EXPFILL }
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_osiris,
        &ett_osiris_chunk_header,
        &ett_osiris_entries,
        &ett_osiris_entry,
        &ett_osiris_tracking_entry,
        &ett_osiris_trailer,
        &ett_osiris_trailer_entry,
    };

    proto_osiris_chunk = proto_register_protocol(
        "Osiris Chunk",
        "Osiris chunk",
        "osiris-chunk");

    proto_register_field_array(proto_osiris_chunk, hf, array_length(hf));
    expert_osiris = expert_register_protocol(proto_osiris_chunk);
    expert_register_field_array(expert_osiris, ei, array_length(ei));
    proto_register_subtree_array(ett, array_length(ett));

    static hf_register_info log_hf[] = {
        { &hf_osiris_log_magic,
            { "Segment file magic", "osiris.log.magic",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },

        { &hf_osiris_log_version,
            { "Segment file version", "osiris.log.version",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
    };

    static gint *log_ett[] = {
        &ett_osiris_log,
    };

    proto_osiris_log_file = proto_register_protocol(
        "Osiris Log File",
        "Osiris log",
        "osiris-log");

    proto_register_field_array(proto_osiris_log_file,
        log_hf, array_length(log_hf));
    proto_register_subtree_array(log_ett, array_length(log_ett));
}

void
proto_reg_handoff_osiris(void)
{
    dissector_handle_t osiris_handle, osiris_log_handle;

    osiris_handle = create_dissector_handle(dissect_osiris_tcp,
        proto_osiris_chunk);
    dissector_add_uint_range_with_preference(
        "tcp.port", OSIRIS_TCP_PORT_RANGE, osiris_handle);

    osiris_log_handle = create_dissector_handle(NULL, proto_osiris_log_file);
    heur_dissector_add("wtap_file", dissect_osiris_heur_file,
        "Osiris log file", "osiris_wtap", proto_osiris_log_file,
        HEURISTIC_ENABLE);
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
