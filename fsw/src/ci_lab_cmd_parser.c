#include "cfe.h"

#include "hammer.h"
#include "glue.h"

#include "ci_lab_cmd_parser.h"

typedef enum{
    CMD_PKT_PRI_HDR_CCSDS_VERSION = 1,
    CMD_PKT_PRI_HDR_PACKET_TYPE,
    CMD_PKT_PRI_HDR_SEC_HDR_PRESENT,
    CMD_PKT_PRI_HDR_APP_ID,
    CMD_PKT_PRI_HDR_SEG_FLAG,
    CMD_PKT_PRI_HDR_SEQ_CNT,
    CMD_PKT_PRI_HDR_LEN,
    CMD_PKT_PRI_HDR_NUM_ATTR
}CMD_PKT_PRI_HDR_ATTR;

typedef enum{
    CMD_PKT_SEC_HDR_FUNC_CODE = 1,
    CMD_PKT_SEC_HDR_CHECKSUM,
    CMD_PKT_SEC_HDR_NUM_ATTR
}CMD_PKT_SEC_HDR_ATTR;

bool validate_primary_cmd_header(HParseResult *p, void *user_data)
{
    //double check that the parser result is a sequence
    if (p->ast->token_type != TT_SEQUENCE){
        return false;
    }

    int32 *length = (int32 *)user_data;

    const HParsedToken *seq, *elem[CMD_PKT_PRI_HDR_NUM_ATTR];

    seq = p->ast;
    elem[CMD_PKT_PRI_HDR_CCSDS_VERSION] = h_seq_index(seq, CMD_PKT_PRI_HDR_CCSDS_VERSION);
    elem[CMD_PKT_PRI_HDR_PACKET_TYPE] = h_seq_index(seq, CMD_PKT_PRI_HDR_PACKET_TYPE);
    elem[CMD_PKT_PRI_HDR_SEC_HDR_PRESENT] = h_seq_index(seq, CMD_PKT_PRI_HDR_SEC_HDR_PRESENT);
    elem[CMD_PKT_PRI_HDR_APP_ID] = h_seq_index(seq, CMD_PKT_PRI_HDR_APP_ID);
    elem[CMD_PKT_PRI_HDR_SEG_FLAG] = h_seq_index(seq, CMD_PKT_PRI_HDR_SEG_FLAG);
    elem[CMD_PKT_PRI_HDR_SEQ_CNT] = h_seq_index(seq, CMD_PKT_PRI_HDR_SEQ_CNT);
    elem[CMD_PKT_PRI_HDR_LEN] = h_seq_index(seq, CMD_PKT_PRI_HDR_LEN);

#ifdef MESSAGE_FORMAT_IS_CCSDS_VER_2
    if (elem[CMD_PKT_PRI_HDR_CCSDS_VERSION]->token_data.uint == false){
        return false;
    }
#else
    if (elem[CMD_PKT_PRI_HDR_CCSDS_VERSION]->token_data.uint == true){
        return false;
    }
#endif

    if ((elem[CMD_PKT_PRI_HDR_LEN]->token_data.uint + 7) < sizeof(CFE_MSG_CommandHeader_t)){
        return false;
    }

    if ((elem[CMD_PKT_PRI_HDR_LEN]->token_data.uint + 7) != *length){
        return false;
    }

    if ((elem[CMD_PKT_PRI_HDR_PACKET_TYPE]->token_data.uint) == false){
        return false;
    }

    if ((elem[CMD_PKT_PRI_HDR_SEC_HDR_PRESENT]->token_data.uint) == false){
        return false;
    }

    if ((elem[CMD_PKT_PRI_HDR_SEG_FLAG]->token_data.uint) != 3){
        return false;
    }

    return true;
}

HParsedToken *act_primary_cmd_header(const HParseResult *p, void *user_data){
    const HParsedToken *seq, *appid, *len, *ext_hdr;

    //If CCSDS version defined as 2, returns token with true, meaning we need to parse extended header, else, returns token with false,
#ifdef MESSAGE_FORMAT_IS_CCSDS_VER_2
    ext_hdr = H_MAKE_UINT(1);
#else
    ext_hdr = H_MAKE_UINT(0);
#endif

    // TODO:  Any way to avoid having to do this twice?
    seq = p->ast;

    appid = h_seq_index(seq, CMD_PKT_PRI_HDR_APP_ID);
    len = h_seq_index(seq, CMD_PKT_PRI_HDR_LEN);

    HParsedToken *t = H_MAKE_SEQ();

    h_seq_snoc(t, ext_hdr);
    h_seq_snoc(t, appid);
    h_seq_snoc(t, len);

    return t;
}

HParser* CI_LAB_Init_Cmd_Pkt_Pri_Hdr_Parser(int32* Bytes_Received){

    // Parser Definitions - Primary Header Elements
    H_RULE(reserved_2bit, h_bits(2, false));
    H_RULE(ccsds_version, h_bits(1, false));
    H_RULE(packet_type, h_bits(1, false));
    H_RULE(sec_hdr_present, h_bits(1, false));
    H_RULE(app_id, h_bits(11, false));

    H_RULE(seg_flag, h_bits(2, false));
    H_RULE(seq_cnt, h_bits(14, false));

    H_RULE(length, h_uint16());

    //Parser Definition for Primary Header
    H_RULE(primary_cmd_header_def, h_sequence(reserved_2bit, ccsds_version, packet_type, sec_hdr_present, app_id, seg_flag, seq_cnt, length, NULL));

    // primary_cmd_header validation function which checks
    // CCSDS packet type should be 1 for CMD
    // CCSDS Secondary Header should be present
    // CCSDS segmentation flag should = 3
    // length field + 7 in primary header should match size of packet received from socket
    // If CCSDS version is 2, should be defined by mission as using version 2
    // If validation is success, action will be taken which will return Parse Result indicating whether we should parse extended or secondary header

    H_AVDRULE(primary_cmd_header, primary_cmd_header_def, Bytes_Received);

    return primary_cmd_header;

}

HParser* CI_LAB_Init_Cmd_Pkt_Ext_Hdr_Parser(void){

    // Parser Definitions - Extended Header Elements
    H_RULE(eds_version, h_bits(5, false));
    H_RULE(endian, h_bits(1, false));
    H_RULE(playback, h_bits(1, false));
    H_RULE(subsys_id, h_bits(9, false));
    H_RULE(sys_id, h_uint16()); 

    //Parser Definition for Extended Header
    H_RULE(ext_cmd_header_def, h_sequence(eds_version, endian, playback, subsys_id, sys_id, NULL));

    return ext_cmd_header_def;
}

HParsedToken *act_secondary_cmd_header(const HParseResult *p, void *user_data){

    const HParsedToken *seq;

    // TODO:  Any way to avoid having to do this twice?
    seq = p->ast;

    return h_seq_index(seq, CMD_PKT_SEC_HDR_FUNC_CODE);
}

bool validate_secondary_cmd_header(HParseResult *p, void *user_data){

    cmd_pkt_parser_input_type* parse_data = (cmd_pkt_parser_input_type *)user_data;

    const HParsedToken *seq, *elem[CMD_PKT_SEC_HDR_NUM_ATTR] __attribute__((unused));

    seq = p->ast;

    elem[CMD_PKT_SEC_HDR_CHECKSUM] = h_seq_index(seq, CMD_PKT_SEC_HDR_CHECKSUM);

    size_t             PktLen = *(parse_data->msgLen);
    const uint8       *BytePtr = (const uint8 *)(*(parse_data->msgPtr));
    CFE_MSG_Checksum_t chksum  = 0xFF;

    /* Message already checked, no error case reachable */

    while (PktLen--)
    {
        chksum ^= *(BytePtr++);
    }

    return (chksum == 0);

}

HParser* CI_LAB_Init_Cmd_Pkt_Sec_Hdr_Parser(cmd_pkt_parser_input_type* cmd_pkt_input){

    //Parser Definition - Secondary Header
    H_RULE(reserved_bit, h_bits(1, false));
    H_RULE(func_code, h_bits(7, false));

    H_RULE(checksum, h_uint8());

    H_RULE(sec_cmd_header_def, h_sequence(reserved_bit, func_code, checksum, NULL));

    H_AVDRULE(secondary_cmd_header, sec_cmd_header_def, cmd_pkt_input);

    return secondary_cmd_header;
}

HParsedToken *act_cmd_hdr(const HParseResult *p, void *user_data){

    return (h_act_flatten(p, user_data));

}

HParser* CI_LAB_Init_Cmd_Pkt_Parser(cmd_pkt_parser_input_type* cmd_pkt_input){

    H_RULE(cmd_pri_hdr_parser, CI_LAB_Init_Cmd_Pkt_Pri_Hdr_Parser(cmd_pkt_input->msgLen));
    
    H_RULE(cmd_sec_hdr_parser, CI_LAB_Init_Cmd_Pkt_Sec_Hdr_Parser(cmd_pkt_input));

#ifdef MESSAGE_FORMAT_IS_CCSDS_VER_2
    H_RULE(cmd_ext_hdr_parser, CI_LAB_Init_Cmd_Pkt_Ext_Hdr_Parser());
    H_RULE(cmd_hdr_parser, h_sequence(cmd_pri_hdr_parser, cmd_ext_hdr_parser, cmd_sec_hdr_parser));
#else
    H_RULE(cmd_hdr_parser, h_sequence(cmd_pri_hdr_parser, cmd_sec_hdr_parser, NULL));
#endif

    H_ARULE(cmd_hdr, cmd_hdr_parser);

    return cmd_hdr;
}
