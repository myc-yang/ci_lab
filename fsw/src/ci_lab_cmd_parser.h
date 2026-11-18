#ifndef _ci_lab_cmd_parser_
#define _ci_lab_cmd_parser_

#include "hammer.h"
#include "glue.h"

typedef struct{
    void**  msgPtr;
    int32*   msgLen;
}cmd_pkt_parser_input_type;

HParser* CI_LAB_Init_Cmd_Pkt_Parser(cmd_pkt_parser_input_type* cmd_pkt_input);

#endif