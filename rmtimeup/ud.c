/* udis86-1.7 */

/* -----------------------------------------------------------------------------
 * decode.c
 *
 * Copyright (c) 2005, 2006, Vivek Mohan <vivek@sig9.com>
 * All rights reserved. See LICENSE
 * -----------------------------------------------------------------------------
 */

#if USE_PTS
#define __UD_STANDALONE__ 1
#define assert(x) do {} while(0)
#else
#include <assert.h>
#include <string.h>
#include "input.h"
#include "decode.h"
#endif

/* -----------------------------------------------------------------------------
 * input.h
 *
 * Copyright (c) 2006, Vivek Mohan <vivek@sig9.com>
 * All rights reserved. See LICENSE
 * -----------------------------------------------------------------------------
 */
#ifndef UD_INPUT_H
#define UD_INPUT_H

#include "ud.h"

uint8_t inp_next(struct ud*);
uint8_t inp_peek(struct ud*);
uint8_t inp_uint8(struct ud*);
uint16_t inp_uint16(struct ud*);
uint32_t inp_uint32(struct ud*);
uint64_t inp_uint64(struct ud*);
void inp_move(struct ud*, size_t);
void inp_back(struct ud*);

/* inp_init() - Initializes the input system. */
#define inp_init(u) \
do { \
  u->inp_curr = 0; \
  u->inp_fill = 0; \
  u->inp_ctr  = 0; \
  u->inp_end  = 0; \
} while (0)

/* inp_start() - Should be called before each de-code operation. */
#define inp_start(u) u->inp_ctr = 0

/* inp_back() - Resets the current pointer to its position before the current
 * instruction disassembly was started.
 */
#define inp_reset(u) \
do { \
  u->inp_curr -= u->inp_ctr; \
  u->inp_ctr = 0; \
} while (0)

/* inp_sess() - Returns the pointer to current session. */
#define inp_sess(u) (u->inp_sess)

/* inp_cur() - Returns the current input byte. */
#define inp_curr(u) ((u)->inp_cache[(u)->inp_curr])

#endif

#ifndef UD_DECODE_H
#define UD_DECODE_H

#define MAX_INSN_LENGTH 15

/* register classes */
#define T_NONE  0
#define T_GPR   1
#define T_MMX   2
#define T_CRG   3
#define T_DBG   4
#define T_SEG   5
#define T_XMM   6

/* itab prefix bits */
#define P_none          ( 0 )
#define P_c1            ( 1 << 0 )
#define P_C1(n)         ( ( n >> 0 ) & 1 )
#define P_rexb          ( 1 << 1 )
#define P_REXB(n)       ( ( n >> 1 ) & 1 )
#define P_depM          ( 1 << 2 )
#define P_DEPM(n)       ( ( n >> 2 ) & 1 )
#define P_c3            ( 1 << 3 )
#define P_C3(n)         ( ( n >> 3 ) & 1 )
#define P_inv64         ( 1 << 4 )
#define P_INV64(n)      ( ( n >> 4 ) & 1 )
#define P_rexw          ( 1 << 5 )
#define P_REXW(n)       ( ( n >> 5 ) & 1 )
#define P_c2            ( 1 << 6 )
#define P_C2(n)         ( ( n >> 6 ) & 1 )
#define P_def64         ( 1 << 7 )
#define P_DEF64(n)      ( ( n >> 7 ) & 1 )
#define P_rexr          ( 1 << 8 )
#define P_REXR(n)       ( ( n >> 8 ) & 1 )
#define P_oso           ( 1 << 9 )
#define P_OSO(n)        ( ( n >> 9 ) & 1 )
#define P_aso           ( 1 << 10 )
#define P_ASO(n)        ( ( n >> 10 ) & 1 )
#define P_rexx          ( 1 << 11 )
#define P_REXX(n)       ( ( n >> 11 ) & 1 )
#define P_ImpAddr       ( 1 << 12 )
#define P_IMPADDR(n)    ( ( n >> 12 ) & 1 )

/* rex prefix bits */
#define REX_W(r)        ( ( 0xF & ( r ) )  >> 3 )
#define REX_R(r)        ( ( 0x7 & ( r ) )  >> 2 )
#define REX_X(r)        ( ( 0x3 & ( r ) )  >> 1 )
#define REX_B(r)        ( ( 0x1 & ( r ) )  >> 0 )
#define REX_PFX_MASK(n) ( ( P_REXW(n) << 3 ) | \
                          ( P_REXR(n) << 2 ) | \
                          ( P_REXX(n) << 1 ) | \
                          ( P_REXB(n) << 0 ) )

/* scable-index-base bits */
#define SIB_S(b)        ( ( b ) >> 6 )
#define SIB_I(b)        ( ( ( b ) >> 3 ) & 7 )
#define SIB_B(b)        ( ( b ) & 7 )

/* modrm bits */
#define MODRM_REG(b)    ( ( ( b ) >> 3 ) & 7 )
#define MODRM_NNN(b)    ( ( ( b ) >> 3 ) & 7 )
#define MODRM_MOD(b)    ( ( ( b ) >> 6 ) & 3 )
#define MODRM_RM(b)     ( ( b ) & 7 )

/* operand type constants -- order is important! */

enum ud_operand_code {
    OP_NONE,

    OP_A,      OP_E,      OP_M,       OP_G,       
    OP_I,

    OP_AL,     OP_CL,     OP_DL,      OP_BL,
    OP_AH,     OP_CH,     OP_DH,      OP_BH,

    OP_ALr8b,  OP_CLr9b,  OP_DLr10b,  OP_BLr11b,
    OP_AHr12b, OP_CHr13b, OP_DHr14b,  OP_BHr15b,

    OP_AX,     OP_CX,     OP_DX,      OP_BX,
    OP_SI,     OP_DI,     OP_SP,      OP_BP,

    OP_rAX,    OP_rCX,    OP_rDX,     OP_rBX,  
    OP_rSP,    OP_rBP,    OP_rSI,     OP_rDI,

    OP_rAXr8,  OP_rCXr9,  OP_rDXr10,  OP_rBXr11,  
    OP_rSPr12, OP_rBPr13, OP_rSIr14,  OP_rDIr15,

    OP_eAX,    OP_eCX,    OP_eDX,     OP_eBX,
    OP_eSP,    OP_eBP,    OP_eSI,     OP_eDI,

    OP_ES,     OP_CS,     OP_SS,      OP_DS,  
    OP_FS,     OP_GS,

    OP_ST0,    OP_ST1,    OP_ST2,     OP_ST3,
    OP_ST4,    OP_ST5,    OP_ST6,     OP_ST7,

    OP_J,      OP_S,      OP_O,          
    OP_I1,     OP_I3, 

    OP_V,      OP_W,      OP_Q,       OP_P, 

    OP_R,      OP_C,  OP_D,       OP_VR,  OP_PR
};


/* operand size constants */

enum ud_operand_size {
    SZ_NA  = 0,
    SZ_Z   = 1,
    SZ_V   = 2,
    SZ_P   = 3,
    SZ_WP  = 4,
    SZ_DP  = 5,
    SZ_MDQ = 6,
    SZ_RDQ = 7,

    /* the following values are used as is,
     * and thus hard-coded. changing them 
     * will break internals 
     */
    SZ_B   = 8,
    SZ_W   = 16,
    SZ_D   = 32,
    SZ_Q   = 64,
    SZ_T   = 80,
};

/* itab entry operand definitions */

#define O_rSPr12  { OP_rSPr12,   SZ_NA    }
#define O_BL      { OP_BL,       SZ_NA    }
#define O_BH      { OP_BH,       SZ_NA    }
#define O_BP      { OP_BP,       SZ_NA    }
#define O_AHr12b  { OP_AHr12b,   SZ_NA    }
#define O_BX      { OP_BX,       SZ_NA    }
#define O_Jz      { OP_J,        SZ_Z     }
#define O_Jv      { OP_J,        SZ_V     }
#define O_Jb      { OP_J,        SZ_B     }
#define O_rSIr14  { OP_rSIr14,   SZ_NA    }
#define O_GS      { OP_GS,       SZ_NA    }
#define O_D       { OP_D,        SZ_NA    }
#define O_rBPr13  { OP_rBPr13,   SZ_NA    }
#define O_Ob      { OP_O,        SZ_B     }
#define O_P       { OP_P,        SZ_NA    }
#define O_Ow      { OP_O,        SZ_W     }
#define O_Ov      { OP_O,        SZ_V     }
#define O_Gw      { OP_G,        SZ_W     }
#define O_Gv      { OP_G,        SZ_V     }
#define O_rDX     { OP_rDX,      SZ_NA    }
#define O_Gx      { OP_G,        SZ_MDQ   }
#define O_Gd      { OP_G,        SZ_D     }
#define O_Gb      { OP_G,        SZ_B     }
#define O_rBXr11  { OP_rBXr11,   SZ_NA    }
#define O_rDI     { OP_rDI,      SZ_NA    }
#define O_rSI     { OP_rSI,      SZ_NA    }
#define O_ALr8b   { OP_ALr8b,    SZ_NA    }
#define O_eDI     { OP_eDI,      SZ_NA    }
#define O_Gz      { OP_G,        SZ_Z     }
#define O_eDX     { OP_eDX,      SZ_NA    }
#define O_DHr14b  { OP_DHr14b,   SZ_NA    }
#define O_rSP     { OP_rSP,      SZ_NA    }
#define O_PR      { OP_PR,       SZ_NA    }
#define O_NONE    { OP_NONE,     SZ_NA    }
#define O_rCX     { OP_rCX,      SZ_NA    }
#define O_jWP     { OP_J,        SZ_WP    }
#define O_rDXr10  { OP_rDXr10,   SZ_NA    }
#define O_Md      { OP_M,        SZ_D     }
#define O_C       { OP_C,        SZ_NA    }
#define O_G       { OP_G,        SZ_NA    }
#define O_Mb      { OP_M,        SZ_B     }
#define O_Mt      { OP_M,        SZ_T     }
#define O_S       { OP_S,        SZ_NA    }
#define O_Mq      { OP_M,        SZ_Q     }
#define O_W       { OP_W,        SZ_NA    }
#define O_ES      { OP_ES,       SZ_NA    }
#define O_rBX     { OP_rBX,      SZ_NA    }
#define O_Ed      { OP_E,        SZ_D     }
#define O_DLr10b  { OP_DLr10b,   SZ_NA    }
#define O_Mw      { OP_M,        SZ_W     }
#define O_Eb      { OP_E,        SZ_B     }
#define O_Ex      { OP_E,        SZ_MDQ   }
#define O_Ez      { OP_E,        SZ_Z     }
#define O_Ew      { OP_E,        SZ_W     }
#define O_Ev      { OP_E,        SZ_V     }
#define O_Ep      { OP_E,        SZ_P     }
#define O_FS      { OP_FS,       SZ_NA    }
#define O_Ms      { OP_M,        SZ_W     }
#define O_rAXr8   { OP_rAXr8,    SZ_NA    }
#define O_eBP     { OP_eBP,      SZ_NA    }
#define O_Isb     { OP_I,        SZ_SB    }
#define O_eBX     { OP_eBX,      SZ_NA    }
#define O_rCXr9   { OP_rCXr9,    SZ_NA    }
#define O_jDP     { OP_J,        SZ_DP    }
#define O_CH      { OP_CH,       SZ_NA    }
#define O_CL      { OP_CL,       SZ_NA    }
#define O_R       { OP_R,        SZ_RDQ   }
#define O_V       { OP_V,        SZ_NA    }
#define O_CS      { OP_CS,       SZ_NA    }
#define O_CHr13b  { OP_CHr13b,   SZ_NA    }
#define O_eCX     { OP_eCX,      SZ_NA    }
#define O_eSP     { OP_eSP,      SZ_NA    }
#define O_SS      { OP_SS,       SZ_NA    }
#define O_SP      { OP_SP,       SZ_NA    }
#define O_BLr11b  { OP_BLr11b,   SZ_NA    }
#define O_SI      { OP_SI,       SZ_NA    }
#define O_eSI     { OP_eSI,      SZ_NA    }
#define O_DL      { OP_DL,       SZ_NA    }
#define O_DH      { OP_DH,       SZ_NA    }
#define O_DI      { OP_DI,       SZ_NA    }
#define O_DX      { OP_DX,       SZ_NA    }
#define O_rBP     { OP_rBP,      SZ_NA    }
#define O_Gvw     { OP_G,        SZ_MDQ   }
#define O_I1      { OP_I1,       SZ_NA    }
#define O_I3      { OP_I3,       SZ_NA    }
#define O_DS      { OP_DS,       SZ_NA    }
#define O_ST4     { OP_ST4,      SZ_NA    }
#define O_ST5     { OP_ST5,      SZ_NA    }
#define O_ST6     { OP_ST6,      SZ_NA    }
#define O_ST7     { OP_ST7,      SZ_NA    }
#define O_ST0     { OP_ST0,      SZ_NA    }
#define O_ST1     { OP_ST1,      SZ_NA    }
#define O_ST2     { OP_ST2,      SZ_NA    }
#define O_ST3     { OP_ST3,      SZ_NA    }
#define O_E       { OP_E,        SZ_NA    }
#define O_AH      { OP_AH,       SZ_NA    }
#define O_M       { OP_M,        SZ_NA    }
#define O_AL      { OP_AL,       SZ_NA    }
#define O_CLr9b   { OP_CLr9b,    SZ_NA    }
#define O_Q       { OP_Q,        SZ_NA    }
#define O_eAX     { OP_eAX,      SZ_NA    }
#define O_VR      { OP_VR,       SZ_NA    }
#define O_AX      { OP_AX,       SZ_NA    }
#define O_rAX     { OP_rAX,      SZ_NA    }
#define O_Iz      { OP_I,        SZ_Z     }
#define O_rDIr15  { OP_rDIr15,   SZ_NA    }
#define O_Iw      { OP_I,        SZ_W     }
#define O_Iv      { OP_I,        SZ_V     }
#define O_Ap      { OP_A,        SZ_P     }
#define O_CX      { OP_CX,       SZ_NA    }
#define O_Ib      { OP_I,        SZ_B     }
#define O_BHr15b  { OP_BHr15b,   SZ_NA    }


/* A single operand of an entry in the instruction table. 
 * (internal use only)
 */
struct ud_itab_entry_operand 
{
  enum ud_operand_code type;
  enum ud_operand_size size;
};


/* A single entry in an instruction table. 
 *(internal use only)
 */
struct ud_itab_entry 
{
  enum ud_mnemonic_code         mnemonic;
  struct ud_itab_entry_operand  operand1;
  struct ud_itab_entry_operand  operand2;
  struct ud_itab_entry_operand  operand3;
  uint32_t                      prefix;
};

extern const char * ud_lookup_mnemonic( enum ud_mnemonic_code c );

#endif /* UD_DECODE_H */

/* vim:cindent
 * vim:expandtab
 * vim:ts=4
 * vim:sw=4
 */

/* -----------------------------------------------------------------------------
 * syn.h
 *
 * Copyright (c) 2006, Vivek Mohan <vivek@sig9.com>
 * All rights reserved. See LICENSE
 * -----------------------------------------------------------------------------
 */
#ifndef UD_SYN_H
#define UD_SYN_H

#if USE_PTS
#else
#include <stdio.h>
#include <stdarg.h>
#endif

extern const char* ud_reg_tab[];

static void mkasm_str1(struct ud* u, const char* str1)
{
  while (*str1 != '\0') u->insn_buffer[u->insn_fill++] = *str1++;
  u->insn_buffer[u->insn_fill] = '\0';
}

static void mkasm_hex1(struct ud* u, uint64_t n)
{
  char *p = u->insn_buffer + u->insn_fill, *q = p, c;
  static char hextable[] = "0123456789abcdef";
  do {
    *q++ = hextable[n & 15];
    n >>= 4;
  } while (n > 0);
  *q = '\0';
  u->insn_fill += q - p;
  q--;
  while (q > p) {
    c = *p;
    *p++ = *q;
    *q-- = c;
  }
}

static void mkasm_dec32(struct ud* u, uint32_t n)
{
  char *p = u->insn_buffer + u->insn_fill, *q = p, c;
  do {
    *q++ = '0' + (n % 10);
    n /= 10;
  } while (n > 0);
  *q = '\0';
  u->insn_fill += q - p;
  q--;
  while (q > p) {
    c = *p;
    *p++ = *q;
    *q-- = c;
  }
}

#endif

/* The max number of prefixes to an instruction */
#define MAX_PREFIXES    15

static struct ud_itab_entry ie_invalid = { UD_Iinvalid, O_NONE, O_NONE, O_NONE, P_none };
static struct ud_itab_entry ie_pause   = { UD_Ipause,   O_NONE, O_NONE, O_NONE, P_none };
static struct ud_itab_entry ie_nop     = { UD_Inop,     O_NONE, O_NONE, O_NONE, P_none };


/* Looks up mnemonic code in the mnemonic string table
 * Returns NULL if the mnemonic code is invalid
 */
const char * ud_lookup_mnemonic( enum ud_mnemonic_code c )
{
    if ( c < UD_Id3vil )
        return ud_mnemonics_str[ c ];
    return NULL;
}


/* Extracts instruction prefixes.
 */
static int get_prefixes( struct ud* u )
{
    unsigned int have_pfx = 1;
    unsigned int i;
    uint8_t curr;

    /* if in error state, bail out */
    if ( u->error ) 
        return -1; 

    /* keep going as long as there are prefixes available */
    for ( i = 0; have_pfx ; ++i ) {

        /* Get next byte. */
        inp_next(u); 
        if ( u->error ) 
            return -1;
        curr = inp_curr( u );

        /* rex prefixes in 64bit mode */
        if ( u->dis_mode == 64 && ( curr & 0xF0 ) == 0x40 ) {
            u->pfx_rex = curr;  
        } else {
            switch ( curr )  
            {
            case 0x2E : 
                u->pfx_seg = UD_R_CS; 
                u->pfx_rex = 0;
                break;
            case 0x36 :     
                u->pfx_seg = UD_R_SS; 
                u->pfx_rex = 0;
                break;
            case 0x3E : 
                u->pfx_seg = UD_R_DS; 
                u->pfx_rex = 0;
                break;
            case 0x26 : 
                u->pfx_seg = UD_R_ES; 
                u->pfx_rex = 0;
                break;
            case 0x64 : 
                u->pfx_seg = UD_R_FS; 
                u->pfx_rex = 0;
                break;
            case 0x65 : 
                u->pfx_seg = UD_R_GS; 
                u->pfx_rex = 0;
                break;
            case 0x67 : /* adress-size override prefix */ 
                u->pfx_adr = 0x67;
                u->pfx_rex = 0;
                break;
            case 0xF0 : 
                u->pfx_lock = 0xF0;
                u->pfx_rex  = 0;
                break;
            case 0x66: 
                /* the 0x66 sse prefix is only effective if no other sse prefix
                 * has already been specified.
                 */
                if ( !u->pfx_insn ) u->pfx_insn = 0x66;
                u->pfx_opr = 0x66;           
                u->pfx_rex = 0;
                break;
            case 0xF2:
                u->pfx_insn  = 0xF2;
                u->pfx_repne = 0xF2; 
                u->pfx_rex   = 0;
                break;
            case 0xF3:
                u->pfx_insn = 0xF3;
                u->pfx_rep  = 0xF3; 
                u->pfx_repe = 0xF3; 
                u->pfx_rex  = 0;
                break;
            default : 
                /* No more prefixes */
                have_pfx = 0;
                break;
            }
        }

        /* check if we reached max instruction length */
        if ( i + 1 == MAX_INSN_LENGTH ) {
            u->error = 1;
            break;
        }
    }

    /* return status */
    if ( u->error ) 
        return -1; 

    /* rewind back one byte in stream, since the above loop 
     * stops with a non-prefix byte. 
     */
    inp_back(u);

    /* speculatively determine the effective operand mode,
     * based on the prefixes and the current disassembly
     * mode. This may be inaccurate, but useful for mode
     * dependent decoding.
     */
    if ( u->dis_mode == 64 ) {
        u->opr_mode = REX_W( u->pfx_rex ) ? 64 : ( ( u->pfx_opr ) ? 16 : 32 ) ;
        u->adr_mode = ( u->pfx_adr ) ? 32 : 64;
    } else if ( u->dis_mode == 32 ) {
        u->opr_mode = ( u->pfx_opr ) ? 16 : 32;
        u->adr_mode = ( u->pfx_adr ) ? 16 : 32;
    } else if ( u->dis_mode == 16 ) {
        u->opr_mode = ( u->pfx_opr ) ? 32 : 16;
        u->adr_mode = ( u->pfx_adr ) ? 32 : 16;
    }

    return 0;
}


/* Searches the instruction tables for the right entry.
 */
static int search_itab( struct ud * u )
{
    struct ud_itab_entry * e = NULL;
    enum ud_itab_index table;
    uint8_t peek;
    uint8_t did_peek = 0;
    uint8_t curr; 
    uint8_t index;

    /* if in state of error, return */
    if ( u->error ) 
        return -1;

    /* get first byte of opcode. */
    inp_next(u); 
    if ( u->error ) 
        return -1;
    curr = inp_curr(u); 

    /* resolve xchg, nop, pause crazyness */
    if ( 0x90 == curr ) {
        if ( !( u->dis_mode == 64 && REX_B( u->pfx_rex ) ) ) {
            if ( u->pfx_rep ) {
                u->pfx_rep = 0;
                e = & ie_pause;
            } else {
                e = & ie_nop;
            }
            goto found_entry;
        }
    }

    /* get top-level table */
    if ( 0x0F == curr ) {
        table = ITAB__0F;
        curr  = inp_next(u);
        if ( u->error )
            return -1;

        /* 2byte opcodes can be modified by 0x66, F3, and F2 prefixes */
        if ( 0x66 == u->pfx_insn ) {
            if ( ud_itab_list[ ITAB__PFX_SSE66__0F ][ curr ].mnemonic != UD_Iinvalid ) {
                table = ITAB__PFX_SSE66__0F;
                u->pfx_opr = 0;
            }
        } else if ( 0xF2 == u->pfx_insn ) {
            if ( ud_itab_list[ ITAB__PFX_SSEF2__0F ][ curr ].mnemonic != UD_Iinvalid ) {
                table = ITAB__PFX_SSEF2__0F; 
                u->pfx_repne = 0;
            }
        } else if ( 0xF3 == u->pfx_insn ) {
            if ( ud_itab_list[ ITAB__PFX_SSEF3__0F ][ curr ].mnemonic != UD_Iinvalid ) {
                table = ITAB__PFX_SSEF3__0F;
                u->pfx_repe = 0;
                u->pfx_rep  = 0;
            }
        }
    /* pick an instruction from the 1byte table */
    } else {
        table = ITAB__1BYTE; 
    }

    index = curr;

search:

    e = & ud_itab_list[ table ][ index ];

    /* if mnemonic constant is a standard instruction constant
     * our search is over.
     */
    
    if ( e->mnemonic < UD_Id3vil ) {
        if ( e->mnemonic == UD_Iinvalid ) {
            if ( did_peek ) {
                inp_next( u ); if ( u->error ) return -1;
            }
            goto found_entry;
        }
        goto found_entry;
    }

    table = e->prefix;

    switch ( e->mnemonic )
    {
    case UD_Igrp_reg:
        peek     = inp_peek( u );
        did_peek = 1;
        index    = MODRM_REG( peek );
        break;

    case UD_Igrp_mod:
        peek     = inp_peek( u );
        did_peek = 1;
        index    = MODRM_MOD( peek );
        if ( index == 3 )
           index = ITAB__MOD_INDX__11;
        else 
           index = ITAB__MOD_INDX__NOT_11; 
        break;

    case UD_Igrp_rm:
        curr     = inp_next( u );
        did_peek = 0;
        if ( u->error )
            return -1;
        index    = MODRM_RM( curr );
        break;

    case UD_Igrp_x87:
        curr     = inp_next( u );
        did_peek = 0;
        if ( u->error )
            return -1;
        index    = curr - 0xC0;
        break;

    case UD_Igrp_osize:
        if ( u->opr_mode == 64 ) 
            index = ITAB__MODE_INDX__64;
        else if ( u->opr_mode == 32 ) 
            index = ITAB__MODE_INDX__32;
        else
            index = ITAB__MODE_INDX__16;
        break;
 
    case UD_Igrp_asize:
        if ( u->adr_mode == 64 ) 
            index = ITAB__MODE_INDX__64;
        else if ( u->adr_mode == 32 ) 
            index = ITAB__MODE_INDX__32;
        else
            index = ITAB__MODE_INDX__16;
        break;               

    case UD_Igrp_mode:
        if ( u->dis_mode == 64 ) 
            index = ITAB__MODE_INDX__64;
        else if ( u->dis_mode == 32 ) 
            index = ITAB__MODE_INDX__32;
        else
            index = ITAB__MODE_INDX__16;
        break;

    case UD_Igrp_vendor:
        if ( u->vendor == UD_VENDOR_INTEL ) 
            index = ITAB__VENDOR_INDX__INTEL; 
        else if ( u->vendor == UD_VENDOR_AMD )
            index = ITAB__VENDOR_INDX__AMD;
        else
            assert( !"unrecognized vendor id" );
        break;

    case UD_Id3vil:
        assert( !"invalid instruction mnemonic constant Id3vil" );
        break;

    default:
        assert( !"invalid instruction mnemonic constant" );
        break;
    }

    goto search;

found_entry:

    u->itab_entry = e;
    u->mnemonic = u->itab_entry->mnemonic;

    return 0;
}


static unsigned int resolve_operand_size( const struct ud * u, unsigned int s )
{
    switch ( s ) 
    {
    case SZ_V:
        return ( u->opr_mode );
    case SZ_Z:  
        return ( u->opr_mode == 16 ) ? 16 : 32;
    case SZ_P:  
        return ( u->opr_mode == 16 ) ? SZ_WP : SZ_DP;
    case SZ_MDQ:
        return ( u->opr_mode == 16 ) ? 32 : u->opr_mode;
    case SZ_RDQ:
        return ( u->dis_mode == 64 ) ? 64 : 32;
    default:
        return s;
    }
}


static int resolve_mnemonic( struct ud* u )
{
  /* far/near flags */
  u->br_far = 0;
  u->br_near = 0;
  /* readjust operand sizes for call/jmp instrcutions */
  if ( u->mnemonic == UD_Icall || u->mnemonic == UD_Ijmp ) {
    /* WP: 16bit pointer */
    if ( u->operand[ 0 ].size == SZ_WP ) {
        u->operand[ 0 ].size = 16;
        u->br_far = 1;
        u->br_near= 0;
    /* DP: 32bit pointer */
    } else if ( u->operand[ 0 ].size == SZ_DP ) {
        u->operand[ 0 ].size = 32;
        u->br_far = 1;
        u->br_near= 0;
    } else {
        u->br_far = 0;
        u->br_near= 1;
    }
  /* resolve 3dnow weirdness. */
  } else if ( u->mnemonic == UD_I3dnow ) {
    u->mnemonic = ud_itab_list[ ITAB__3DNOW ][ inp_curr( u )  ].mnemonic;
  }
  /* SWAPGS is only valid in 64bits mode */
  if ( u->mnemonic == UD_Iswapgs && u->dis_mode != 64 ) {
    u->error = 1;
    return -1;
  }

  return 0;
}


/* -----------------------------------------------------------------------------
 * decode_a()- Decodes operands of the type seg:offset
 * -----------------------------------------------------------------------------
 */
static void 
decode_a(struct ud* u, struct ud_operand *op)
{
  if (u->opr_mode == 16) {  
    /* seg16:off16 */
    op->type = UD_OP_PTR;
    op->size = 32;
    op->lval.ptr.off = inp_uint16(u);
    op->lval.ptr.seg = inp_uint16(u);
  } else {
    /* seg16:off32 */
    op->type = UD_OP_PTR;
    op->size = 48;
    op->lval.ptr.off = inp_uint32(u);
    op->lval.ptr.seg = inp_uint16(u);
  }
}

/* -----------------------------------------------------------------------------
 * decode_gpr() - Returns decoded General Purpose Register 
 * -----------------------------------------------------------------------------
 */
static enum ud_type 
decode_gpr(register struct ud* u, unsigned int s, unsigned char rm)
{
  s = resolve_operand_size(u, s);
        
  switch (s) {
    case 64:
        return UD_R_RAX + rm;
    case SZ_DP:
    case 32:
        return UD_R_EAX + rm;
    case SZ_WP:
    case 16:
        return UD_R_AX  + rm;
    case  8:
        if (u->dis_mode == 64 && u->pfx_rex) {
            if (rm >= 4)
                return UD_R_SPL + (rm-4);
            return UD_R_AL + rm;
        } else return UD_R_AL + rm;
    default:
        return 0;
  }
}

/* -----------------------------------------------------------------------------
 * resolve_gpr64() - 64bit General Purpose Register-Selection. 
 * -----------------------------------------------------------------------------
 */
static enum ud_type 
resolve_gpr64(struct ud* u, enum ud_operand_code gpr_op)
{
  if (gpr_op >= OP_rAXr8 && gpr_op <= OP_rDIr15)
    gpr_op = (gpr_op - OP_rAXr8) | (REX_B(u->pfx_rex) << 3);          
  else  gpr_op = (gpr_op - OP_rAX);

  if (u->opr_mode == 16)
    return gpr_op + UD_R_AX;
  if (u->dis_mode == 32 || 
    (u->opr_mode == 32 && ! (REX_W(u->pfx_rex) || u->default64))) {
    return gpr_op + UD_R_EAX;
  }

  return gpr_op + UD_R_RAX;
}

/* -----------------------------------------------------------------------------
 * resolve_gpr32 () - 32bit General Purpose Register-Selection. 
 * -----------------------------------------------------------------------------
 */
static enum ud_type 
resolve_gpr32(struct ud* u, enum ud_operand_code gpr_op)
{
  gpr_op = gpr_op - OP_eAX;

  if (u->opr_mode == 16) 
    return gpr_op + UD_R_AX;

  return gpr_op +  UD_R_EAX;
}

/* -----------------------------------------------------------------------------
 * resolve_reg() - Resolves the register type 
 * -----------------------------------------------------------------------------
 */
static enum ud_type 
resolve_reg(struct ud* u, unsigned int type, unsigned char i)
{
#if USE_PTS
  (void)u;
#endif
  switch (type) {
    case T_MMX :    return UD_R_MM0  + (i & 7);
    case T_XMM :    return UD_R_XMM0 + i;
    case T_CRG :    return UD_R_CR0  + i;
    case T_DBG :    return UD_R_DR0  + i;
    case T_SEG :    return UD_R_ES   + (i & 7);
    case T_NONE:
    default:    return UD_NONE;
  }
}

/* -----------------------------------------------------------------------------
 * decode_imm() - Decodes Immediate values.
 * -----------------------------------------------------------------------------
 */
static void 
decode_imm(struct ud* u, unsigned int s, struct ud_operand *op)
{
  op->size = resolve_operand_size(u, s);
  op->type = UD_OP_IMM;

  switch (op->size) {
    case  8: op->lval.sbyte = inp_uint8(u);   break;
    case 16: op->lval.uword = inp_uint16(u);  break;
    case 32: op->lval.udword = inp_uint32(u); break;
    case 64: op->lval.uqword = inp_uint64(u); break;
    default: return;
  }
}

/* -----------------------------------------------------------------------------
 * decode_modrm() - Decodes ModRM Byte
 * -----------------------------------------------------------------------------
 */
static void 
decode_modrm(struct ud* u, struct ud_operand *op, unsigned int s, 
         unsigned char rm_type, struct ud_operand *opreg, 
         unsigned char reg_size, unsigned char reg_type)
{
  unsigned char mod, rm, reg;

  inp_next(u);

  /* get mod, r/m and reg fields */
  mod = MODRM_MOD(inp_curr(u));
  rm  = (REX_B(u->pfx_rex) << 3) | MODRM_RM(inp_curr(u));
  reg = (REX_R(u->pfx_rex) << 3) | MODRM_REG(inp_curr(u));

  op->size = resolve_operand_size(u, s);

  /* if mod is 11b, then the UD_R_m specifies a gpr/mmx/sse/control/debug */
  if (mod == 3) {
    op->type = UD_OP_REG;
    if (rm_type ==  T_GPR)
        op->base = decode_gpr(u, op->size, rm);
    else    op->base = resolve_reg(u, rm_type, (REX_B(u->pfx_rex) << 3) | (rm&7));
  } 
  /* else its memory addressing */  
  else {
    op->type = UD_OP_MEM;

    /* 64bit addressing */
    if (u->adr_mode == 64) {

        op->base = UD_R_RAX + rm;

        /* get offset type */
        if (mod == 1)
            op->offset = 8;
        else if (mod == 2)
            op->offset = 32;
        else if (mod == 0 && (rm & 7) == 5) {           
            op->base = UD_R_RIP;
            op->offset = 32;
        } else  op->offset = 0;

        /* Scale-Index-Base (SIB) */
        if ((rm & 7) == 4) {
            inp_next(u);
            
            op->scale = (1 << SIB_S(inp_curr(u))) & ~1;
            op->index = UD_R_RAX + (SIB_I(inp_curr(u)) | (REX_X(u->pfx_rex) << 3));
            op->base  = UD_R_RAX + (SIB_B(inp_curr(u)) | (REX_B(u->pfx_rex) << 3));

            /* special conditions for base reference */
            if (op->index == UD_R_RSP) {
                op->index = UD_NONE;
                op->scale = UD_NONE;
            }

            if (op->base == UD_R_RBP || op->base == UD_R_R13) {
                if (mod == 0) 
                    op->base = UD_NONE;
                if (mod == 1)
                    op->offset = 8;
                else op->offset = 32;
            }
        }
    } 

    /* 32-Bit addressing mode */
    else if (u->adr_mode == 32) {

        /* get base */
        op->base = UD_R_EAX + rm;

        /* get offset type */
        if (mod == 1)
            op->offset = 8;
        else if (mod == 2)
            op->offset = 32;
        else if (mod == 0 && rm == 5) {
            op->base = UD_NONE;
            op->offset = 32;
        } else  op->offset = 0;

        /* Scale-Index-Base (SIB) */
        if ((rm & 7) == 4) {
            inp_next(u);

            op->scale = (1 << SIB_S(inp_curr(u))) & ~1;
            op->index = UD_R_EAX + (SIB_I(inp_curr(u)) | (REX_X(u->pfx_rex) << 3));
            op->base  = UD_R_EAX + (SIB_B(inp_curr(u)) | (REX_B(u->pfx_rex) << 3));

            if (op->index == UD_R_ESP) {
                op->index = UD_NONE;
                op->scale = UD_NONE;
            }

            /* special condition for base reference */
            if (op->base == UD_R_EBP) {
                if (mod == 0)
                    op->base = UD_NONE;
                if (mod == 1)
                    op->offset = 8;
                else op->offset = 32;
            }
        }
    } 

    /* 16bit addressing mode */
    else  {
        switch (rm) {
            case 0: op->base = UD_R_BX; op->index = UD_R_SI; break;
            case 1: op->base = UD_R_BX; op->index = UD_R_DI; break;
            case 2: op->base = UD_R_BP; op->index = UD_R_SI; break;
            case 3: op->base = UD_R_BP; op->index = UD_R_DI; break;
            case 4: op->base = UD_R_SI; break;
            case 5: op->base = UD_R_DI; break;
            case 6: op->base = UD_R_BP; break;
            case 7: op->base = UD_R_BX; break;
        }

        if (mod == 0 && rm == 6) {
            op->offset= 16;
            op->base = UD_NONE;
        }
        else if (mod == 1)
            op->offset = 8;
        else if (mod == 2) 
            op->offset = 16;
    }
  }  

  /* extract offset, if any */
  switch(op->offset) {
    case 8 : op->lval.ubyte  = inp_uint8(u);  break;
    case 16: op->lval.uword  = inp_uint16(u);  break;
    case 32: op->lval.udword = inp_uint32(u); break;
    case 64: op->lval.uqword = inp_uint64(u); break;
    default: break;
  }

  /* resolve register encoded in reg field */
  if (opreg) {
    opreg->type = UD_OP_REG;
    opreg->size = resolve_operand_size(u, reg_size);
    if (reg_type == T_GPR) 
        opreg->base = decode_gpr(u, opreg->size, reg);
    else opreg->base = resolve_reg(u, reg_type, reg);
  }
}

/* -----------------------------------------------------------------------------
 * decode_o() - Decodes offset
 * -----------------------------------------------------------------------------
 */
static void 
decode_o(struct ud* u, unsigned int s, struct ud_operand *op)
{
  switch (u->adr_mode) {
    case 64:
        op->offset = 64; 
        op->lval.uqword = inp_uint64(u); 
        break;
    case 32:
        op->offset = 32; 
        op->lval.udword = inp_uint32(u); 
        break;
    case 16:
        op->offset = 16; 
        op->lval.uword  = inp_uint16(u); 
        break;
    default:
        return;
  }
  op->type = UD_OP_MEM;
  op->size = resolve_operand_size(u, s);
}

/* -----------------------------------------------------------------------------
 * disasm_operands() - Disassembles Operands.
 * -----------------------------------------------------------------------------
 */
static int disasm_operands(register struct ud* u)
{


  /* mopXt = map entry, operand X, type; */
  enum ud_operand_code mop1t = u->itab_entry->operand1.type;
  enum ud_operand_code mop2t = u->itab_entry->operand2.type;
  enum ud_operand_code mop3t = u->itab_entry->operand3.type;

  /* mopXs = map entry, operand X, size */
  unsigned int mop1s = u->itab_entry->operand1.size;
  unsigned int mop2s = u->itab_entry->operand2.size;
  unsigned int mop3s = u->itab_entry->operand3.size;

  /* iop = instruction operand */
  register struct ud_operand* iop = u->operand;
    
  switch(mop1t) {
    
    case OP_A :
        decode_a(u, &(iop[0]));
        break;
    
    /* M[b] ... */
    case OP_M :
        if (MODRM_MOD(inp_peek(u)) == 3)
            u->error= 1;
    /* E, G/P/V/I/CL/1/S */
    case OP_E :
        if (mop2t == OP_G) {
            decode_modrm(u, &(iop[0]), mop1s, T_GPR, &(iop[1]), mop2s, T_GPR);
            if (mop3t == OP_I)
                decode_imm(u, mop3s, &(iop[2]));
            else if (mop3t == OP_CL) {
                iop[2].type = UD_OP_REG;
                iop[2].base = UD_R_CL;
                iop[2].size = 8;
            }
        }
        else if (mop2t == OP_P)
            decode_modrm(u, &(iop[0]), mop1s, T_GPR, &(iop[1]), mop2s, T_MMX);
        else if (mop2t == OP_V)
            decode_modrm(u, &(iop[0]), mop1s, T_GPR, &(iop[1]), mop2s, T_XMM);
        else if (mop2t == OP_S)
            decode_modrm(u, &(iop[0]), mop1s, T_GPR, &(iop[1]), mop2s, T_SEG);
        else {
            decode_modrm(u, &(iop[0]), mop1s, T_GPR, NULL, 0, T_NONE);
            if (mop2t == OP_CL) {
                iop[1].type = UD_OP_REG;
                iop[1].base = UD_R_CL;
                iop[1].size = 8;
            } else if (mop2t == OP_I1) {
                iop[1].type = UD_OP_CONST;
                u->operand[1].lval.udword = 1;
            } else if (mop2t == OP_I) {
                decode_imm(u, mop2s, &(iop[1]));
            }
        }
        break;

    /* G, E/PR[,I]/VR */
    case OP_G :
        if (mop2t == OP_M) {
            if (MODRM_MOD(inp_peek(u)) == 3)
                u->error= 1;
            decode_modrm(u, &(iop[1]), mop2s, T_GPR, &(iop[0]), mop1s, T_GPR);
        } else if (mop2t == OP_E) {
            decode_modrm(u, &(iop[1]), mop2s, T_GPR, &(iop[0]), mop1s, T_GPR);
            if (mop3t == OP_I)
                decode_imm(u, mop3s, &(iop[2]));
        } else if (mop2t == OP_PR) {
            decode_modrm(u, &(iop[1]), mop2s, T_MMX, &(iop[0]), mop1s, T_GPR);
            if (mop3t == OP_I)
                decode_imm(u, mop3s, &(iop[2]));
        } else if (mop2t == OP_VR) {
            if (MODRM_MOD(inp_peek(u)) != 3)
                u->error = 1;
            decode_modrm(u, &(iop[1]), mop2s, T_XMM, &(iop[0]), mop1s, T_GPR);
        } else if (mop2t == OP_W)
            decode_modrm(u, &(iop[1]), mop2s, T_XMM, &(iop[0]), mop1s, T_GPR);
        break;

    /* AL..BH, I/O/DX */
    case OP_AL : case OP_CL : case OP_DL : case OP_BL :
    case OP_AH : case OP_CH : case OP_DH : case OP_BH :

        iop[0].type = UD_OP_REG;
        iop[0].base = UD_R_AL + (mop1t - OP_AL);
        iop[0].size = 8;

        if (mop2t == OP_I)
            decode_imm(u, mop2s, &(iop[1]));
        else if (mop2t == OP_DX) {
            iop[1].type = UD_OP_REG;
            iop[1].base = UD_R_DX;
            iop[1].size = 16;
        }
        else if (mop2t == OP_O)
            decode_o(u, mop2s, &(iop[1]));
        break;

    /* rAX[r8]..rDI[r15], I/rAX..rDI/O */
    case OP_rAXr8 : case OP_rCXr9 : case OP_rDXr10 : case OP_rBXr11 :
    case OP_rSPr12: case OP_rBPr13: case OP_rSIr14 : case OP_rDIr15 :
    case OP_rAX : case OP_rCX : case OP_rDX : case OP_rBX :
    case OP_rSP : case OP_rBP : case OP_rSI : case OP_rDI :

        iop[0].type = UD_OP_REG;
        iop[0].base = resolve_gpr64(u, mop1t);

        if (mop2t == OP_I)
            decode_imm(u, mop2s, &(iop[1]));
        else if (mop2t >= OP_rAX && mop2t <= OP_rDI) {
            iop[1].type = UD_OP_REG;
            iop[1].base = resolve_gpr64(u, mop2t);
        }
        else if (mop2t == OP_O) {
            decode_o(u, mop2s, &(iop[1]));  
            iop[0].size = resolve_operand_size(u, mop2s);
        }
        break;

    /* AL[r8b]..BH[r15b], I */
    case OP_ALr8b : case OP_CLr9b : case OP_DLr10b : case OP_BLr11b :
    case OP_AHr12b: case OP_CHr13b: case OP_DHr14b : case OP_BHr15b :
    {
        ud_type_t gpr = (mop1t - OP_ALr8b) + UD_R_AL + 
                        (REX_B(u->pfx_rex) << 3);
        if (UD_R_AH <= gpr && u->pfx_rex)
            gpr = gpr + 4;
        iop[0].type = UD_OP_REG;
        iop[0].base = gpr;
        if (mop2t == OP_I)
            decode_imm(u, mop2s, &(iop[1]));
        break;
    }

    /* eAX..eDX, DX/I */
    case OP_eAX : case OP_eCX : case OP_eDX : case OP_eBX :
    case OP_eSP : case OP_eBP : case OP_eSI : case OP_eDI :
        iop[0].type = UD_OP_REG;
        iop[0].base = resolve_gpr32(u, mop1t);
        if (mop2t == OP_DX) {
            iop[1].type = UD_OP_REG;
            iop[1].base = UD_R_DX;
            iop[1].size = 16;
        } else if (mop2t == OP_I)
            decode_imm(u, mop2s, &(iop[1]));
        break;

    /* ES..GS */
    case OP_ES : case OP_CS : case OP_DS :
    case OP_SS : case OP_FS : case OP_GS :

        /* in 64bits mode, only fs and gs are allowed */
        if (u->dis_mode == 64)
            if (mop1t != OP_FS && mop1t != OP_GS)
                u->error= 1;
        iop[0].type = UD_OP_REG;
        iop[0].base = (mop1t - OP_ES) + UD_R_ES;
        iop[0].size = 16;

        break;

    /* J */
    case OP_J :
        decode_imm(u, mop1s, &(iop[0]));        
        iop[0].type = UD_OP_JIMM;
        break ;

    /* PR, I */
    case OP_PR:
        if (MODRM_MOD(inp_peek(u)) != 3)
            u->error = 1;
        decode_modrm(u, &(iop[0]), mop1s, T_MMX, NULL, 0, T_NONE);
        if (mop2t == OP_I)
            decode_imm(u, mop2s, &(iop[1]));
        break; 

    /* VR, I */
    case OP_VR:
        if (MODRM_MOD(inp_peek(u)) != 3)
            u->error = 1;
        decode_modrm(u, &(iop[0]), mop1s, T_XMM, NULL, 0, T_NONE);
        if (mop2t == OP_I)
            decode_imm(u, mop2s, &(iop[1]));
        break; 

    /* P, Q[,I]/W/E[,I],VR */
    case OP_P :
        if (mop2t == OP_Q) {
            decode_modrm(u, &(iop[1]), mop2s, T_MMX, &(iop[0]), mop1s, T_MMX);
            if (mop3t == OP_I)
                decode_imm(u, mop3s, &(iop[2]));
        } else if (mop2t == OP_W) {
            decode_modrm(u, &(iop[1]), mop2s, T_XMM, &(iop[0]), mop1s, T_MMX);
        } else if (mop2t == OP_VR) {
            if (MODRM_MOD(inp_peek(u)) != 3)
                u->error = 1;
            decode_modrm(u, &(iop[1]), mop2s, T_XMM, &(iop[0]), mop1s, T_MMX);
        } else if (mop2t == OP_E) {
            decode_modrm(u, &(iop[1]), mop2s, T_GPR, &(iop[0]), mop1s, T_MMX);
            if (mop3t == OP_I)
                decode_imm(u, mop3s, &(iop[2]));
        }
        break;

    /* R, C/D */
    case OP_R :
        if (mop2t == OP_C)
            decode_modrm(u, &(iop[0]), mop1s, T_GPR, &(iop[1]), mop2s, T_CRG);
        else if (mop2t == OP_D)
            decode_modrm(u, &(iop[0]), mop1s, T_GPR, &(iop[1]), mop2s, T_DBG);
        break;

    /* C, R */
    case OP_C :
        decode_modrm(u, &(iop[1]), mop2s, T_GPR, &(iop[0]), mop1s, T_CRG);
        break;

    /* D, R */
    case OP_D :
        decode_modrm(u, &(iop[1]), mop2s, T_GPR, &(iop[0]), mop1s, T_DBG);
        break;

    /* Q, P */
    case OP_Q :
        decode_modrm(u, &(iop[0]), mop1s, T_MMX, &(iop[1]), mop2s, T_MMX);
        break;

    /* S, E */
    case OP_S :
        decode_modrm(u, &(iop[1]), mop2s, T_GPR, &(iop[0]), mop1s, T_SEG);
        break;

    /* W, V */
    case OP_W :
        decode_modrm(u, &(iop[0]), mop1s, T_XMM, &(iop[1]), mop2s, T_XMM);
        break;

    /* V, W[,I]/Q/M/E */
    case OP_V :
        if (mop2t == OP_W) {
            /* special cases for movlps and movhps */
            if (MODRM_MOD(inp_peek(u)) == 3) {
                if (u->mnemonic == UD_Imovlps)
                    u->mnemonic = UD_Imovhlps;
                else
                if (u->mnemonic == UD_Imovhps)
                    u->mnemonic = UD_Imovlhps;
            }
            decode_modrm(u, &(iop[1]), mop2s, T_XMM, &(iop[0]), mop1s, T_XMM);
            if (mop3t == OP_I)
                decode_imm(u, mop3s, &(iop[2]));
        } else if (mop2t == OP_Q)
            decode_modrm(u, &(iop[1]), mop2s, T_MMX, &(iop[0]), mop1s, T_XMM);
        else if (mop2t == OP_M) {
            if (MODRM_MOD(inp_peek(u)) == 3)
                u->error= 1;
            decode_modrm(u, &(iop[1]), mop2s, T_GPR, &(iop[0]), mop1s, T_XMM);
        } else if (mop2t == OP_E) {
            decode_modrm(u, &(iop[1]), mop2s, T_GPR, &(iop[0]), mop1s, T_XMM);
        } else if (mop2t == OP_PR) {
            decode_modrm(u, &(iop[1]), mop2s, T_MMX, &(iop[0]), mop1s, T_XMM);
        }
        break;

    /* DX, eAX/AL */
    case OP_DX :
        iop[0].type = UD_OP_REG;
        iop[0].base = UD_R_DX;
        iop[0].size = 16;

        if (mop2t == OP_eAX) {
            iop[1].type = UD_OP_REG;    
            iop[1].base = resolve_gpr32(u, mop2t);
        } else if (mop2t == OP_AL) {
            iop[1].type = UD_OP_REG;
            iop[1].base = UD_R_AL;
            iop[1].size = 8;
        }

        break;

    /* I, I/AL/eAX */
    case OP_I :
        decode_imm(u, mop1s, &(iop[0]));
        if (mop2t == OP_I)
            decode_imm(u, mop2s, &(iop[1]));
        else if (mop2t == OP_AL) {
            iop[1].type = UD_OP_REG;
            iop[1].base = UD_R_AL;
            iop[1].size = 16;
        } else if (mop2t == OP_eAX) {
            iop[1].type = UD_OP_REG;    
            iop[1].base = resolve_gpr32(u, mop2t);
        }
        break;

    /* O, AL/eAX */
    case OP_O :
        decode_o(u, mop1s, &(iop[0]));
        iop[1].type = UD_OP_REG;
        iop[1].size = resolve_operand_size(u, mop1s);
        if (mop2t == OP_AL)
            iop[1].base = UD_R_AL;
        else if (mop2t == OP_eAX)
            iop[1].base = resolve_gpr32(u, mop2t);
        else if (mop2t == OP_rAX)
            iop[1].base = resolve_gpr64(u, mop2t);      
        break;

    /* 3 */
    case OP_I3 :
        iop[0].type = UD_OP_CONST;
        iop[0].lval.sbyte = 3;
        break;

    /* ST(n), ST(n) */
    case OP_ST0 : case OP_ST1 : case OP_ST2 : case OP_ST3 :
    case OP_ST4 : case OP_ST5 : case OP_ST6 : case OP_ST7 :

        iop[0].type = UD_OP_REG;
        iop[0].base = (mop1t-OP_ST0) + UD_R_ST0;
        iop[0].size = 0;

        if (mop2t >= OP_ST0 && mop2t <= OP_ST7) {
            iop[1].type = UD_OP_REG;
            iop[1].base = (mop2t-OP_ST0) + UD_R_ST0;
            iop[1].size = 0;
        }
        break;

    /* AX */
    case OP_AX:
        iop[0].type = UD_OP_REG;
        iop[0].base = UD_R_AX;
        iop[0].size = 16;
        break;

    /* none */
    default :
        iop[0].type = iop[1].type = iop[2].type = UD_NONE;
  }

  return 0;
}

/* -----------------------------------------------------------------------------
 * clear_insn() - clear instruction pointer 
 * -----------------------------------------------------------------------------
 */
static int clear_insn(register struct ud* u)
{
  char *msp; unsigned mslen;
  u->error     = 0;
  u->pfx_seg   = 0;
  u->pfx_opr   = 0;
  u->pfx_adr   = 0;
  u->pfx_lock  = 0;
  u->pfx_repne = 0;
  u->pfx_rep   = 0;
  u->pfx_repe  = 0;
  u->pfx_seg   = 0;
  u->pfx_rex   = 0;
  u->pfx_insn  = 0;
  u->mnemonic  = UD_Inone;
  u->itab_entry = NULL;

  for (msp = (char*)&u->operand, mslen = sizeof u->operand;
       mslen > 0; --mslen) {
    *msp++ = 0;
  }

  return 0;
}

static int do_mode( struct ud* u )
{
  /* if in error state, bail out */
  if ( u->error ) return -1; 

  /* propagate perfix effects */
  if ( u->dis_mode == 64 ) {  /* set 64bit-mode flags */

    /* Check validity of  instruction m64 */
    if ( P_INV64( u->itab_entry->prefix ) ) {
        u->error = 1;
        return -1;
    }

    /* effective rex prefix is the  effective mask for the 
     * instruction hard-coded in the opcode map.
     */
    u->pfx_rex = ( u->pfx_rex & 0x40 ) | 
                 ( u->pfx_rex & REX_PFX_MASK( u->itab_entry->prefix ) ); 

    /* whether this instruction has a default operand size of 
     * 64bit, also hardcoded into the opcode map.
     */
    u->default64 = P_DEF64( u->itab_entry->prefix ); 
    /* calculate effective operand size */
    if ( REX_W( u->pfx_rex ) ) {
        u->opr_mode = 64;
    } else if ( u->pfx_opr ) {
        u->opr_mode = 16;
    } else {
        /* unless the default opr size of instruction is 64,
         * the effective operand size in the absence of rex.w
         * prefix is 32.
         */
        u->opr_mode = ( u->default64 ) ? 64 : 32;
    }

    /* calculate effective address size */
    u->adr_mode = (u->pfx_adr) ? 32 : 64;
  } else if ( u->dis_mode == 32 ) { /* set 32bit-mode flags */
    u->opr_mode = ( u->pfx_opr ) ? 16 : 32;
    u->adr_mode = ( u->pfx_adr ) ? 16 : 32;
  } else if ( u->dis_mode == 16 ) { /* set 16bit-mode flags */
    u->opr_mode = ( u->pfx_opr ) ? 32 : 16;
    u->adr_mode = ( u->pfx_adr ) ? 32 : 16;
  }

  /* These flags determine which operand to apply the operand size
   * cast to.
   */
  u->c1 = ( P_C1( u->itab_entry->prefix ) ) ? 1 : 0;
  u->c2 = ( P_C2( u->itab_entry->prefix ) ) ? 1 : 0;
  u->c3 = ( P_C3( u->itab_entry->prefix ) ) ? 1 : 0;

  /* set flags for implicit addressing */
  u->implicit_addr = P_IMPADDR( u->itab_entry->prefix );

  return 0;
}

#if USE_PTS
#define gen_hex(u) do {} while(0)
#else
static int gen_hex( struct ud *u )
{
  unsigned int i;
  unsigned char *src_ptr = inp_sess( u );
  char* src_hex;

  /* bail out if in error stat. */
  if ( u->error ) return -1; 
  /* output buffer pointe */
  src_hex = ( char* ) u->insn_hexcode;
  /* for each byte used to decode instruction */
  for ( i = 0; i < u->inp_ctr; ++i, ++src_ptr) {
    sprintf( src_hex, "%02x", *src_ptr & 0xFF );
    src_hex += 2;
  }
  return 0;
}
#endif

/* =============================================================================
 * ud_decode() - Instruction decoder. Returns the number of bytes decoded.
 * =============================================================================
 */
unsigned int ud_decode( struct ud* u )
{
  inp_start(u);

  if ( clear_insn( u ) ) {
    ; /* error */
  } else if ( get_prefixes( u ) != 0 ) {
    ; /* error */
  } else if ( search_itab( u ) != 0 ) {
    ; /* error */
  } else if ( do_mode( u ) != 0 ) {
    ; /* error */
  } else if ( disasm_operands( u ) != 0 ) {
    ; /* error */
  } else if ( resolve_mnemonic( u ) != 0 ) {
    ; /* error */
  }

  /* Handle decode error. */
  if ( u->error ) {
    /* clear out the decode data. */
    clear_insn( u );
    /* mark the sequence of bytes as invalid. */
    u->itab_entry = & ie_invalid;
    u->mnemonic = u->itab_entry->mnemonic;
  } 

  u->insn_offset = u->pc; /* set offset of instruction */
  u->insn_fill = 0;   /* set translation buffer index to 0 */
  u->pc += u->inp_ctr;    /* move program counter by bytes decoded */
  gen_hex( u );       /* generate hex code */

  /* return number of bytes disassembled. */
  return u->inp_ctr;
}

/* vim:cindent
 * vim:ts=4
 * vim:sw=4
 * vim:expandtab
 */
/* -----------------------------------------------------------------------------
 * input.c
 *
 * Copyright (c) 2004, 2005, 2006, Vivek Mohan <vivek@sig9.com>
 * All rights reserved. See LICENSE
 * -----------------------------------------------------------------------------
 */
#if USE_PTS
#else
#include "extern.h"
#include "types.h"
#include "input.h"
#endif

/* -----------------------------------------------------------------------------
 * inp_buff_hook() - Hook for buffered inputs.
 * -----------------------------------------------------------------------------
 */
static int 
inp_buff_hook(struct ud* u)
{
  if (u->inp_buff < u->inp_buff_end)
	return *u->inp_buff++;
  else	return -1;
}

#ifndef __UD_STANDALONE__
/* -----------------------------------------------------------------------------
 * inp_file_hook() - Hook for FILE inputs.
 * -----------------------------------------------------------------------------
 */
static int 
inp_file_hook(struct ud* u)
{
  return fgetc(u->inp_file);
}
#endif /* __UD_STANDALONE__*/

/* =============================================================================
 * ud_inp_set_hook() - Sets input hook.
 * =============================================================================
 */
extern void 
ud_set_input_hook(register struct ud* u, int (*hook)(struct ud*))
{
  u->inp_hook = hook;
  inp_init(u);
}

/* =============================================================================
 * ud_inp_set_buffer() - Set buffer as input.
 * =============================================================================
 */
extern void 
ud_set_input_buffer(register struct ud* u, uint8_t* buf, size_t len)
{
  u->inp_hook = inp_buff_hook;
  u->inp_buff = buf;
  u->inp_buff_end = buf + len;
  inp_init(u);
}

#ifndef __UD_STANDALONE__
/* =============================================================================
 * ud_input_set_file() - Set buffer as input.
 * =============================================================================
 */
extern void 
ud_set_input_file(register struct ud* u, FILE* f)
{
  u->inp_hook = inp_file_hook;
  u->inp_file = f;
  inp_init(u);
}
#endif /* __UD_STANDALONE__ */

/* =============================================================================
 * ud_input_skip() - Skip n input bytes.
 * =============================================================================
 */
extern void 
ud_input_skip(struct ud* u, size_t n)
{
  while (n--) {
	u->inp_hook(u);
  }
}

/* =============================================================================
 * ud_input_end() - Test for end of input.
 * =============================================================================
 */
extern int 
ud_input_end(struct ud* u)
{
  return (u->inp_curr == u->inp_fill) && u->inp_end;
}

/* -----------------------------------------------------------------------------
 * inp_next() - Loads and returns the next byte from input.
 *
 * inp_curr and inp_fill are pointers to the cache. The program is written based
 * on the property that they are 8-bits in size, and will eventually wrap around
 * forming a circular buffer. So, the size of the cache is 256 in size, kind of
 * unnecessary yet optimized.
 *
 * A buffer inp_sess stores the bytes disassembled for a single session.
 * -----------------------------------------------------------------------------
 */
extern uint8_t inp_next(struct ud* u) 
{
  int c = -1;
  /* if current pointer is not upto the fill point in the 
   * input cache.
   */
  if ( u->inp_curr != u->inp_fill ) {
	c = u->inp_cache[ ++u->inp_curr ];
  /* if !end-of-input, call the input hook and get a byte */
  } else if ( u->inp_end || ( c = u->inp_hook( u ) ) == -1 ) {
	/* end-of-input, mark it as an error, since the decoder,
	 * expected a byte more.
	 */
	u->error = 1;
	/* flag end of input */
	u->inp_end = 1;
	return 0;
  } else {
	/* increment pointers, we have a new byte.  */
	u->inp_curr = ++u->inp_fill;
	/* add the byte to the cache */
	u->inp_cache[ u->inp_fill ] = c;
  }
  /* record bytes input per decode-session. */
  u->inp_sess[ u->inp_ctr++ ] = c;
  /* return byte */
  return ( uint8_t ) c;
}

/* -----------------------------------------------------------------------------
 * inp_back() - Move back a single byte in the stream.
 * -----------------------------------------------------------------------------
 */
extern void
inp_back(struct ud* u) 
{
  if ( u->inp_ctr > 0 ) {
	--u->inp_curr;
	--u->inp_ctr;
  }
}

/* -----------------------------------------------------------------------------
 * inp_peek() - Peek into the next byte in source. 
 * -----------------------------------------------------------------------------
 */
extern uint8_t
inp_peek(struct ud* u) 
{
  uint8_t r = inp_next(u);
  if ( !u->error ) inp_back(u); /* Don't backup if there was an error */
  return r;
}

/* -----------------------------------------------------------------------------
 * inp_move() - Move ahead n input bytes.
 * -----------------------------------------------------------------------------
 */
extern void
inp_move(struct ud* u, size_t n) 
{
  while (n--)
	inp_next(u);
}

/*------------------------------------------------------------------------------
 *  inp_uintN() - return uintN from source.
 *------------------------------------------------------------------------------
 */
extern uint8_t 
inp_uint8(struct ud* u)
{
  return inp_next(u);
}

extern uint16_t 
inp_uint16(struct ud* u)
{
  uint16_t r, ret;

  ret = inp_next(u);
  r = inp_next(u);
  return ret | (r << 8);
}

extern uint32_t 
inp_uint32(struct ud* u)
{
  uint32_t r, ret;

  ret = inp_next(u);
  r = inp_next(u);
  ret = ret | (r << 8);
  r = inp_next(u);
  ret = ret | (r << 16);
  r = inp_next(u);
  return ret | (r << 24);
}

extern uint64_t 
inp_uint64(struct ud* u)
{
  uint64_t r, ret;

  ret = inp_next(u);
  r = inp_next(u);
  ret = ret | (r << 8);
  r = inp_next(u);
  ret = ret | (r << 16);
  r = inp_next(u);
  ret = ret | (r << 24);
  r = inp_next(u);
  ret = ret | (r << 32);
  r = inp_next(u);
  ret = ret | (r << 40);
  r = inp_next(u);
  ret = ret | (r << 48);
  r = inp_next(u);
  return ret | (r << 56);
}

/* itab.c -- auto generated by opgen.py, do not edit. */

#if USE_PTS
#else
#include "types.h"
#include "itab.h"
#include "decode.h"
#endif

const char * ud_mnemonics_str[] = {
  "3dnow",
  "aaa",
  "aad",
  "aam",
  "aas",
  "adc",
  "add",
  "addpd",
  "addps",
  "addsd",
  "addss",
  "addsubpd",
  "addsubps",
  "and",
  "andpd",
  "andps",
  "andnpd",
  "andnps",
  "arpl",
  "movsxd",
  "bound",
  "bsf",
  "bsr",
  "bswap",
  "bt",
  "btc",
  "btr",
  "bts",
  "call",
  "cbw",
  "cwde",
  "cdqe",
  "clc",
  "cld",
  "clflush",
  "clgi",
  "cli",
  "clts",
  "cmc",
  "cmovo",
  "cmovno",
  "cmovb",
  "cmovae",
  "cmovz",
  "cmovnz",
  "cmovbe",
  "cmova",
  "cmovs",
  "cmovns",
  "cmovp",
  "cmovnp",
  "cmovl",
  "cmovge",
  "cmovle",
  "cmovg",
  "cmp",
  "cmppd",
  "cmpps",
  "cmpsb",
  "cmpsw",
  "cmpsd",
  "cmpsq",
  "cmpss",
  "cmpxchg",
  "cmpxchg8b",
  "comisd",
  "comiss",
  "cpuid",
  "cvtdq2pd",
  "cvtdq2ps",
  "cvtpd2dq",
  "cvtpd2pi",
  "cvtpd2ps",
  "cvtpi2ps",
  "cvtpi2pd",
  "cvtps2dq",
  "cvtps2pi",
  "cvtps2pd",
  "cvtsd2si",
  "cvtsd2ss",
  "cvtsi2ss",
  "cvtss2si",
  "cvtss2sd",
  "cvttpd2pi",
  "cvttpd2dq",
  "cvttps2dq",
  "cvttps2pi",
  "cvttsd2si",
  "cvtsi2sd",
  "cvttss2si",
  "cwd",
  "cdq",
  "cqo",
  "daa",
  "das",
  "dec",
  "div",
  "divpd",
  "divps",
  "divsd",
  "divss",
  "emms",
  "enter",
  "f2xm1",
  "fabs",
  "fadd",
  "faddp",
  "fbld",
  "fbstp",
  "fchs",
  "fclex",
  "fcmovb",
  "fcmove",
  "fcmovbe",
  "fcmovu",
  "fcmovnb",
  "fcmovne",
  "fcmovnbe",
  "fcmovnu",
  "fucomi",
  "fcom",
  "fcom2",
  "fcomp3",
  "fcomi",
  "fucomip",
  "fcomip",
  "fcomp",
  "fcomp5",
  "fcompp",
  "fcos",
  "fdecstp",
  "fdiv",
  "fdivp",
  "fdivr",
  "fdivrp",
  "femms",
  "ffree",
  "ffreep",
  "ficom",
  "ficomp",
  "fild",
  "fncstp",
  "fninit",
  "fiadd",
  "fidivr",
  "fidiv",
  "fisub",
  "fisubr",
  "fist",
  "fistp",
  "fisttp",
  "fld",
  "fld1",
  "fldl2t",
  "fldl2e",
  "fldlpi",
  "fldlg2",
  "fldln2",
  "fldz",
  "fldcw",
  "fldenv",
  "fmul",
  "fmulp",
  "fimul",
  "fnop",
  "fpatan",
  "fprem",
  "fprem1",
  "fptan",
  "frndint",
  "frstor",
  "fnsave",
  "fscale",
  "fsin",
  "fsincos",
  "fsqrt",
  "fstp",
  "fstp1",
  "fstp8",
  "fstp9",
  "fst",
  "fnstcw",
  "fnstenv",
  "fnstsw",
  "fsub",
  "fsubp",
  "fsubr",
  "fsubrp",
  "ftst",
  "fucom",
  "fucomp",
  "fucompp",
  "fxam",
  "fxch",
  "fxch4",
  "fxch7",
  "fxrstor",
  "fxsave",
  "fpxtract",
  "fyl2x",
  "fyl2xp1",
  "haddpd",
  "haddps",
  "hlt",
  "hsubpd",
  "hsubps",
  "idiv",
  "in",
  "imul",
  "inc",
  "insb",
  "insw",
  "insd",
  "int1",
  "int3",
  "int",
  "into",
  "invd",
  "invlpg",
  "invlpga",
  "iretw",
  "iretd",
  "iretq",
  "jo",
  "jno",
  "jb",
  "jae",
  "jz",
  "jnz",
  "jbe",
  "ja",
  "js",
  "jns",
  "jp",
  "jnp",
  "jl",
  "jge",
  "jle",
  "jg",
  "jcxz",
  "jecxz",
  "jrcxz",
  "jmp",
  "lahf",
  "lar",
  "lddqu",
  "ldmxcsr",
  "lds",
  "lea",
  "les",
  "lfs",
  "lgs",
  "lidt",
  "lss",
  "leave",
  "lfence",
  "lgdt",
  "lldt",
  "lmsw",
  "lock",
  "lodsb",
  "lodsw",
  "lodsd",
  "lodsq",
  "loopnz",
  "loope",
  "loop",
  "lsl",
  "ltr",
  "maskmovq",
  "maxpd",
  "maxps",
  "maxsd",
  "maxss",
  "mfence",
  "minpd",
  "minps",
  "minsd",
  "minss",
  "monitor",
  "mov",
  "movapd",
  "movaps",
  "movd",
  "movddup",
  "movdqa",
  "movdqu",
  "movdq2q",
  "movhpd",
  "movhps",
  "movlhps",
  "movlpd",
  "movlps",
  "movhlps",
  "movmskpd",
  "movmskps",
  "movntdq",
  "movnti",
  "movntpd",
  "movntps",
  "movntq",
  "movq",
  "movqa",
  "movq2dq",
  "movsb",
  "movsw",
  "movsd",
  "movsq",
  "movsldup",
  "movshdup",
  "movss",
  "movsx",
  "movupd",
  "movups",
  "movzx",
  "mul",
  "mulpd",
  "mulps",
  "mulsd",
  "mulss",
  "mwait",
  "neg",
  "nop",
  "not",
  "or",
  "orpd",
  "orps",
  "out",
  "outsb",
  "outsw",
  "outsd",
  "outsq",
  "packsswb",
  "packssdw",
  "packuswb",
  "paddb",
  "paddw",
  "paddq",
  "paddsb",
  "paddsw",
  "paddusb",
  "paddusw",
  "pand",
  "pandn",
  "pause",
  "pavgb",
  "pavgw",
  "pcmpeqb",
  "pcmpeqw",
  "pcmpeqd",
  "pcmpgtb",
  "pcmpgtw",
  "pcmpgtd",
  "pextrw",
  "pinsrw",
  "pmaddwd",
  "pmaxsw",
  "pmaxub",
  "pminsw",
  "pminub",
  "pmovmskb",
  "pmulhuw",
  "pmulhw",
  "pmullw",
  "pmuludq",
  "pop",
  "popa",
  "popad",
  "popfw",
  "popfd",
  "popfq",
  "por",
  "prefetch",
  "prefetchnta",
  "prefetcht0",
  "prefetcht1",
  "prefetcht2",
  "psadbw",
  "pshufd",
  "pshufhw",
  "pshuflw",
  "pshufw",
  "pslldq",
  "psllw",
  "pslld",
  "psllq",
  "psraw",
  "psrad",
  "psrlw",
  "psrld",
  "psrlq",
  "psrldq",
  "psubb",
  "psubw",
  "psubd",
  "psubq",
  "psubsb",
  "psubsw",
  "psubusb",
  "psubusw",
  "punpckhbw",
  "punpckhwd",
  "punpckhdq",
  "punpckhqdq",
  "punpcklbw",
  "punpcklwd",
  "punpckldq",
  "punpcklqdq",
  "pi2fw",
  "pi2fd",
  "pf2iw",
  "pf2id",
  "pfnacc",
  "pfpnacc",
  "pfcmpge",
  "pfmin",
  "pfrcp",
  "pfrsqrt",
  "pfsub",
  "pfadd",
  "pfcmpgt",
  "pfmax",
  "pfrcpit1",
  "pfrspit1",
  "pfsubr",
  "pfacc",
  "pfcmpeq",
  "pfmul",
  "pfrcpit2",
  "pmulhrw",
  "pswapd",
  "pavgusb",
  "push",
  "pusha",
  "pushad",
  "pushfw",
  "pushfd",
  "pushfq",
  "pxor",
  "rcl",
  "rcr",
  "rol",
  "ror",
  "rcpps",
  "rcpss",
  "rdmsr",
  "rdpmc",
  "rdtsc",
  "rdtscp",
  "repne",
  "rep",
  "ret",
  "retf",
  "rsm",
  "rsqrtps",
  "rsqrtss",
  "sahf",
  "sal",
  "salc",
  "sar",
  "shl",
  "shr",
  "sbb",
  "scasb",
  "scasw",
  "scasd",
  "scasq",
  "seto",
  "setno",
  "setb",
  "setnb",
  "setz",
  "setnz",
  "setbe",
  "seta",
  "sets",
  "setns",
  "setp",
  "setnp",
  "setl",
  "setge",
  "setle",
  "setg",
  "sfence",
  "sgdt",
  "shld",
  "shrd",
  "shufpd",
  "shufps",
  "sidt",
  "sldt",
  "smsw",
  "sqrtps",
  "sqrtpd",
  "sqrtsd",
  "sqrtss",
  "stc",
  "std",
  "stgi",
  "sti",
  "skinit",
  "stmxcsr",
  "stosb",
  "stosw",
  "stosd",
  "stosq",
  "str",
  "sub",
  "subpd",
  "subps",
  "subsd",
  "subss",
  "swapgs",
  "syscall",
  "sysenter",
  "sysexit",
  "sysret",
  "test",
  "ucomisd",
  "ucomiss",
  "ud2",
  "unpckhpd",
  "unpckhps",
  "unpcklps",
  "unpcklpd",
  "verr",
  "verw",
  "vmcall",
  "vmclear",
  "vmxon",
  "vmptrld",
  "vmptrst",
  "vmresume",
  "vmxoff",
  "vmrun",
  "vmmcall",
  "vmload",
  "vmsave",
  "wait",
  "wbinvd",
  "wrmsr",
  "xadd",
  "xchg",
  "xlatb",
  "xor",
  "xorpd",
  "xorps",
  "db",
  "invalid",
};



static struct ud_itab_entry itab__0f[256] = {
  /* 00 */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_00__REG },
  /* 01 */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_01__REG },
  /* 02 */  { UD_Ilar,         O_Gv,    O_Ew,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 03 */  { UD_Ilsl,         O_Gv,    O_Ew,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 04 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 05 */  { UD_Isyscall,     O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 06 */  { UD_Iclts,        O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 07 */  { UD_Isysret,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 08 */  { UD_Iinvd,        O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 09 */  { UD_Iwbinvd,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 0A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 0B */  { UD_Iud2,         O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 0C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 0D */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_0D__REG },
  /* 0E */  { UD_Ifemms,       O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 0F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 10 */  { UD_Imovups,      O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 11 */  { UD_Imovups,      O_W,     O_V,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 12 */  { UD_Imovlps,      O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 13 */  { UD_Imovlps,      O_M,     O_V,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 14 */  { UD_Iunpcklps,    O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 15 */  { UD_Iunpckhps,    O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 16 */  { UD_Imovhps,      O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 17 */  { UD_Imovhps,      O_M,     O_V,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 18 */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_18__REG },
  /* 19 */  { UD_Inop,         O_M,     O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 1A */  { UD_Inop,         O_M,     O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 1B */  { UD_Inop,         O_M,     O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 1C */  { UD_Inop,         O_M,     O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 1D */  { UD_Inop,         O_M,     O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 1E */  { UD_Inop,         O_M,     O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 1F */  { UD_Inop,         O_M,     O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 20 */  { UD_Imov,         O_R,     O_C,     O_NONE,  P_rexr },
  /* 21 */  { UD_Imov,         O_R,     O_D,     O_NONE,  P_rexr },
  /* 22 */  { UD_Imov,         O_C,     O_R,     O_NONE,  P_rexr },
  /* 23 */  { UD_Imov,         O_D,     O_R,     O_NONE,  P_rexr },
  /* 24 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 25 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 26 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 27 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 28 */  { UD_Imovaps,      O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 29 */  { UD_Imovaps,      O_W,     O_V,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 2A */  { UD_Icvtpi2ps,    O_V,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 2B */  { UD_Imovntps,     O_M,     O_V,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 2C */  { UD_Icvttps2pi,   O_P,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 2D */  { UD_Icvtps2pi,    O_P,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 2E */  { UD_Iucomiss,     O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 2F */  { UD_Icomiss,      O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 30 */  { UD_Iwrmsr,       O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 31 */  { UD_Irdtsc,       O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 32 */  { UD_Irdmsr,       O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 33 */  { UD_Irdpmc,       O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 34 */  { UD_Isysenter,    O_NONE,  O_NONE,  O_NONE,  P_inv64|P_none },
  /* 35 */  { UD_Isysexit,     O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 36 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 37 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 38 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 39 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 40 */  { UD_Icmovo,       O_Gv,    O_Ev,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 41 */  { UD_Icmovno,      O_Gv,    O_Ev,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 42 */  { UD_Icmovb,       O_Gv,    O_Ev,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 43 */  { UD_Icmovae,      O_Gv,    O_Ev,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 44 */  { UD_Icmovz,       O_Gv,    O_Ev,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 45 */  { UD_Icmovnz,      O_Gv,    O_Ev,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 46 */  { UD_Icmovbe,      O_Gv,    O_Ev,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 47 */  { UD_Icmova,       O_Gv,    O_Ev,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 48 */  { UD_Icmovs,       O_Gv,    O_Ev,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 49 */  { UD_Icmovns,      O_Gv,    O_Ev,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 4A */  { UD_Icmovp,       O_Gv,    O_Ev,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 4B */  { UD_Icmovnp,      O_Gv,    O_Ev,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 4C */  { UD_Icmovl,       O_Gv,    O_Ev,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 4D */  { UD_Icmovge,      O_Gv,    O_Ev,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 4E */  { UD_Icmovle,      O_Gv,    O_Ev,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 4F */  { UD_Icmovg,       O_Gv,    O_Ev,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 50 */  { UD_Imovmskps,    O_Gd,    O_VR,    O_NONE,  P_oso|P_rexr|P_rexb },
  /* 51 */  { UD_Isqrtps,      O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 52 */  { UD_Irsqrtps,     O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 53 */  { UD_Ircpps,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 54 */  { UD_Iandps,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 55 */  { UD_Iandnps,      O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 56 */  { UD_Iorps,        O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 57 */  { UD_Ixorps,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 58 */  { UD_Iaddps,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 59 */  { UD_Imulps,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 5A */  { UD_Icvtps2pd,    O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 5B */  { UD_Icvtdq2ps,    O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 5C */  { UD_Isubps,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 5D */  { UD_Iminps,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 5E */  { UD_Idivps,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 5F */  { UD_Imaxps,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 60 */  { UD_Ipunpcklbw,   O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 61 */  { UD_Ipunpcklwd,   O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 62 */  { UD_Ipunpckldq,   O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 63 */  { UD_Ipacksswb,    O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 64 */  { UD_Ipcmpgtb,     O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 65 */  { UD_Ipcmpgtw,     O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 66 */  { UD_Ipcmpgtd,     O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 67 */  { UD_Ipackuswb,    O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 68 */  { UD_Ipunpckhbw,   O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 69 */  { UD_Ipunpckhwd,   O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 6A */  { UD_Ipunpckhdq,   O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 6B */  { UD_Ipackssdw,    O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 6C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 6D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 6E */  { UD_Imovd,        O_P,     O_Ex,    O_NONE,  P_c2|P_aso|P_rexr|P_rexx|P_rexb },
  /* 6F */  { UD_Imovq,        O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 70 */  { UD_Ipshufw,      O_P,     O_Q,     O_Ib,    P_aso|P_rexr|P_rexx|P_rexb },
  /* 71 */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_71__REG },
  /* 72 */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_72__REG },
  /* 73 */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_73__REG },
  /* 74 */  { UD_Ipcmpeqb,     O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 75 */  { UD_Ipcmpeqw,     O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 76 */  { UD_Ipcmpeqd,     O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 77 */  { UD_Iemms,        O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 78 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 79 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 7A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 7B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 7C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 7D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 7E */  { UD_Imovd,        O_Ex,    O_P,     O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 7F */  { UD_Imovq,        O_Q,     O_P,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 80 */  { UD_Ijo,          O_Jz,    O_NONE,  O_NONE,  P_c1|P_def64|P_depM|P_oso },
  /* 81 */  { UD_Ijno,         O_Jz,    O_NONE,  O_NONE,  P_c1|P_def64|P_depM|P_oso },
  /* 82 */  { UD_Ijb,          O_Jz,    O_NONE,  O_NONE,  P_c1|P_def64|P_depM|P_oso },
  /* 83 */  { UD_Ijae,         O_Jz,    O_NONE,  O_NONE,  P_c1|P_def64|P_depM|P_oso },
  /* 84 */  { UD_Ijz,          O_Jz,    O_NONE,  O_NONE,  P_c1|P_def64|P_depM|P_oso },
  /* 85 */  { UD_Ijnz,         O_Jz,    O_NONE,  O_NONE,  P_c1|P_def64|P_depM|P_oso },
  /* 86 */  { UD_Ijbe,         O_Jz,    O_NONE,  O_NONE,  P_c1|P_def64|P_depM|P_oso },
  /* 87 */  { UD_Ija,          O_Jz,    O_NONE,  O_NONE,  P_c1|P_def64|P_depM|P_oso },
  /* 88 */  { UD_Ijs,          O_Jz,    O_NONE,  O_NONE,  P_c1|P_def64|P_depM|P_oso },
  /* 89 */  { UD_Ijns,         O_Jz,    O_NONE,  O_NONE,  P_c1|P_def64|P_depM|P_oso },
  /* 8A */  { UD_Ijp,          O_Jz,    O_NONE,  O_NONE,  P_c1|P_def64|P_depM|P_oso },
  /* 8B */  { UD_Ijnp,         O_Jz,    O_NONE,  O_NONE,  P_c1|P_def64|P_depM|P_oso },
  /* 8C */  { UD_Ijl,          O_Jz,    O_NONE,  O_NONE,  P_c1|P_def64|P_depM|P_oso },
  /* 8D */  { UD_Ijge,         O_Jz,    O_NONE,  O_NONE,  P_c1|P_def64|P_depM|P_oso },
  /* 8E */  { UD_Ijle,         O_Jz,    O_NONE,  O_NONE,  P_c1|P_def64|P_depM|P_oso },
  /* 8F */  { UD_Ijg,          O_Jz,    O_NONE,  O_NONE,  P_c1|P_def64|P_depM|P_oso },
  /* 90 */  { UD_Iseto,        O_Eb,    O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 91 */  { UD_Isetno,       O_Eb,    O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 92 */  { UD_Isetb,        O_Eb,    O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 93 */  { UD_Isetnb,       O_Eb,    O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 94 */  { UD_Isetz,        O_Eb,    O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 95 */  { UD_Isetnz,       O_Eb,    O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 96 */  { UD_Isetbe,       O_Eb,    O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 97 */  { UD_Iseta,        O_Eb,    O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 98 */  { UD_Isets,        O_Eb,    O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 99 */  { UD_Isetns,       O_Eb,    O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 9A */  { UD_Isetp,        O_Eb,    O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 9B */  { UD_Isetnp,       O_Eb,    O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 9C */  { UD_Isetl,        O_Eb,    O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 9D */  { UD_Isetge,       O_Eb,    O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 9E */  { UD_Isetle,       O_Eb,    O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 9F */  { UD_Isetg,        O_Eb,    O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* A0 */  { UD_Ipush,        O_FS,    O_NONE,  O_NONE,  P_none },
  /* A1 */  { UD_Ipop,         O_FS,    O_NONE,  O_NONE,  P_none },
  /* A2 */  { UD_Icpuid,       O_NONE,  O_NONE,  O_NONE,  P_none },
  /* A3 */  { UD_Ibt,          O_Ev,    O_Gv,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* A4 */  { UD_Ishld,        O_Ev,    O_Gv,    O_Ib,    P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* A5 */  { UD_Ishld,        O_Ev,    O_Gv,    O_CL,    P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* A6 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A7 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A8 */  { UD_Ipush,        O_GS,    O_NONE,  O_NONE,  P_none },
  /* A9 */  { UD_Ipop,         O_GS,    O_NONE,  O_NONE,  P_none },
  /* AA */  { UD_Irsm,         O_NONE,  O_NONE,  O_NONE,  P_none },
  /* AB */  { UD_Ibts,         O_Ev,    O_Gv,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* AC */  { UD_Ishrd,        O_Ev,    O_Gv,    O_Ib,    P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* AD */  { UD_Ishrd,        O_Ev,    O_Gv,    O_CL,    P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* AE */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_AE__REG },
  /* AF */  { UD_Iimul,        O_Gv,    O_Ev,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* B0 */  { UD_Icmpxchg,     O_Eb,    O_Gb,    O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* B1 */  { UD_Icmpxchg,     O_Ev,    O_Gv,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* B2 */  { UD_Ilss,         O_Gz,    O_M,     O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* B3 */  { UD_Ibtr,         O_Ev,    O_Gv,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* B4 */  { UD_Ilfs,         O_Gz,    O_M,     O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* B5 */  { UD_Ilgs,         O_Gz,    O_M,     O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* B6 */  { UD_Imovzx,       O_Gv,    O_Eb,    O_NONE,  P_c2|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* B7 */  { UD_Imovzx,       O_Gv,    O_Ew,    O_NONE,  P_c2|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* B8 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B9 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* BA */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_BA__REG },
  /* BB */  { UD_Ibtc,         O_Ev,    O_Gv,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* BC */  { UD_Ibsf,         O_Gv,    O_Ev,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* BD */  { UD_Ibsr,         O_Gv,    O_Ev,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* BE */  { UD_Imovsx,       O_Gv,    O_Eb,    O_NONE,  P_c2|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* BF */  { UD_Imovsx,       O_Gv,    O_Ew,    O_NONE,  P_c2|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* C0 */  { UD_Ixadd,        O_Eb,    O_Gb,    O_NONE,  P_aso|P_oso|P_rexr|P_rexx|P_rexb },
  /* C1 */  { UD_Ixadd,        O_Ev,    O_Gv,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* C2 */  { UD_Icmpps,       O_V,     O_W,     O_Ib,    P_aso|P_rexr|P_rexx|P_rexb },
  /* C3 */  { UD_Imovnti,      O_M,     O_Gvw,   O_NONE,  P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* C4 */  { UD_Ipinsrw,      O_P,     O_Ew,    O_Ib,    P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* C5 */  { UD_Ipextrw,      O_Gd,    O_PR,    O_Ib,    P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* C6 */  { UD_Ishufps,      O_V,     O_W,     O_Ib,    P_aso|P_rexr|P_rexx|P_rexb },
  /* C7 */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_C7__REG },
  /* C8 */  { UD_Ibswap,       O_rAXr8, O_NONE,  O_NONE,  P_oso|P_rexw|P_rexb },
  /* C9 */  { UD_Ibswap,       O_rCXr9, O_NONE,  O_NONE,  P_oso|P_rexw|P_rexb },
  /* CA */  { UD_Ibswap,       O_rDXr10, O_NONE,  O_NONE, P_oso|P_rexw|P_rexb },
  /* CB */  { UD_Ibswap,       O_rBXr11, O_NONE,  O_NONE, P_oso|P_rexw|P_rexb },
  /* CC */  { UD_Ibswap,       O_rSPr12, O_NONE,  O_NONE, P_oso|P_rexw|P_rexb },
  /* CD */  { UD_Ibswap,       O_rBPr13, O_NONE,  O_NONE, P_oso|P_rexw|P_rexb },
  /* CE */  { UD_Ibswap,       O_rSIr14, O_NONE,  O_NONE, P_oso|P_rexw|P_rexb },
  /* CF */  { UD_Ibswap,       O_rDIr15, O_NONE,  O_NONE, P_oso|P_rexw|P_rexb },
  /* D0 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* D1 */  { UD_Ipsrlw,       O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* D2 */  { UD_Ipsrld,       O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* D3 */  { UD_Ipsrlq,       O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* D4 */  { UD_Ipaddq,       O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* D5 */  { UD_Ipmullw,      O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* D6 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* D7 */  { UD_Ipmovmskb,    O_Gd,    O_PR,    O_NONE,  P_oso|P_rexr|P_rexb },
  /* D8 */  { UD_Ipsubusb,     O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* D9 */  { UD_Ipsubusw,     O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* DA */  { UD_Ipminub,      O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* DB */  { UD_Ipand,        O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* DC */  { UD_Ipaddusb,     O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* DD */  { UD_Ipaddusw,     O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* DE */  { UD_Ipmaxub,      O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* DF */  { UD_Ipandn,       O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* E0 */  { UD_Ipavgb,       O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* E1 */  { UD_Ipsraw,       O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* E2 */  { UD_Ipsrad,       O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* E3 */  { UD_Ipavgw,       O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* E4 */  { UD_Ipmulhuw,     O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* E5 */  { UD_Ipmulhw,      O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* E6 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* E7 */  { UD_Imovntq,      O_M,     O_P,     O_NONE,  P_none },
  /* E8 */  { UD_Ipsubsb,      O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* E9 */  { UD_Ipsubsw,      O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* EA */  { UD_Ipminsw,      O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* EB */  { UD_Ipor,         O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* EC */  { UD_Ipaddsb,      O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* ED */  { UD_Ipaddsw,      O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* EE */  { UD_Ipmaxsw,      O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* EF */  { UD_Ipxor,        O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* F0 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* F1 */  { UD_Ipsllw,       O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* F2 */  { UD_Ipslld,       O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* F3 */  { UD_Ipsllq,       O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* F4 */  { UD_Ipmuludq,     O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* F5 */  { UD_Ipmaddwd,     O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* F6 */  { UD_Ipsadbw,      O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* F7 */  { UD_Imaskmovq,    O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* F8 */  { UD_Ipsubb,       O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* F9 */  { UD_Ipsubw,       O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* FA */  { UD_Ipsubd,       O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* FB */  { UD_Ipsubq,       O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* FC */  { UD_Ipaddb,       O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* FD */  { UD_Ipaddw,       O_P,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* FE */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* FF */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__0f__op_00__reg[8] = {
  /* 00 */  { UD_Isldt,        O_Ev,    O_NONE,  O_NONE,  P_aso|P_oso|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Istr,         O_Ev,    O_NONE,  O_NONE,  P_aso|P_oso|P_rexr|P_rexx|P_rexb },
  /* 02 */  { UD_Illdt,        O_Ew,    O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 03 */  { UD_Iltr,         O_Ew,    O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 04 */  { UD_Iverr,        O_Ew,    O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 05 */  { UD_Iverw,        O_Ew,    O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 06 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 07 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__0f__op_01__reg[8] = {
  /* 00 */  { UD_Igrp_mod,     O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_01__REG__OP_00__MOD },
  /* 01 */  { UD_Igrp_mod,     O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_01__REG__OP_01__MOD },
  /* 02 */  { UD_Igrp_mod,     O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_01__REG__OP_02__MOD },
  /* 03 */  { UD_Igrp_mod,     O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_01__REG__OP_03__MOD },
  /* 04 */  { UD_Igrp_mod,     O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_01__REG__OP_04__MOD },
  /* 05 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 06 */  { UD_Igrp_mod,     O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_01__REG__OP_06__MOD },
  /* 07 */  { UD_Igrp_mod,     O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_01__REG__OP_07__MOD },
};

static struct ud_itab_entry itab__0f__op_01__reg__op_00__mod[2] = {
  /* 00 */  { UD_Isgdt,        O_M,     O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Igrp_rm,      O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_01__REG__OP_00__MOD__OP_01__RM },
};

static struct ud_itab_entry itab__0f__op_01__reg__op_00__mod__op_01__rm[8] = {
  /* 00 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 01 */  { UD_Igrp_vendor,  O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_01__REG__OP_00__MOD__OP_01__RM__OP_01__VENDOR },
  /* 02 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 03 */  { UD_Igrp_vendor,  O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_01__REG__OP_00__MOD__OP_01__RM__OP_03__VENDOR },
  /* 04 */  { UD_Igrp_vendor,  O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_01__REG__OP_00__MOD__OP_01__RM__OP_04__VENDOR },
  /* 05 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 06 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 07 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__0f__op_01__reg__op_00__mod__op_01__rm__op_01__vendor[2] = {
  /* 00 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 01 */  { UD_Ivmcall,      O_NONE,  O_NONE,  O_NONE,  P_none },
};

static struct ud_itab_entry itab__0f__op_01__reg__op_00__mod__op_01__rm__op_03__vendor[2] = {
  /* 00 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 01 */  { UD_Ivmresume,    O_NONE,  O_NONE,  O_NONE,  P_none },
};

static struct ud_itab_entry itab__0f__op_01__reg__op_00__mod__op_01__rm__op_04__vendor[2] = {
  /* 00 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 01 */  { UD_Ivmxoff,      O_NONE,  O_NONE,  O_NONE,  P_none },
};

static struct ud_itab_entry itab__0f__op_01__reg__op_01__mod[2] = {
  /* 00 */  { UD_Isidt,        O_M,     O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Igrp_rm,      O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_01__REG__OP_01__MOD__OP_01__RM },
};

static struct ud_itab_entry itab__0f__op_01__reg__op_01__mod__op_01__rm[8] = {
  /* 00 */  { UD_Imonitor,     O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 01 */  { UD_Imwait,       O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 02 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 03 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 04 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 05 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 06 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 07 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__0f__op_01__reg__op_02__mod[2] = {
  /* 00 */  { UD_Ilgdt,        O_M,     O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__0f__op_01__reg__op_03__mod[2] = {
  /* 00 */  { UD_Ilidt,        O_M,     O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Igrp_rm,      O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_01__REG__OP_03__MOD__OP_01__RM },
};

static struct ud_itab_entry itab__0f__op_01__reg__op_03__mod__op_01__rm[8] = {
  /* 00 */  { UD_Igrp_vendor,  O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_01__REG__OP_03__MOD__OP_01__RM__OP_00__VENDOR },
  /* 01 */  { UD_Igrp_vendor,  O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_01__REG__OP_03__MOD__OP_01__RM__OP_01__VENDOR },
  /* 02 */  { UD_Igrp_vendor,  O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_01__REG__OP_03__MOD__OP_01__RM__OP_02__VENDOR },
  /* 03 */  { UD_Igrp_vendor,  O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_01__REG__OP_03__MOD__OP_01__RM__OP_03__VENDOR },
  /* 04 */  { UD_Igrp_vendor,  O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_01__REG__OP_03__MOD__OP_01__RM__OP_04__VENDOR },
  /* 05 */  { UD_Igrp_vendor,  O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_01__REG__OP_03__MOD__OP_01__RM__OP_05__VENDOR },
  /* 06 */  { UD_Igrp_vendor,  O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_01__REG__OP_03__MOD__OP_01__RM__OP_06__VENDOR },
  /* 07 */  { UD_Igrp_vendor,  O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_01__REG__OP_03__MOD__OP_01__RM__OP_07__VENDOR },
};

static struct ud_itab_entry itab__0f__op_01__reg__op_03__mod__op_01__rm__op_00__vendor[2] = {
  /* 00 */  { UD_Ivmrun,       O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 01 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__0f__op_01__reg__op_03__mod__op_01__rm__op_01__vendor[2] = {
  /* 00 */  { UD_Ivmmcall,     O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 01 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__0f__op_01__reg__op_03__mod__op_01__rm__op_02__vendor[2] = {
  /* 00 */  { UD_Ivmload,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 01 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__0f__op_01__reg__op_03__mod__op_01__rm__op_03__vendor[2] = {
  /* 00 */  { UD_Ivmsave,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 01 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__0f__op_01__reg__op_03__mod__op_01__rm__op_04__vendor[2] = {
  /* 00 */  { UD_Istgi,        O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 01 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__0f__op_01__reg__op_03__mod__op_01__rm__op_05__vendor[2] = {
  /* 00 */  { UD_Iclgi,        O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 01 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__0f__op_01__reg__op_03__mod__op_01__rm__op_06__vendor[2] = {
  /* 00 */  { UD_Iskinit,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 01 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__0f__op_01__reg__op_03__mod__op_01__rm__op_07__vendor[2] = {
  /* 00 */  { UD_Iinvlpga,     O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 01 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__0f__op_01__reg__op_04__mod[2] = {
  /* 00 */  { UD_Ismsw,        O_M,     O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__0f__op_01__reg__op_06__mod[2] = {
  /* 00 */  { UD_Ilmsw,        O_Ew,    O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__0f__op_01__reg__op_07__mod[2] = {
  /* 00 */  { UD_Iinvlpg,      O_M,     O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Igrp_rm,      O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_01__REG__OP_07__MOD__OP_01__RM },
};

static struct ud_itab_entry itab__0f__op_01__reg__op_07__mod__op_01__rm[8] = {
  /* 00 */  { UD_Iswapgs,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 01 */  { UD_Igrp_vendor,  O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_01__REG__OP_07__MOD__OP_01__RM__OP_01__VENDOR },
  /* 02 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 03 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 04 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 05 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 06 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 07 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__0f__op_01__reg__op_07__mod__op_01__rm__op_01__vendor[2] = {
  /* 00 */  { UD_Irdtscp,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 01 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__0f__op_0d__reg[8] = {
  /* 00 */  { UD_Iprefetch,    O_M,     O_NONE,  O_NONE,  P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Iprefetch,    O_M,     O_NONE,  O_NONE,  P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 02 */  { UD_Iprefetch,    O_M,     O_NONE,  O_NONE,  P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 03 */  { UD_Iprefetch,    O_M,     O_NONE,  O_NONE,  P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 04 */  { UD_Iprefetch,    O_M,     O_NONE,  O_NONE,  P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 05 */  { UD_Iprefetch,    O_M,     O_NONE,  O_NONE,  P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 06 */  { UD_Iprefetch,    O_M,     O_NONE,  O_NONE,  P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 07 */  { UD_Iprefetch,    O_M,     O_NONE,  O_NONE,  P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
};

static struct ud_itab_entry itab__0f__op_18__reg[8] = {
  /* 00 */  { UD_Iprefetchnta, O_M,     O_NONE,  O_NONE,  P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Iprefetcht0,  O_M,     O_NONE,  O_NONE,  P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 02 */  { UD_Iprefetcht1,  O_M,     O_NONE,  O_NONE,  P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 03 */  { UD_Iprefetcht2,  O_M,     O_NONE,  O_NONE,  P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 04 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 05 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 06 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 07 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__0f__op_71__reg[8] = {
  /* 00 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 01 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 02 */  { UD_Ipsrlw,       O_PR,    O_Ib,    O_NONE,  P_none },
  /* 03 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 04 */  { UD_Ipsraw,       O_PR,    O_Ib,    O_NONE,  P_none },
  /* 05 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 06 */  { UD_Ipsllw,       O_PR,    O_Ib,    O_NONE,  P_none },
  /* 07 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__0f__op_72__reg[8] = {
  /* 00 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 01 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 02 */  { UD_Ipsrld,       O_PR,    O_Ib,    O_NONE,  P_none },
  /* 03 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 04 */  { UD_Ipsrad,       O_PR,    O_Ib,    O_NONE,  P_none },
  /* 05 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 06 */  { UD_Ipslld,       O_PR,    O_Ib,    O_NONE,  P_none },
  /* 07 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__0f__op_73__reg[8] = {
  /* 00 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 01 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 02 */  { UD_Ipsrlq,       O_PR,    O_Ib,    O_NONE,  P_none },
  /* 03 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 04 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 05 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 06 */  { UD_Ipsllq,       O_PR,    O_Ib,    O_NONE,  P_none },
  /* 07 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__0f__op_ae__reg[8] = {
  /* 00 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 01 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 02 */  { UD_Ildmxcsr,     O_Md,    O_NONE,  O_NONE,  P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 03 */  { UD_Istmxcsr,     O_Md,    O_NONE,  O_NONE,  P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 04 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 05 */  { UD_Igrp_mod,     O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_AE__REG__OP_05__MOD },
  /* 06 */  { UD_Igrp_mod,     O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_AE__REG__OP_06__MOD },
  /* 07 */  { UD_Igrp_mod,     O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_AE__REG__OP_07__MOD },
};

static struct ud_itab_entry itab__0f__op_ae__reg__op_05__mod[2] = {
  /* 00 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 01 */  { UD_Igrp_rm,      O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_AE__REG__OP_05__MOD__OP_01__RM },
};

static struct ud_itab_entry itab__0f__op_ae__reg__op_05__mod__op_01__rm[8] = {
  /* 00 */  { UD_Ilfence,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 01 */  { UD_Ilfence,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 02 */  { UD_Ilfence,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 03 */  { UD_Ilfence,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 04 */  { UD_Ilfence,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 05 */  { UD_Ilfence,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 06 */  { UD_Ilfence,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 07 */  { UD_Ilfence,      O_NONE,  O_NONE,  O_NONE,  P_none },
};

static struct ud_itab_entry itab__0f__op_ae__reg__op_06__mod[2] = {
  /* 00 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 01 */  { UD_Igrp_rm,      O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_AE__REG__OP_06__MOD__OP_01__RM },
};

static struct ud_itab_entry itab__0f__op_ae__reg__op_06__mod__op_01__rm[8] = {
  /* 00 */  { UD_Imfence,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 01 */  { UD_Imfence,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 02 */  { UD_Imfence,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 03 */  { UD_Imfence,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 04 */  { UD_Imfence,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 05 */  { UD_Imfence,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 06 */  { UD_Imfence,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 07 */  { UD_Imfence,      O_NONE,  O_NONE,  O_NONE,  P_none },
};

static struct ud_itab_entry itab__0f__op_ae__reg__op_07__mod[2] = {
  /* 00 */  { UD_Iclflush,     O_M,     O_NONE,  O_NONE,  P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Igrp_rm,      O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_AE__REG__OP_07__MOD__OP_01__RM },
};

static struct ud_itab_entry itab__0f__op_ae__reg__op_07__mod__op_01__rm[8] = {
  /* 00 */  { UD_Isfence,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 01 */  { UD_Isfence,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 02 */  { UD_Isfence,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 03 */  { UD_Isfence,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 04 */  { UD_Isfence,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 05 */  { UD_Isfence,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 06 */  { UD_Isfence,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 07 */  { UD_Isfence,      O_NONE,  O_NONE,  O_NONE,  P_none },
};

static struct ud_itab_entry itab__0f__op_ba__reg[8] = {
  /* 00 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 01 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 02 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 03 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 04 */  { UD_Ibt,          O_Ev,    O_Ib,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 05 */  { UD_Ibts,         O_Ev,    O_Ib,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 06 */  { UD_Ibtr,         O_Ev,    O_Ib,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 07 */  { UD_Ibtc,         O_Ev,    O_Ib,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
};

static struct ud_itab_entry itab__0f__op_c7__reg[8] = {
  /* 00 */  { UD_Igrp_vendor,  O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_C7__REG__OP_00__VENDOR },
  /* 01 */  { UD_Icmpxchg8b,   O_M,     O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 02 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 03 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 04 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 05 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 06 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 07 */  { UD_Igrp_vendor,  O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_C7__REG__OP_07__VENDOR },
};

static struct ud_itab_entry itab__0f__op_c7__reg__op_00__vendor[2] = {
  /* 00 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 01 */  { UD_Ivmptrld,     O_Mq,    O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
};

static struct ud_itab_entry itab__0f__op_c7__reg__op_07__vendor[2] = {
  /* 00 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 01 */  { UD_Ivmptrst,     O_Mq,    O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
};

static struct ud_itab_entry itab__0f__op_d9__mod[2] = {
  /* 00 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 01 */  { UD_Igrp_x87,     O_NONE, O_NONE, O_NONE,    ITAB__0F__OP_D9__MOD__OP_01__X87 },
};

static struct ud_itab_entry itab__0f__op_d9__mod__op_01__x87[64] = {
  /* 00 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 01 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 02 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 03 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 04 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 05 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 06 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 07 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 08 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 09 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 0A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 0B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 0C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 0D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 0E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 0F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 10 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 11 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 12 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 13 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 14 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 15 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 16 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 17 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 18 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 19 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 1A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 1B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 1C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 1D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 1E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 1F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 20 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 21 */  { UD_Ifabs,        O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 22 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 23 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 24 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 25 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 26 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 27 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 28 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 29 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 2A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 2B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 2C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 2D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 2E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 2F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 30 */  { UD_If2xm1,       O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 31 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 32 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 33 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 34 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 35 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 36 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 37 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 38 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 39 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__1byte[256] = {
  /* 00 */  { UD_Iadd,         O_Eb,    O_Gb,    O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Iadd,         O_Ev,    O_Gv,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 02 */  { UD_Iadd,         O_Gb,    O_Eb,    O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 03 */  { UD_Iadd,         O_Gv,    O_Ev,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 04 */  { UD_Iadd,         O_AL,    O_Ib,    O_NONE,  P_none },
  /* 05 */  { UD_Iadd,         O_rAX,   O_Iz,    O_NONE,  P_oso|P_rexw },
  /* 06 */  { UD_Ipush,        O_ES,    O_NONE,  O_NONE,  P_inv64|P_none },
  /* 07 */  { UD_Ipop,         O_ES,    O_NONE,  O_NONE,  P_inv64|P_none },
  /* 08 */  { UD_Ior,          O_Eb,    O_Gb,    O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 09 */  { UD_Ior,          O_Ev,    O_Gv,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 0A */  { UD_Ior,          O_Gb,    O_Eb,    O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 0B */  { UD_Ior,          O_Gv,    O_Ev,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 0C */  { UD_Ior,          O_AL,    O_Ib,    O_NONE,  P_none },
  /* 0D */  { UD_Ior,          O_rAX,   O_Iz,    O_NONE,  P_oso|P_rexw },
  /* 0E */  { UD_Ipush,        O_CS,    O_NONE,  O_NONE,  P_inv64|P_none },
  /* 0F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 10 */  { UD_Iadc,         O_Eb,    O_Gb,    O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 11 */  { UD_Iadc,         O_Ev,    O_Gv,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 12 */  { UD_Iadc,         O_Gb,    O_Eb,    O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 13 */  { UD_Iadc,         O_Gv,    O_Ev,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 14 */  { UD_Iadc,         O_AL,    O_Ib,    O_NONE,  P_none },
  /* 15 */  { UD_Iadc,         O_rAX,   O_Iz,    O_NONE,  P_oso|P_rexw },
  /* 16 */  { UD_Ipush,        O_SS,    O_NONE,  O_NONE,  P_inv64|P_none },
  /* 17 */  { UD_Ipop,         O_SS,    O_NONE,  O_NONE,  P_inv64|P_none },
  /* 18 */  { UD_Isbb,         O_Eb,    O_Gb,    O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 19 */  { UD_Isbb,         O_Ev,    O_Gv,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 1A */  { UD_Isbb,         O_Gb,    O_Eb,    O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 1B */  { UD_Isbb,         O_Gv,    O_Ev,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 1C */  { UD_Isbb,         O_AL,    O_Ib,    O_NONE,  P_none },
  /* 1D */  { UD_Isbb,         O_rAX,   O_Iz,    O_NONE,  P_oso|P_rexw },
  /* 1E */  { UD_Ipush,        O_DS,    O_NONE,  O_NONE,  P_inv64|P_none },
  /* 1F */  { UD_Ipop,         O_DS,    O_NONE,  O_NONE,  P_inv64|P_none },
  /* 20 */  { UD_Iand,         O_Eb,    O_Gb,    O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 21 */  { UD_Iand,         O_Ev,    O_Gv,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 22 */  { UD_Iand,         O_Gb,    O_Eb,    O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 23 */  { UD_Iand,         O_Gv,    O_Ev,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 24 */  { UD_Iand,         O_AL,    O_Ib,    O_NONE,  P_none },
  /* 25 */  { UD_Iand,         O_rAX,   O_Iz,    O_NONE,  P_oso|P_rexw },
  /* 26 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 27 */  { UD_Idaa,         O_NONE,  O_NONE,  O_NONE,  P_inv64|P_none },
  /* 28 */  { UD_Isub,         O_Eb,    O_Gb,    O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 29 */  { UD_Isub,         O_Ev,    O_Gv,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 2A */  { UD_Isub,         O_Gb,    O_Eb,    O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 2B */  { UD_Isub,         O_Gv,    O_Ev,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 2C */  { UD_Isub,         O_AL,    O_Ib,    O_NONE,  P_none },
  /* 2D */  { UD_Isub,         O_rAX,   O_Iz,    O_NONE,  P_oso|P_rexw },
  /* 2E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 2F */  { UD_Idas,         O_NONE,  O_NONE,  O_NONE,  P_inv64|P_none },
  /* 30 */  { UD_Ixor,         O_Eb,    O_Gb,    O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 31 */  { UD_Ixor,         O_Ev,    O_Gv,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 32 */  { UD_Ixor,         O_Gb,    O_Eb,    O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 33 */  { UD_Ixor,         O_Gv,    O_Ev,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 34 */  { UD_Ixor,         O_AL,    O_Ib,    O_NONE,  P_none },
  /* 35 */  { UD_Ixor,         O_rAX,   O_Iz,    O_NONE,  P_oso|P_rexw },
  /* 36 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 37 */  { UD_Iaaa,         O_NONE,  O_NONE,  O_NONE,  P_inv64|P_none },
  /* 38 */  { UD_Icmp,         O_Eb,    O_Gb,    O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 39 */  { UD_Icmp,         O_Ev,    O_Gv,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 3A */  { UD_Icmp,         O_Gb,    O_Eb,    O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 3B */  { UD_Icmp,         O_Gv,    O_Ev,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 3C */  { UD_Icmp,         O_AL,    O_Ib,    O_NONE,  P_none },
  /* 3D */  { UD_Icmp,         O_rAX,   O_Iz,    O_NONE,  P_oso|P_rexw },
  /* 3E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3F */  { UD_Iaas,         O_NONE,  O_NONE,  O_NONE,  P_inv64|P_none },
  /* 40 */  { UD_Iinc,         O_eAX,   O_NONE,  O_NONE,  P_oso },
  /* 41 */  { UD_Iinc,         O_eCX,   O_NONE,  O_NONE,  P_oso },
  /* 42 */  { UD_Iinc,         O_eDX,   O_NONE,  O_NONE,  P_oso },
  /* 43 */  { UD_Iinc,         O_eBX,   O_NONE,  O_NONE,  P_oso },
  /* 44 */  { UD_Iinc,         O_eSP,   O_NONE,  O_NONE,  P_oso },
  /* 45 */  { UD_Iinc,         O_eBP,   O_NONE,  O_NONE,  P_oso },
  /* 46 */  { UD_Iinc,         O_eSI,   O_NONE,  O_NONE,  P_oso },
  /* 47 */  { UD_Iinc,         O_eDI,   O_NONE,  O_NONE,  P_oso },
  /* 48 */  { UD_Idec,         O_eAX,   O_NONE,  O_NONE,  P_oso },
  /* 49 */  { UD_Idec,         O_eCX,   O_NONE,  O_NONE,  P_oso },
  /* 4A */  { UD_Idec,         O_eDX,   O_NONE,  O_NONE,  P_oso },
  /* 4B */  { UD_Idec,         O_eBX,   O_NONE,  O_NONE,  P_oso },
  /* 4C */  { UD_Idec,         O_eSP,   O_NONE,  O_NONE,  P_oso },
  /* 4D */  { UD_Idec,         O_eBP,   O_NONE,  O_NONE,  P_oso },
  /* 4E */  { UD_Idec,         O_eSI,   O_NONE,  O_NONE,  P_oso },
  /* 4F */  { UD_Idec,         O_eDI,   O_NONE,  O_NONE,  P_oso },
  /* 50 */  { UD_Ipush,        O_rAXr8, O_NONE,  O_NONE,  P_def64|P_depM|P_oso|P_rexb },
  /* 51 */  { UD_Ipush,        O_rCXr9, O_NONE,  O_NONE,  P_def64|P_depM|P_oso|P_rexb },
  /* 52 */  { UD_Ipush,        O_rDXr10, O_NONE,  O_NONE, P_def64|P_depM|P_oso|P_rexb },
  /* 53 */  { UD_Ipush,        O_rBXr11, O_NONE,  O_NONE, P_def64|P_depM|P_oso|P_rexb },
  /* 54 */  { UD_Ipush,        O_rSPr12, O_NONE,  O_NONE, P_def64|P_depM|P_oso|P_rexb },
  /* 55 */  { UD_Ipush,        O_rBPr13, O_NONE,  O_NONE, P_def64|P_depM|P_oso|P_rexb },
  /* 56 */  { UD_Ipush,        O_rSIr14, O_NONE,  O_NONE, P_def64|P_depM|P_oso|P_rexb },
  /* 57 */  { UD_Ipush,        O_rDIr15, O_NONE,  O_NONE, P_def64|P_depM|P_oso|P_rexb },
  /* 58 */  { UD_Ipop,         O_rAXr8, O_NONE,  O_NONE,  P_def64|P_depM|P_oso|P_rexb },
  /* 59 */  { UD_Ipop,         O_rCXr9, O_NONE,  O_NONE,  P_def64|P_depM|P_oso|P_rexb },
  /* 5A */  { UD_Ipop,         O_rDXr10, O_NONE,  O_NONE, P_def64|P_depM|P_oso|P_rexb },
  /* 5B */  { UD_Ipop,         O_rBXr11, O_NONE,  O_NONE, P_def64|P_depM|P_oso|P_rexb },
  /* 5C */  { UD_Ipop,         O_rSPr12, O_NONE,  O_NONE, P_def64|P_depM|P_oso|P_rexb },
  /* 5D */  { UD_Ipop,         O_rBPr13, O_NONE,  O_NONE, P_def64|P_depM|P_oso|P_rexb },
  /* 5E */  { UD_Ipop,         O_rSIr14, O_NONE,  O_NONE, P_def64|P_depM|P_oso|P_rexb },
  /* 5F */  { UD_Ipop,         O_rDIr15, O_NONE,  O_NONE, P_def64|P_depM|P_oso|P_rexb },
  /* 60 */  { UD_Igrp_osize,   O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_60__OSIZE },
  /* 61 */  { UD_Igrp_osize,   O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_61__OSIZE },
  /* 62 */  { UD_Ibound,       O_Gv,    O_M,     O_NONE,  P_inv64|P_aso|P_oso },
  /* 63 */  { UD_Igrp_mode,    O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_63__MODE },
  /* 64 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 65 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 66 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 67 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 68 */  { UD_Ipush,        O_Iz,    O_NONE,  O_NONE,  P_c1|P_oso },
  /* 69 */  { UD_Iimul,        O_Gv,    O_Ev,    O_Iz,    P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 6A */  { UD_Ipush,        O_Ib,    O_NONE,  O_NONE,  P_none },
  /* 6B */  { UD_Iimul,        O_Gv,    O_Ev,    O_Ib,    P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 6C */  { UD_Iinsb,        O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 6D */  { UD_Igrp_osize,   O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_6D__OSIZE },
  /* 6E */  { UD_Ioutsb,       O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 6F */  { UD_Igrp_osize,   O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_6F__OSIZE },
  /* 70 */  { UD_Ijo,          O_Jb,    O_NONE,  O_NONE,  P_none },
  /* 71 */  { UD_Ijno,         O_Jb,    O_NONE,  O_NONE,  P_none },
  /* 72 */  { UD_Ijb,          O_Jb,    O_NONE,  O_NONE,  P_none },
  /* 73 */  { UD_Ijae,         O_Jb,    O_NONE,  O_NONE,  P_none },
  /* 74 */  { UD_Ijz,          O_Jb,    O_NONE,  O_NONE,  P_none },
  /* 75 */  { UD_Ijnz,         O_Jb,    O_NONE,  O_NONE,  P_none },
  /* 76 */  { UD_Ijbe,         O_Jb,    O_NONE,  O_NONE,  P_none },
  /* 77 */  { UD_Ija,          O_Jb,    O_NONE,  O_NONE,  P_none },
  /* 78 */  { UD_Ijs,          O_Jb,    O_NONE,  O_NONE,  P_none },
  /* 79 */  { UD_Ijns,         O_Jb,    O_NONE,  O_NONE,  P_none },
  /* 7A */  { UD_Ijp,          O_Jb,    O_NONE,  O_NONE,  P_none },
  /* 7B */  { UD_Ijnp,         O_Jb,    O_NONE,  O_NONE,  P_none },
  /* 7C */  { UD_Ijl,          O_Jb,    O_NONE,  O_NONE,  P_none },
  /* 7D */  { UD_Ijge,         O_Jb,    O_NONE,  O_NONE,  P_none },
  /* 7E */  { UD_Ijle,         O_Jb,    O_NONE,  O_NONE,  P_none },
  /* 7F */  { UD_Ijg,          O_Jb,    O_NONE,  O_NONE,  P_none },
  /* 80 */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_80__REG },
  /* 81 */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_81__REG },
  /* 82 */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_82__REG },
  /* 83 */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_83__REG },
  /* 84 */  { UD_Itest,        O_Eb,    O_Gb,    O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 85 */  { UD_Itest,        O_Ev,    O_Gv,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 86 */  { UD_Ixchg,        O_Eb,    O_Gb,    O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 87 */  { UD_Ixchg,        O_Ev,    O_Gv,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 88 */  { UD_Imov,         O_Eb,    O_Gb,    O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 89 */  { UD_Imov,         O_Ev,    O_Gv,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 8A */  { UD_Imov,         O_Gb,    O_Eb,    O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 8B */  { UD_Imov,         O_Gv,    O_Ev,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 8C */  { UD_Imov,         O_Ev,    O_S,     O_NONE,  P_aso|P_oso|P_rexr|P_rexx|P_rexb },
  /* 8D */  { UD_Ilea,         O_Gv,    O_M,     O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 8E */  { UD_Imov,         O_S,     O_Ev,    O_NONE,  P_aso|P_oso|P_rexr|P_rexx|P_rexb },
  /* 8F */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_8F__REG },
  /* 90 */  { UD_Ixchg,        O_rAXr8, O_rAX,   O_NONE,  P_oso|P_rexw|P_rexb },
  /* 91 */  { UD_Ixchg,        O_rCXr9, O_rAX,   O_NONE,  P_oso|P_rexw|P_rexb },
  /* 92 */  { UD_Ixchg,        O_rDXr10, O_rAX,   O_NONE, P_oso|P_rexw|P_rexb },
  /* 93 */  { UD_Ixchg,        O_rBXr11, O_rAX,   O_NONE, P_oso|P_rexw|P_rexb },
  /* 94 */  { UD_Ixchg,        O_rSPr12, O_rAX,   O_NONE, P_oso|P_rexw|P_rexb },
  /* 95 */  { UD_Ixchg,        O_rBPr13, O_rAX,   O_NONE, P_oso|P_rexw|P_rexb },
  /* 96 */  { UD_Ixchg,        O_rSIr14, O_rAX,   O_NONE, P_oso|P_rexw|P_rexb },
  /* 97 */  { UD_Ixchg,        O_rDIr15, O_rAX,   O_NONE, P_oso|P_rexw|P_rexb },
  /* 98 */  { UD_Igrp_osize,   O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_98__OSIZE },
  /* 99 */  { UD_Igrp_osize,   O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_99__OSIZE },
  /* 9A */  { UD_Icall,        O_Ap,    O_NONE,  O_NONE,  P_inv64|P_oso },
  /* 9B */  { UD_Iwait,        O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 9C */  { UD_Igrp_mode,    O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_9C__MODE },
  /* 9D */  { UD_Igrp_mode,    O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_9D__MODE },
  /* 9E */  { UD_Isahf,        O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 9F */  { UD_Ilahf,        O_NONE,  O_NONE,  O_NONE,  P_none },
  /* A0 */  { UD_Imov,         O_AL,    O_Ob,    O_NONE,  P_none },
  /* A1 */  { UD_Imov,         O_rAX,   O_Ov,    O_NONE,  P_aso|P_oso|P_rexw },
  /* A2 */  { UD_Imov,         O_Ob,    O_AL,    O_NONE,  P_none },
  /* A3 */  { UD_Imov,         O_Ov,    O_rAX,   O_NONE,  P_aso|P_oso|P_rexw },
  /* A4 */  { UD_Imovsb,       O_NONE,  O_NONE,  O_NONE,  P_ImpAddr|P_none },
  /* A5 */  { UD_Igrp_osize,   O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_A5__OSIZE },
  /* A6 */  { UD_Icmpsb,       O_NONE,  O_NONE,  O_NONE,  P_none },
  /* A7 */  { UD_Igrp_osize,   O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_A7__OSIZE },
  /* A8 */  { UD_Itest,        O_AL,    O_Ib,    O_NONE,  P_none },
  /* A9 */  { UD_Itest,        O_rAX,   O_Iz,    O_NONE,  P_oso|P_rexw },
  /* AA */  { UD_Istosb,       O_NONE,  O_NONE,  O_NONE,  P_ImpAddr|P_none },
  /* AB */  { UD_Igrp_osize,   O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_AB__OSIZE },
  /* AC */  { UD_Ilodsb,       O_NONE,  O_NONE,  O_NONE,  P_ImpAddr|P_none },
  /* AD */  { UD_Igrp_osize,   O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_AD__OSIZE },
  /* AE */  { UD_Iscasb,       O_NONE,  O_NONE,  O_NONE,  P_none },
  /* AF */  { UD_Igrp_osize,   O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_AF__OSIZE },
  /* B0 */  { UD_Imov,         O_ALr8b, O_Ib,    O_NONE,  P_rexb },
  /* B1 */  { UD_Imov,         O_CLr9b, O_Ib,    O_NONE,  P_rexb },
  /* B2 */  { UD_Imov,         O_DLr10b, O_Ib,    O_NONE, P_rexb },
  /* B3 */  { UD_Imov,         O_BLr11b, O_Ib,    O_NONE, P_rexb },
  /* B4 */  { UD_Imov,         O_AHr12b, O_Ib,    O_NONE, P_rexb },
  /* B5 */  { UD_Imov,         O_CHr13b, O_Ib,    O_NONE, P_rexb },
  /* B6 */  { UD_Imov,         O_DHr14b, O_Ib,    O_NONE, P_rexb },
  /* B7 */  { UD_Imov,         O_BHr15b, O_Ib,    O_NONE, P_rexb },
  /* B8 */  { UD_Imov,         O_rAXr8, O_Iv,    O_NONE,  P_oso|P_rexw|P_rexb },
  /* B9 */  { UD_Imov,         O_rCXr9, O_Iv,    O_NONE,  P_oso|P_rexw|P_rexb },
  /* BA */  { UD_Imov,         O_rDXr10, O_Iv,    O_NONE, P_oso|P_rexw|P_rexb },
  /* BB */  { UD_Imov,         O_rBXr11, O_Iv,    O_NONE, P_oso|P_rexw|P_rexb },
  /* BC */  { UD_Imov,         O_rSPr12, O_Iv,    O_NONE, P_oso|P_rexw|P_rexb },
  /* BD */  { UD_Imov,         O_rBPr13, O_Iv,    O_NONE, P_oso|P_rexw|P_rexb },
  /* BE */  { UD_Imov,         O_rSIr14, O_Iv,    O_NONE, P_oso|P_rexw|P_rexb },
  /* BF */  { UD_Imov,         O_rDIr15, O_Iv,    O_NONE, P_oso|P_rexw|P_rexb },
  /* C0 */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_C0__REG },
  /* C1 */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_C1__REG },
  /* C2 */  { UD_Iret,         O_Iw,    O_NONE,  O_NONE,  P_none },
  /* C3 */  { UD_Iret,         O_NONE,  O_NONE,  O_NONE,  P_none },
  /* C4 */  { UD_Iles,         O_Gv,    O_M,     O_NONE,  P_inv64|P_aso|P_oso },
  /* C5 */  { UD_Ilds,         O_Gv,    O_M,     O_NONE,  P_inv64|P_aso|P_oso },
  /* C6 */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_C6__REG },
  /* C7 */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_C7__REG },
  /* C8 */  { UD_Ienter,       O_Iw,    O_Ib,    O_NONE,  P_def64|P_depM|P_none },
  /* C9 */  { UD_Ileave,       O_NONE,  O_NONE,  O_NONE,  P_none },
  /* CA */  { UD_Iretf,        O_Iw,    O_NONE,  O_NONE,  P_none },
  /* CB */  { UD_Iretf,        O_NONE,  O_NONE,  O_NONE,  P_none },
  /* CC */  { UD_Iint3,        O_NONE,  O_NONE,  O_NONE,  P_none },
  /* CD */  { UD_Iint,         O_Ib,    O_NONE,  O_NONE,  P_none },
  /* CE */  { UD_Iinto,        O_NONE,  O_NONE,  O_NONE,  P_inv64|P_none },
  /* CF */  { UD_Igrp_osize,   O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_CF__OSIZE },
  /* D0 */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_D0__REG },
  /* D1 */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_D1__REG },
  /* D2 */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_D2__REG },
  /* D3 */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_D3__REG },
  /* D4 */  { UD_Iaam,         O_Ib,    O_NONE,  O_NONE,  P_inv64|P_none },
  /* D5 */  { UD_Iaad,         O_Ib,    O_NONE,  O_NONE,  P_inv64|P_none },
  /* D6 */  { UD_Isalc,        O_NONE,  O_NONE,  O_NONE,  P_inv64|P_none },
  /* D7 */  { UD_Ixlatb,       O_NONE,  O_NONE,  O_NONE,  P_rexw },
  /* D8 */  { UD_Igrp_mod,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_D8__MOD },
  /* D9 */  { UD_Igrp_mod,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_D9__MOD },
  /* DA */  { UD_Igrp_mod,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_DA__MOD },
  /* DB */  { UD_Igrp_mod,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_DB__MOD },
  /* DC */  { UD_Igrp_mod,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_DC__MOD },
  /* DD */  { UD_Igrp_mod,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_DD__MOD },
  /* DE */  { UD_Igrp_mod,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_DE__MOD },
  /* DF */  { UD_Igrp_mod,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_DF__MOD },
  /* E0 */  { UD_Iloopnz,      O_Jb,    O_NONE,  O_NONE,  P_none },
  /* E1 */  { UD_Iloope,       O_Jb,    O_NONE,  O_NONE,  P_none },
  /* E2 */  { UD_Iloop,        O_Jb,    O_NONE,  O_NONE,  P_none },
  /* E3 */  { UD_Igrp_asize,   O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_E3__ASIZE },
  /* E4 */  { UD_Iin,          O_AL,    O_Ib,    O_NONE,  P_none },
  /* E5 */  { UD_Iin,          O_eAX,   O_Ib,    O_NONE,  P_oso },
  /* E6 */  { UD_Iout,         O_Ib,    O_AL,    O_NONE,  P_none },
  /* E7 */  { UD_Iout,         O_Ib,    O_eAX,   O_NONE,  P_oso },
  /* E8 */  { UD_Icall,        O_Jz,    O_NONE,  O_NONE,  P_def64|P_oso },
  /* E9 */  { UD_Ijmp,         O_Jz,    O_NONE,  O_NONE,  P_def64|P_depM|P_oso },
  /* EA */  { UD_Ijmp,         O_Ap,    O_NONE,  O_NONE,  P_inv64|P_none },
  /* EB */  { UD_Ijmp,         O_Jb,    O_NONE,  O_NONE,  P_none },
  /* EC */  { UD_Iin,          O_AL,    O_DX,    O_NONE,  P_none },
  /* ED */  { UD_Iin,          O_eAX,   O_DX,    O_NONE,  P_oso },
  /* EE */  { UD_Iout,         O_DX,    O_AL,    O_NONE,  P_none },
  /* EF */  { UD_Iout,         O_DX,    O_eAX,   O_NONE,  P_oso },
  /* F0 */  { UD_Ilock,        O_NONE,  O_NONE,  O_NONE,  P_none },
  /* F1 */  { UD_Iint1,        O_NONE,  O_NONE,  O_NONE,  P_none },
  /* F2 */  { UD_Irepne,       O_NONE,  O_NONE,  O_NONE,  P_none },
  /* F3 */  { UD_Irep,         O_NONE,  O_NONE,  O_NONE,  P_none },
  /* F4 */  { UD_Ihlt,         O_NONE,  O_NONE,  O_NONE,  P_none },
  /* F5 */  { UD_Icmc,         O_NONE,  O_NONE,  O_NONE,  P_none },
  /* F6 */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_F6__REG },
  /* F7 */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_F7__REG },
  /* F8 */  { UD_Iclc,         O_NONE,  O_NONE,  O_NONE,  P_none },
  /* F9 */  { UD_Istc,         O_NONE,  O_NONE,  O_NONE,  P_none },
  /* FA */  { UD_Icli,         O_NONE,  O_NONE,  O_NONE,  P_none },
  /* FB */  { UD_Isti,         O_NONE,  O_NONE,  O_NONE,  P_none },
  /* FC */  { UD_Icld,         O_NONE,  O_NONE,  O_NONE,  P_none },
  /* FD */  { UD_Istd,         O_NONE,  O_NONE,  O_NONE,  P_none },
  /* FE */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_FE__REG },
  /* FF */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_FF__REG },
};

static struct ud_itab_entry itab__1byte__op_60__osize[3] = {
  /* 00 */  { UD_Ipusha,       O_NONE,  O_NONE,  O_NONE,  P_inv64|P_oso },
  /* 01 */  { UD_Ipushad,      O_NONE,  O_NONE,  O_NONE,  P_inv64|P_oso },
  /* 02 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__1byte__op_61__osize[3] = {
  /* 00 */  { UD_Ipopa,        O_NONE,  O_NONE,  O_NONE,  P_inv64|P_oso },
  /* 01 */  { UD_Ipopad,       O_NONE,  O_NONE,  O_NONE,  P_inv64|P_oso },
  /* 02 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__1byte__op_63__mode[3] = {
  /* 00 */  { UD_Iarpl,        O_Ew,    O_Gw,    O_NONE,  P_inv64|P_aso },
  /* 01 */  { UD_Iarpl,        O_Ew,    O_Gw,    O_NONE,  P_inv64|P_aso },
  /* 02 */  { UD_Imovsxd,      O_Gv,    O_Ed,    O_NONE,  P_c2|P_aso|P_oso|P_rexw|P_rexx|P_rexr|P_rexb },
};

static struct ud_itab_entry itab__1byte__op_6d__osize[3] = {
  /* 00 */  { UD_Iinsw,        O_NONE,  O_NONE,  O_NONE,  P_oso },
  /* 01 */  { UD_Iinsd,        O_NONE,  O_NONE,  O_NONE,  P_oso },
  /* 02 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__1byte__op_6f__osize[3] = {
  /* 00 */  { UD_Ioutsw,       O_NONE,  O_NONE,  O_NONE,  P_oso },
  /* 01 */  { UD_Ioutsd,       O_NONE,  O_NONE,  O_NONE,  P_oso },
  /* 02 */  { UD_Ioutsq,       O_NONE,  O_NONE,  O_NONE,  P_oso },
};

static struct ud_itab_entry itab__1byte__op_80__reg[8] = {
  /* 00 */  { UD_Iadd,         O_Eb,    O_Ib,    O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Ior,          O_Eb,    O_Ib,    O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 02 */  { UD_Iadc,         O_Eb,    O_Ib,    O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 03 */  { UD_Isbb,         O_Eb,    O_Ib,    O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 04 */  { UD_Iand,         O_Eb,    O_Ib,    O_NONE,  P_c1|P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 05 */  { UD_Isub,         O_Eb,    O_Ib,    O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 06 */  { UD_Ixor,         O_Eb,    O_Ib,    O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 07 */  { UD_Icmp,         O_Eb,    O_Ib,    O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
};

static struct ud_itab_entry itab__1byte__op_81__reg[8] = {
  /* 00 */  { UD_Iadd,         O_Ev,    O_Iz,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Ior,          O_Ev,    O_Iz,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 02 */  { UD_Iadc,         O_Ev,    O_Iz,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 03 */  { UD_Isbb,         O_Ev,    O_Iz,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 04 */  { UD_Iand,         O_Ev,    O_Iz,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 05 */  { UD_Isub,         O_Ev,    O_Iz,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 06 */  { UD_Ixor,         O_Ev,    O_Iz,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 07 */  { UD_Icmp,         O_Ev,    O_Iz,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
};

static struct ud_itab_entry itab__1byte__op_82__reg[8] = {
  /* 00 */  { UD_Iadd,         O_Eb,    O_Ib,    O_NONE,  P_c1|P_inv64|P_aso|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Ior,          O_Eb,    O_Ib,    O_NONE,  P_c1|P_inv64|P_aso|P_rexr|P_rexx|P_rexb },
  /* 02 */  { UD_Iadc,         O_Eb,    O_Ib,    O_NONE,  P_c1|P_inv64|P_aso|P_rexr|P_rexx|P_rexb },
  /* 03 */  { UD_Isbb,         O_Eb,    O_Ib,    O_NONE,  P_c1|P_inv64|P_aso|P_rexr|P_rexx|P_rexb },
  /* 04 */  { UD_Iand,         O_Eb,    O_Ib,    O_NONE,  P_c1|P_inv64|P_aso|P_rexr|P_rexx|P_rexb },
  /* 05 */  { UD_Isub,         O_Eb,    O_Ib,    O_NONE,  P_c1|P_inv64|P_aso|P_rexr|P_rexx|P_rexb },
  /* 06 */  { UD_Ixor,         O_Eb,    O_Ib,    O_NONE,  P_c1|P_inv64|P_aso|P_rexr|P_rexx|P_rexb },
  /* 07 */  { UD_Icmp,         O_Eb,    O_Ib,    O_NONE,  P_c1|P_inv64|P_aso|P_rexr|P_rexx|P_rexb },
};

static struct ud_itab_entry itab__1byte__op_83__reg[8] = {
  /* 00 */  { UD_Iadd,         O_Ev,    O_Ib,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Ior,          O_Ev,    O_Ib,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 02 */  { UD_Iadc,         O_Ev,    O_Ib,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 03 */  { UD_Isbb,         O_Ev,    O_Ib,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 04 */  { UD_Iand,         O_Ev,    O_Ib,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 05 */  { UD_Isub,         O_Ev,    O_Ib,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 06 */  { UD_Ixor,         O_Ev,    O_Ib,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 07 */  { UD_Icmp,         O_Ev,    O_Ib,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
};

static struct ud_itab_entry itab__1byte__op_8f__reg[8] = {
  /* 00 */  { UD_Ipop,         O_Ev,    O_NONE,  O_NONE,  P_c1|P_def64|P_depM|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 02 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 03 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 04 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 05 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 06 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 07 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__1byte__op_98__osize[3] = {
  /* 00 */  { UD_Icbw,         O_NONE,  O_NONE,  O_NONE,  P_oso|P_rexw },
  /* 01 */  { UD_Icwde,        O_NONE,  O_NONE,  O_NONE,  P_oso|P_rexw },
  /* 02 */  { UD_Icdqe,        O_NONE,  O_NONE,  O_NONE,  P_oso|P_rexw },
};

static struct ud_itab_entry itab__1byte__op_99__osize[3] = {
  /* 00 */  { UD_Icwd,         O_NONE,  O_NONE,  O_NONE,  P_oso|P_rexw },
  /* 01 */  { UD_Icdq,         O_NONE,  O_NONE,  O_NONE,  P_oso|P_rexw },
  /* 02 */  { UD_Icqo,         O_NONE,  O_NONE,  O_NONE,  P_oso|P_rexw },
};

static struct ud_itab_entry itab__1byte__op_9c__mode[3] = {
  /* 00 */  { UD_Igrp_osize,   O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_9C__MODE__OP_00__OSIZE },
  /* 01 */  { UD_Igrp_osize,   O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_9C__MODE__OP_01__OSIZE },
  /* 02 */  { UD_Ipushfq,      O_NONE,  O_NONE,  O_NONE,  P_def64|P_oso|P_rexw },
};

static struct ud_itab_entry itab__1byte__op_9c__mode__op_00__osize[3] = {
  /* 00 */  { UD_Ipushfw,      O_NONE,  O_NONE,  O_NONE,  P_def64|P_oso },
  /* 01 */  { UD_Ipushfd,      O_NONE,  O_NONE,  O_NONE,  P_def64|P_oso },
  /* 02 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__1byte__op_9c__mode__op_01__osize[3] = {
  /* 00 */  { UD_Ipushfw,      O_NONE,  O_NONE,  O_NONE,  P_def64|P_oso },
  /* 01 */  { UD_Ipushfd,      O_NONE,  O_NONE,  O_NONE,  P_def64|P_oso },
  /* 02 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__1byte__op_9d__mode[3] = {
  /* 00 */  { UD_Igrp_osize,   O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_9D__MODE__OP_00__OSIZE },
  /* 01 */  { UD_Igrp_osize,   O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_9D__MODE__OP_01__OSIZE },
  /* 02 */  { UD_Ipopfq,       O_NONE,  O_NONE,  O_NONE,  P_def64|P_depM|P_oso },
};

static struct ud_itab_entry itab__1byte__op_9d__mode__op_00__osize[3] = {
  /* 00 */  { UD_Ipopfw,       O_NONE,  O_NONE,  O_NONE,  P_def64|P_depM|P_oso },
  /* 01 */  { UD_Ipopfd,       O_NONE,  O_NONE,  O_NONE,  P_def64|P_depM|P_oso },
  /* 02 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__1byte__op_9d__mode__op_01__osize[3] = {
  /* 00 */  { UD_Ipopfw,       O_NONE,  O_NONE,  O_NONE,  P_def64|P_depM|P_oso },
  /* 01 */  { UD_Ipopfd,       O_NONE,  O_NONE,  O_NONE,  P_def64|P_depM|P_oso },
  /* 02 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__1byte__op_a5__osize[3] = {
  /* 00 */  { UD_Imovsw,       O_NONE,  O_NONE,  O_NONE,  P_ImpAddr|P_oso|P_rexw },
  /* 01 */  { UD_Imovsd,       O_NONE,  O_NONE,  O_NONE,  P_ImpAddr|P_oso|P_rexw },
  /* 02 */  { UD_Imovsq,       O_NONE,  O_NONE,  O_NONE,  P_ImpAddr|P_oso|P_rexw },
};

static struct ud_itab_entry itab__1byte__op_a7__osize[3] = {
  /* 00 */  { UD_Icmpsw,       O_NONE,  O_NONE,  O_NONE,  P_oso|P_rexw },
  /* 01 */  { UD_Icmpsd,       O_NONE,  O_NONE,  O_NONE,  P_oso|P_rexw },
  /* 02 */  { UD_Icmpsq,       O_NONE,  O_NONE,  O_NONE,  P_oso|P_rexw },
};

static struct ud_itab_entry itab__1byte__op_ab__osize[3] = {
  /* 00 */  { UD_Istosw,       O_NONE,  O_NONE,  O_NONE,  P_ImpAddr|P_oso|P_rexw },
  /* 01 */  { UD_Istosd,       O_NONE,  O_NONE,  O_NONE,  P_ImpAddr|P_oso|P_rexw },
  /* 02 */  { UD_Istosq,       O_NONE,  O_NONE,  O_NONE,  P_ImpAddr|P_oso|P_rexw },
};

static struct ud_itab_entry itab__1byte__op_ad__osize[3] = {
  /* 00 */  { UD_Ilodsw,       O_NONE,  O_NONE,  O_NONE,  P_ImpAddr|P_oso|P_rexw },
  /* 01 */  { UD_Ilodsd,       O_NONE,  O_NONE,  O_NONE,  P_ImpAddr|P_oso|P_rexw },
  /* 02 */  { UD_Ilodsq,       O_NONE,  O_NONE,  O_NONE,  P_ImpAddr|P_oso|P_rexw },
};

static struct ud_itab_entry itab__1byte__op_ae__mod[2] = {
  /* 00 */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_AE__MOD__OP_00__REG },
  /* 01 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__1byte__op_ae__mod__op_00__reg[8] = {
  /* 00 */  { UD_Ifxsave,      O_M,     O_NONE,  O_NONE,  P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Ifxrstor,     O_M,     O_NONE,  O_NONE,  P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 02 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 03 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 04 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 05 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 06 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 07 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__1byte__op_af__osize[3] = {
  /* 00 */  { UD_Iscasw,       O_NONE,  O_NONE,  O_NONE,  P_oso|P_rexw },
  /* 01 */  { UD_Iscasd,       O_NONE,  O_NONE,  O_NONE,  P_oso|P_rexw },
  /* 02 */  { UD_Iscasq,       O_NONE,  O_NONE,  O_NONE,  P_oso|P_rexw },
};

static struct ud_itab_entry itab__1byte__op_c0__reg[8] = {
  /* 00 */  { UD_Irol,         O_Eb,    O_Ib,    O_NONE,  P_c1|P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Iror,         O_Eb,    O_Ib,    O_NONE,  P_c1|P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 02 */  { UD_Ircl,         O_Eb,    O_Ib,    O_NONE,  P_c1|P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 03 */  { UD_Ircr,         O_Eb,    O_Ib,    O_NONE,  P_c1|P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 04 */  { UD_Ishl,         O_Eb,    O_Ib,    O_NONE,  P_c1|P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 05 */  { UD_Ishr,         O_Eb,    O_Ib,    O_NONE,  P_c1|P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 06 */  { UD_Ishl,         O_Eb,    O_Ib,    O_NONE,  P_c1|P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 07 */  { UD_Isar,         O_Eb,    O_Ib,    O_NONE,  P_c1|P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
};

static struct ud_itab_entry itab__1byte__op_c1__reg[8] = {
  /* 00 */  { UD_Irol,         O_Ev,    O_Ib,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Iror,         O_Ev,    O_Ib,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 02 */  { UD_Ircl,         O_Ev,    O_Ib,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 03 */  { UD_Ircr,         O_Ev,    O_Ib,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 04 */  { UD_Ishl,         O_Ev,    O_Ib,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 05 */  { UD_Ishr,         O_Ev,    O_Ib,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 06 */  { UD_Ishl,         O_Ev,    O_Ib,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 07 */  { UD_Isar,         O_Ev,    O_Ib,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
};

static struct ud_itab_entry itab__1byte__op_c6__reg[8] = {
  /* 00 */  { UD_Imov,         O_Eb,    O_Ib,    O_NONE,  P_c1|P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 02 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 03 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 04 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 05 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 06 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 07 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__1byte__op_c7__reg[8] = {
  /* 00 */  { UD_Imov,         O_Ev,    O_Iz,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 02 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 03 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 04 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 05 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 06 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 07 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__1byte__op_cf__osize[3] = {
  /* 00 */  { UD_Iiretw,       O_NONE,  O_NONE,  O_NONE,  P_oso|P_rexw },
  /* 01 */  { UD_Iiretd,       O_NONE,  O_NONE,  O_NONE,  P_oso|P_rexw },
  /* 02 */  { UD_Iiretq,       O_NONE,  O_NONE,  O_NONE,  P_oso|P_rexw },
};

static struct ud_itab_entry itab__1byte__op_d0__reg[8] = {
  /* 00 */  { UD_Irol,         O_Eb,    O_I1,    O_NONE,  P_c1|P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Iror,         O_Eb,    O_I1,    O_NONE,  P_c1|P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 02 */  { UD_Ircl,         O_Eb,    O_I1,    O_NONE,  P_c1|P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 03 */  { UD_Ircr,         O_Eb,    O_I1,    O_NONE,  P_c1|P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 04 */  { UD_Ishl,         O_Eb,    O_I1,    O_NONE,  P_c1|P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 05 */  { UD_Ishr,         O_Eb,    O_I1,    O_NONE,  P_c1|P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 06 */  { UD_Ishl,         O_Eb,    O_I1,    O_NONE,  P_c1|P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 07 */  { UD_Isar,         O_Eb,    O_I1,    O_NONE,  P_c1|P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
};

static struct ud_itab_entry itab__1byte__op_d1__reg[8] = {
  /* 00 */  { UD_Irol,         O_Ev,    O_I1,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Iror,         O_Ev,    O_I1,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 02 */  { UD_Ircl,         O_Ev,    O_I1,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 03 */  { UD_Ircr,         O_Ev,    O_I1,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 04 */  { UD_Ishl,         O_Ev,    O_I1,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 05 */  { UD_Ishr,         O_Ev,    O_I1,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 06 */  { UD_Ishl,         O_Ev,    O_I1,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 07 */  { UD_Isar,         O_Ev,    O_I1,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
};

static struct ud_itab_entry itab__1byte__op_d2__reg[8] = {
  /* 00 */  { UD_Irol,         O_Eb,    O_CL,    O_NONE,  P_c1|P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Iror,         O_Eb,    O_CL,    O_NONE,  P_c1|P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 02 */  { UD_Ircl,         O_Eb,    O_CL,    O_NONE,  P_c1|P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 03 */  { UD_Ircr,         O_Eb,    O_CL,    O_NONE,  P_c1|P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 04 */  { UD_Ishl,         O_Eb,    O_CL,    O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 05 */  { UD_Ishr,         O_Eb,    O_CL,    O_NONE,  P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 06 */  { UD_Ishl,         O_Eb,    O_CL,    O_NONE,  P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 07 */  { UD_Isar,         O_Eb,    O_CL,    O_NONE,  P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
};

static struct ud_itab_entry itab__1byte__op_d3__reg[8] = {
  /* 00 */  { UD_Irol,         O_Ev,    O_CL,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Iror,         O_Ev,    O_CL,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 02 */  { UD_Ircl,         O_Ev,    O_CL,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 03 */  { UD_Ircr,         O_Ev,    O_CL,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 04 */  { UD_Ishl,         O_Ev,    O_CL,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 05 */  { UD_Ishr,         O_Ev,    O_CL,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 06 */  { UD_Ishl,         O_Ev,    O_CL,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 07 */  { UD_Isar,         O_Ev,    O_CL,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
};

static struct ud_itab_entry itab__1byte__op_d8__mod[2] = {
  /* 00 */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_D8__MOD__OP_00__REG },
  /* 01 */  { UD_Igrp_x87,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_D8__MOD__OP_01__X87 },
};

static struct ud_itab_entry itab__1byte__op_d8__mod__op_00__reg[8] = {
  /* 00 */  { UD_Ifadd,        O_Md,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Ifmul,        O_Md,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 02 */  { UD_Ifcom,        O_Md,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 03 */  { UD_Ifcomp,       O_Md,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 04 */  { UD_Ifsub,        O_Md,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 05 */  { UD_Ifsubr,       O_Md,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 06 */  { UD_Ifdiv,        O_Md,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 07 */  { UD_Ifdivr,       O_Md,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
};

static struct ud_itab_entry itab__1byte__op_d8__mod__op_01__x87[64] = {
  /* 00 */  { UD_Ifadd,        O_ST0,   O_ST0,   O_NONE,  P_none },
  /* 01 */  { UD_Ifadd,        O_ST0,   O_ST1,   O_NONE,  P_none },
  /* 02 */  { UD_Ifadd,        O_ST0,   O_ST2,   O_NONE,  P_none },
  /* 03 */  { UD_Ifadd,        O_ST0,   O_ST3,   O_NONE,  P_none },
  /* 04 */  { UD_Ifadd,        O_ST0,   O_ST4,   O_NONE,  P_none },
  /* 05 */  { UD_Ifadd,        O_ST0,   O_ST5,   O_NONE,  P_none },
  /* 06 */  { UD_Ifadd,        O_ST0,   O_ST6,   O_NONE,  P_none },
  /* 07 */  { UD_Ifadd,        O_ST0,   O_ST7,   O_NONE,  P_none },
  /* 08 */  { UD_Ifmul,        O_ST0,   O_ST0,   O_NONE,  P_none },
  /* 09 */  { UD_Ifmul,        O_ST0,   O_ST1,   O_NONE,  P_none },
  /* 0A */  { UD_Ifmul,        O_ST0,   O_ST2,   O_NONE,  P_none },
  /* 0B */  { UD_Ifmul,        O_ST0,   O_ST3,   O_NONE,  P_none },
  /* 0C */  { UD_Ifmul,        O_ST0,   O_ST4,   O_NONE,  P_none },
  /* 0D */  { UD_Ifmul,        O_ST0,   O_ST5,   O_NONE,  P_none },
  /* 0E */  { UD_Ifmul,        O_ST0,   O_ST6,   O_NONE,  P_none },
  /* 0F */  { UD_Ifmul,        O_ST0,   O_ST7,   O_NONE,  P_none },
  /* 10 */  { UD_Ifcom,        O_ST0,   O_ST0,   O_NONE,  P_none },
  /* 11 */  { UD_Ifcom,        O_ST0,   O_ST1,   O_NONE,  P_none },
  /* 12 */  { UD_Ifcom,        O_ST0,   O_ST2,   O_NONE,  P_none },
  /* 13 */  { UD_Ifcom,        O_ST0,   O_ST3,   O_NONE,  P_none },
  /* 14 */  { UD_Ifcom,        O_ST0,   O_ST4,   O_NONE,  P_none },
  /* 15 */  { UD_Ifcom,        O_ST0,   O_ST5,   O_NONE,  P_none },
  /* 16 */  { UD_Ifcom,        O_ST0,   O_ST6,   O_NONE,  P_none },
  /* 17 */  { UD_Ifcom,        O_ST0,   O_ST7,   O_NONE,  P_none },
  /* 18 */  { UD_Ifcomp,       O_ST0,   O_ST0,   O_NONE,  P_none },
  /* 19 */  { UD_Ifcomp,       O_ST0,   O_ST1,   O_NONE,  P_none },
  /* 1A */  { UD_Ifcomp,       O_ST0,   O_ST2,   O_NONE,  P_none },
  /* 1B */  { UD_Ifcomp,       O_ST0,   O_ST3,   O_NONE,  P_none },
  /* 1C */  { UD_Ifcomp,       O_ST0,   O_ST4,   O_NONE,  P_none },
  /* 1D */  { UD_Ifcomp,       O_ST0,   O_ST5,   O_NONE,  P_none },
  /* 1E */  { UD_Ifcomp,       O_ST0,   O_ST6,   O_NONE,  P_none },
  /* 1F */  { UD_Ifcomp,       O_ST0,   O_ST7,   O_NONE,  P_none },
  /* 20 */  { UD_Ifsub,        O_ST0,   O_ST0,   O_NONE,  P_none },
  /* 21 */  { UD_Ifsub,        O_ST0,   O_ST1,   O_NONE,  P_none },
  /* 22 */  { UD_Ifsub,        O_ST0,   O_ST2,   O_NONE,  P_none },
  /* 23 */  { UD_Ifsub,        O_ST0,   O_ST3,   O_NONE,  P_none },
  /* 24 */  { UD_Ifsub,        O_ST0,   O_ST4,   O_NONE,  P_none },
  /* 25 */  { UD_Ifsub,        O_ST0,   O_ST5,   O_NONE,  P_none },
  /* 26 */  { UD_Ifsub,        O_ST0,   O_ST6,   O_NONE,  P_none },
  /* 27 */  { UD_Ifsub,        O_ST0,   O_ST7,   O_NONE,  P_none },
  /* 28 */  { UD_Ifsubr,       O_ST0,   O_ST0,   O_NONE,  P_none },
  /* 29 */  { UD_Ifsubr,       O_ST0,   O_ST1,   O_NONE,  P_none },
  /* 2A */  { UD_Ifsubr,       O_ST0,   O_ST2,   O_NONE,  P_none },
  /* 2B */  { UD_Ifsubr,       O_ST0,   O_ST3,   O_NONE,  P_none },
  /* 2C */  { UD_Ifsubr,       O_ST0,   O_ST4,   O_NONE,  P_none },
  /* 2D */  { UD_Ifsubr,       O_ST0,   O_ST5,   O_NONE,  P_none },
  /* 2E */  { UD_Ifsubr,       O_ST0,   O_ST6,   O_NONE,  P_none },
  /* 2F */  { UD_Ifsubr,       O_ST0,   O_ST7,   O_NONE,  P_none },
  /* 30 */  { UD_Ifdiv,        O_ST0,   O_ST0,   O_NONE,  P_none },
  /* 31 */  { UD_Ifdiv,        O_ST0,   O_ST1,   O_NONE,  P_none },
  /* 32 */  { UD_Ifdiv,        O_ST0,   O_ST2,   O_NONE,  P_none },
  /* 33 */  { UD_Ifdiv,        O_ST0,   O_ST3,   O_NONE,  P_none },
  /* 34 */  { UD_Ifdiv,        O_ST0,   O_ST4,   O_NONE,  P_none },
  /* 35 */  { UD_Ifdiv,        O_ST0,   O_ST5,   O_NONE,  P_none },
  /* 36 */  { UD_Ifdiv,        O_ST0,   O_ST6,   O_NONE,  P_none },
  /* 37 */  { UD_Ifdiv,        O_ST0,   O_ST7,   O_NONE,  P_none },
  /* 38 */  { UD_Ifdivr,       O_ST0,   O_ST0,   O_NONE,  P_none },
  /* 39 */  { UD_Ifdivr,       O_ST0,   O_ST1,   O_NONE,  P_none },
  /* 3A */  { UD_Ifdivr,       O_ST0,   O_ST2,   O_NONE,  P_none },
  /* 3B */  { UD_Ifdivr,       O_ST0,   O_ST3,   O_NONE,  P_none },
  /* 3C */  { UD_Ifdivr,       O_ST0,   O_ST4,   O_NONE,  P_none },
  /* 3D */  { UD_Ifdivr,       O_ST0,   O_ST5,   O_NONE,  P_none },
  /* 3E */  { UD_Ifdivr,       O_ST0,   O_ST6,   O_NONE,  P_none },
  /* 3F */  { UD_Ifdivr,       O_ST0,   O_ST7,   O_NONE,  P_none },
};

static struct ud_itab_entry itab__1byte__op_d9__mod[2] = {
  /* 00 */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_D9__MOD__OP_00__REG },
  /* 01 */  { UD_Igrp_x87,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_D9__MOD__OP_01__X87 },
};

static struct ud_itab_entry itab__1byte__op_d9__mod__op_00__reg[8] = {
  /* 00 */  { UD_Ifld,         O_Md,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 02 */  { UD_Ifst,         O_Md,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 03 */  { UD_Ifstp,        O_Md,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 04 */  { UD_Ifldenv,      O_M,     O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 05 */  { UD_Ifldcw,       O_Mw,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 06 */  { UD_Ifnstenv,     O_M,     O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 07 */  { UD_Ifnstcw,      O_Mw,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
};

static struct ud_itab_entry itab__1byte__op_d9__mod__op_01__x87[64] = {
  /* 00 */  { UD_Ifld,         O_ST0,   O_ST0,   O_NONE,  P_none },
  /* 01 */  { UD_Ifld,         O_ST0,   O_ST1,   O_NONE,  P_none },
  /* 02 */  { UD_Ifld,         O_ST0,   O_ST2,   O_NONE,  P_none },
  /* 03 */  { UD_Ifld,         O_ST0,   O_ST3,   O_NONE,  P_none },
  /* 04 */  { UD_Ifld,         O_ST0,   O_ST4,   O_NONE,  P_none },
  /* 05 */  { UD_Ifld,         O_ST0,   O_ST5,   O_NONE,  P_none },
  /* 06 */  { UD_Ifld,         O_ST0,   O_ST6,   O_NONE,  P_none },
  /* 07 */  { UD_Ifld,         O_ST0,   O_ST7,   O_NONE,  P_none },
  /* 08 */  { UD_Ifxch,        O_ST0,   O_ST0,   O_NONE,  P_none },
  /* 09 */  { UD_Ifxch,        O_ST0,   O_ST1,   O_NONE,  P_none },
  /* 0A */  { UD_Ifxch,        O_ST0,   O_ST2,   O_NONE,  P_none },
  /* 0B */  { UD_Ifxch,        O_ST0,   O_ST3,   O_NONE,  P_none },
  /* 0C */  { UD_Ifxch,        O_ST0,   O_ST4,   O_NONE,  P_none },
  /* 0D */  { UD_Ifxch,        O_ST0,   O_ST5,   O_NONE,  P_none },
  /* 0E */  { UD_Ifxch,        O_ST0,   O_ST6,   O_NONE,  P_none },
  /* 0F */  { UD_Ifxch,        O_ST0,   O_ST7,   O_NONE,  P_none },
  /* 10 */  { UD_Ifnop,        O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 11 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 12 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 13 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 14 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 15 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 16 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 17 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 18 */  { UD_Ifstp1,       O_ST0,   O_NONE,  O_NONE,  P_none },
  /* 19 */  { UD_Ifstp1,       O_ST1,   O_NONE,  O_NONE,  P_none },
  /* 1A */  { UD_Ifstp1,       O_ST2,   O_NONE,  O_NONE,  P_none },
  /* 1B */  { UD_Ifstp1,       O_ST3,   O_NONE,  O_NONE,  P_none },
  /* 1C */  { UD_Ifstp1,       O_ST4,   O_NONE,  O_NONE,  P_none },
  /* 1D */  { UD_Ifstp1,       O_ST5,   O_NONE,  O_NONE,  P_none },
  /* 1E */  { UD_Ifstp1,       O_ST6,   O_NONE,  O_NONE,  P_none },
  /* 1F */  { UD_Ifstp1,       O_ST7,   O_NONE,  O_NONE,  P_none },
  /* 20 */  { UD_Ifchs,        O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 21 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 22 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 23 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 24 */  { UD_Iftst,        O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 25 */  { UD_Ifxam,        O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 26 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 27 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 28 */  { UD_Ifld1,        O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 29 */  { UD_Ifldl2t,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 2A */  { UD_Ifldl2e,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 2B */  { UD_Ifldlpi,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 2C */  { UD_Ifldlg2,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 2D */  { UD_Ifldln2,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 2E */  { UD_Ifldz,        O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 2F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 30 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 31 */  { UD_Ifyl2x,       O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 32 */  { UD_Ifptan,       O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 33 */  { UD_Ifpatan,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 34 */  { UD_Ifpxtract,    O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 35 */  { UD_Ifprem1,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 36 */  { UD_Ifdecstp,     O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 37 */  { UD_Ifncstp,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 38 */  { UD_Ifprem,       O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 39 */  { UD_Ifyl2xp1,     O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 3A */  { UD_Ifsqrt,       O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 3B */  { UD_Ifsincos,     O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 3C */  { UD_Ifrndint,     O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 3D */  { UD_Ifscale,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 3E */  { UD_Ifsin,        O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 3F */  { UD_Ifcos,        O_NONE,  O_NONE,  O_NONE,  P_none },
};

static struct ud_itab_entry itab__1byte__op_da__mod[2] = {
  /* 00 */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_DA__MOD__OP_00__REG },
  /* 01 */  { UD_Igrp_x87,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_DA__MOD__OP_01__X87 },
};

static struct ud_itab_entry itab__1byte__op_da__mod__op_00__reg[8] = {
  /* 00 */  { UD_Ifiadd,       O_Md,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Ifimul,       O_Md,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 02 */  { UD_Ificom,       O_Md,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 03 */  { UD_Ificomp,      O_Md,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 04 */  { UD_Ifisub,       O_Md,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 05 */  { UD_Ifisubr,      O_Md,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 06 */  { UD_Ifidiv,       O_Md,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 07 */  { UD_Ifidivr,      O_Md,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
};

static struct ud_itab_entry itab__1byte__op_da__mod__op_01__x87[64] = {
  /* 00 */  { UD_Ifcmovb,      O_ST0,   O_ST0,   O_NONE,  P_none },
  /* 01 */  { UD_Ifcmovb,      O_ST0,   O_ST1,   O_NONE,  P_none },
  /* 02 */  { UD_Ifcmovb,      O_ST0,   O_ST2,   O_NONE,  P_none },
  /* 03 */  { UD_Ifcmovb,      O_ST0,   O_ST3,   O_NONE,  P_none },
  /* 04 */  { UD_Ifcmovb,      O_ST0,   O_ST4,   O_NONE,  P_none },
  /* 05 */  { UD_Ifcmovb,      O_ST0,   O_ST5,   O_NONE,  P_none },
  /* 06 */  { UD_Ifcmovb,      O_ST0,   O_ST6,   O_NONE,  P_none },
  /* 07 */  { UD_Ifcmovb,      O_ST0,   O_ST7,   O_NONE,  P_none },
  /* 08 */  { UD_Ifcmove,      O_ST0,   O_ST0,   O_NONE,  P_none },
  /* 09 */  { UD_Ifcmove,      O_ST0,   O_ST1,   O_NONE,  P_none },
  /* 0A */  { UD_Ifcmove,      O_ST0,   O_ST2,   O_NONE,  P_none },
  /* 0B */  { UD_Ifcmove,      O_ST0,   O_ST3,   O_NONE,  P_none },
  /* 0C */  { UD_Ifcmove,      O_ST0,   O_ST4,   O_NONE,  P_none },
  /* 0D */  { UD_Ifcmove,      O_ST0,   O_ST5,   O_NONE,  P_none },
  /* 0E */  { UD_Ifcmove,      O_ST0,   O_ST6,   O_NONE,  P_none },
  /* 0F */  { UD_Ifcmove,      O_ST0,   O_ST7,   O_NONE,  P_none },
  /* 10 */  { UD_Ifcmovbe,     O_ST0,   O_ST0,   O_NONE,  P_none },
  /* 11 */  { UD_Ifcmovbe,     O_ST0,   O_ST1,   O_NONE,  P_none },
  /* 12 */  { UD_Ifcmovbe,     O_ST0,   O_ST2,   O_NONE,  P_none },
  /* 13 */  { UD_Ifcmovbe,     O_ST0,   O_ST3,   O_NONE,  P_none },
  /* 14 */  { UD_Ifcmovbe,     O_ST0,   O_ST4,   O_NONE,  P_none },
  /* 15 */  { UD_Ifcmovbe,     O_ST0,   O_ST5,   O_NONE,  P_none },
  /* 16 */  { UD_Ifcmovbe,     O_ST0,   O_ST6,   O_NONE,  P_none },
  /* 17 */  { UD_Ifcmovbe,     O_ST0,   O_ST7,   O_NONE,  P_none },
  /* 18 */  { UD_Ifcmovu,      O_ST0,   O_ST0,   O_NONE,  P_none },
  /* 19 */  { UD_Ifcmovu,      O_ST0,   O_ST1,   O_NONE,  P_none },
  /* 1A */  { UD_Ifcmovu,      O_ST0,   O_ST2,   O_NONE,  P_none },
  /* 1B */  { UD_Ifcmovu,      O_ST0,   O_ST3,   O_NONE,  P_none },
  /* 1C */  { UD_Ifcmovu,      O_ST0,   O_ST4,   O_NONE,  P_none },
  /* 1D */  { UD_Ifcmovu,      O_ST0,   O_ST5,   O_NONE,  P_none },
  /* 1E */  { UD_Ifcmovu,      O_ST0,   O_ST6,   O_NONE,  P_none },
  /* 1F */  { UD_Ifcmovu,      O_ST0,   O_ST7,   O_NONE,  P_none },
  /* 20 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 21 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 22 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 23 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 24 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 25 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 26 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 27 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 28 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 29 */  { UD_Ifucompp,     O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 2A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 2B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 2C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 2D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 2E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 2F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 30 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 31 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 32 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 33 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 34 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 35 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 36 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 37 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 38 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 39 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__1byte__op_db__mod[2] = {
  /* 00 */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_DB__MOD__OP_00__REG },
  /* 01 */  { UD_Igrp_x87,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_DB__MOD__OP_01__X87 },
};

static struct ud_itab_entry itab__1byte__op_db__mod__op_00__reg[8] = {
  /* 00 */  { UD_Ifild,        O_Md,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Ifisttp,      O_Md,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 02 */  { UD_Ifist,        O_Md,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 03 */  { UD_Ifistp,       O_Md,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 04 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 05 */  { UD_Ifld,         O_Mt,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 06 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 07 */  { UD_Ifstp,        O_Mt,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
};

static struct ud_itab_entry itab__1byte__op_db__mod__op_01__x87[64] = {
  /* 00 */  { UD_Ifcmovnb,     O_ST0,   O_ST0,   O_NONE,  P_none },
  /* 01 */  { UD_Ifcmovnb,     O_ST0,   O_ST1,   O_NONE,  P_none },
  /* 02 */  { UD_Ifcmovnb,     O_ST0,   O_ST2,   O_NONE,  P_none },
  /* 03 */  { UD_Ifcmovnb,     O_ST0,   O_ST3,   O_NONE,  P_none },
  /* 04 */  { UD_Ifcmovnb,     O_ST0,   O_ST4,   O_NONE,  P_none },
  /* 05 */  { UD_Ifcmovnb,     O_ST0,   O_ST5,   O_NONE,  P_none },
  /* 06 */  { UD_Ifcmovnb,     O_ST0,   O_ST6,   O_NONE,  P_none },
  /* 07 */  { UD_Ifcmovnb,     O_ST0,   O_ST7,   O_NONE,  P_none },
  /* 08 */  { UD_Ifcmovne,     O_ST0,   O_ST0,   O_NONE,  P_none },
  /* 09 */  { UD_Ifcmovne,     O_ST0,   O_ST1,   O_NONE,  P_none },
  /* 0A */  { UD_Ifcmovne,     O_ST0,   O_ST2,   O_NONE,  P_none },
  /* 0B */  { UD_Ifcmovne,     O_ST0,   O_ST3,   O_NONE,  P_none },
  /* 0C */  { UD_Ifcmovne,     O_ST0,   O_ST4,   O_NONE,  P_none },
  /* 0D */  { UD_Ifcmovne,     O_ST0,   O_ST5,   O_NONE,  P_none },
  /* 0E */  { UD_Ifcmovne,     O_ST0,   O_ST6,   O_NONE,  P_none },
  /* 0F */  { UD_Ifcmovne,     O_ST0,   O_ST7,   O_NONE,  P_none },
  /* 10 */  { UD_Ifcmovnbe,    O_ST0,   O_ST0,   O_NONE,  P_none },
  /* 11 */  { UD_Ifcmovnbe,    O_ST0,   O_ST1,   O_NONE,  P_none },
  /* 12 */  { UD_Ifcmovnbe,    O_ST0,   O_ST2,   O_NONE,  P_none },
  /* 13 */  { UD_Ifcmovnbe,    O_ST0,   O_ST3,   O_NONE,  P_none },
  /* 14 */  { UD_Ifcmovnbe,    O_ST0,   O_ST4,   O_NONE,  P_none },
  /* 15 */  { UD_Ifcmovnbe,    O_ST0,   O_ST5,   O_NONE,  P_none },
  /* 16 */  { UD_Ifcmovnbe,    O_ST0,   O_ST6,   O_NONE,  P_none },
  /* 17 */  { UD_Ifcmovnbe,    O_ST0,   O_ST7,   O_NONE,  P_none },
  /* 18 */  { UD_Ifcmovnu,     O_ST0,   O_ST0,   O_NONE,  P_none },
  /* 19 */  { UD_Ifcmovnu,     O_ST0,   O_ST1,   O_NONE,  P_none },
  /* 1A */  { UD_Ifcmovnu,     O_ST0,   O_ST2,   O_NONE,  P_none },
  /* 1B */  { UD_Ifcmovnu,     O_ST0,   O_ST3,   O_NONE,  P_none },
  /* 1C */  { UD_Ifcmovnu,     O_ST0,   O_ST4,   O_NONE,  P_none },
  /* 1D */  { UD_Ifcmovnu,     O_ST0,   O_ST5,   O_NONE,  P_none },
  /* 1E */  { UD_Ifcmovnu,     O_ST0,   O_ST6,   O_NONE,  P_none },
  /* 1F */  { UD_Ifcmovnu,     O_ST0,   O_ST7,   O_NONE,  P_none },
  /* 20 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 21 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 22 */  { UD_Ifclex,       O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 23 */  { UD_Ifninit,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 24 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 25 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 26 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 27 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 28 */  { UD_Ifucomi,      O_ST0,   O_ST0,   O_NONE,  P_none },
  /* 29 */  { UD_Ifucomi,      O_ST0,   O_ST1,   O_NONE,  P_none },
  /* 2A */  { UD_Ifucomi,      O_ST0,   O_ST2,   O_NONE,  P_none },
  /* 2B */  { UD_Ifucomi,      O_ST0,   O_ST3,   O_NONE,  P_none },
  /* 2C */  { UD_Ifucomi,      O_ST0,   O_ST4,   O_NONE,  P_none },
  /* 2D */  { UD_Ifucomi,      O_ST0,   O_ST5,   O_NONE,  P_none },
  /* 2E */  { UD_Ifucomi,      O_ST0,   O_ST6,   O_NONE,  P_none },
  /* 2F */  { UD_Ifucomi,      O_ST0,   O_ST7,   O_NONE,  P_none },
  /* 30 */  { UD_Ifcomi,       O_ST0,   O_ST0,   O_NONE,  P_none },
  /* 31 */  { UD_Ifcomi,       O_ST0,   O_ST1,   O_NONE,  P_none },
  /* 32 */  { UD_Ifcomi,       O_ST0,   O_ST2,   O_NONE,  P_none },
  /* 33 */  { UD_Ifcomi,       O_ST0,   O_ST3,   O_NONE,  P_none },
  /* 34 */  { UD_Ifcomi,       O_ST0,   O_ST4,   O_NONE,  P_none },
  /* 35 */  { UD_Ifcomi,       O_ST0,   O_ST5,   O_NONE,  P_none },
  /* 36 */  { UD_Ifcomi,       O_ST0,   O_ST6,   O_NONE,  P_none },
  /* 37 */  { UD_Ifcomi,       O_ST0,   O_ST7,   O_NONE,  P_none },
  /* 38 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 39 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__1byte__op_dc__mod[2] = {
  /* 00 */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_DC__MOD__OP_00__REG },
  /* 01 */  { UD_Igrp_x87,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_DC__MOD__OP_01__X87 },
};

static struct ud_itab_entry itab__1byte__op_dc__mod__op_00__reg[8] = {
  /* 00 */  { UD_Ifadd,        O_Mq,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Ifmul,        O_Mq,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 02 */  { UD_Ifcom,        O_Mq,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 03 */  { UD_Ifcomp,       O_Mq,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 04 */  { UD_Ifsub,        O_Mq,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 05 */  { UD_Ifsubr,       O_Mq,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 06 */  { UD_Ifdiv,        O_Mq,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 07 */  { UD_Ifdivr,       O_Mq,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
};

static struct ud_itab_entry itab__1byte__op_dc__mod__op_01__x87[64] = {
  /* 00 */  { UD_Ifadd,        O_ST0,   O_ST0,   O_NONE,  P_none },
  /* 01 */  { UD_Ifadd,        O_ST1,   O_ST0,   O_NONE,  P_none },
  /* 02 */  { UD_Ifadd,        O_ST2,   O_ST0,   O_NONE,  P_none },
  /* 03 */  { UD_Ifadd,        O_ST3,   O_ST0,   O_NONE,  P_none },
  /* 04 */  { UD_Ifadd,        O_ST4,   O_ST0,   O_NONE,  P_none },
  /* 05 */  { UD_Ifadd,        O_ST5,   O_ST0,   O_NONE,  P_none },
  /* 06 */  { UD_Ifadd,        O_ST6,   O_ST0,   O_NONE,  P_none },
  /* 07 */  { UD_Ifadd,        O_ST7,   O_ST0,   O_NONE,  P_none },
  /* 08 */  { UD_Ifmul,        O_ST0,   O_ST0,   O_NONE,  P_none },
  /* 09 */  { UD_Ifmul,        O_ST1,   O_ST0,   O_NONE,  P_none },
  /* 0A */  { UD_Ifmul,        O_ST2,   O_ST0,   O_NONE,  P_none },
  /* 0B */  { UD_Ifmul,        O_ST3,   O_ST0,   O_NONE,  P_none },
  /* 0C */  { UD_Ifmul,        O_ST4,   O_ST0,   O_NONE,  P_none },
  /* 0D */  { UD_Ifmul,        O_ST5,   O_ST0,   O_NONE,  P_none },
  /* 0E */  { UD_Ifmul,        O_ST6,   O_ST0,   O_NONE,  P_none },
  /* 0F */  { UD_Ifmul,        O_ST7,   O_ST0,   O_NONE,  P_none },
  /* 10 */  { UD_Ifcom2,       O_ST0,   O_NONE,  O_NONE,  P_none },
  /* 11 */  { UD_Ifcom2,       O_ST1,   O_NONE,  O_NONE,  P_none },
  /* 12 */  { UD_Ifcom2,       O_ST2,   O_NONE,  O_NONE,  P_none },
  /* 13 */  { UD_Ifcom2,       O_ST3,   O_NONE,  O_NONE,  P_none },
  /* 14 */  { UD_Ifcom2,       O_ST4,   O_NONE,  O_NONE,  P_none },
  /* 15 */  { UD_Ifcom2,       O_ST5,   O_NONE,  O_NONE,  P_none },
  /* 16 */  { UD_Ifcom2,       O_ST6,   O_NONE,  O_NONE,  P_none },
  /* 17 */  { UD_Ifcom2,       O_ST7,   O_NONE,  O_NONE,  P_none },
  /* 18 */  { UD_Ifcomp3,      O_ST0,   O_NONE,  O_NONE,  P_none },
  /* 19 */  { UD_Ifcomp3,      O_ST1,   O_NONE,  O_NONE,  P_none },
  /* 1A */  { UD_Ifcomp3,      O_ST2,   O_NONE,  O_NONE,  P_none },
  /* 1B */  { UD_Ifcomp3,      O_ST3,   O_NONE,  O_NONE,  P_none },
  /* 1C */  { UD_Ifcomp3,      O_ST4,   O_NONE,  O_NONE,  P_none },
  /* 1D */  { UD_Ifcomp3,      O_ST5,   O_NONE,  O_NONE,  P_none },
  /* 1E */  { UD_Ifcomp3,      O_ST6,   O_NONE,  O_NONE,  P_none },
  /* 1F */  { UD_Ifcomp3,      O_ST7,   O_NONE,  O_NONE,  P_none },
  /* 20 */  { UD_Ifsubr,       O_ST0,   O_ST0,   O_NONE,  P_none },
  /* 21 */  { UD_Ifsubr,       O_ST1,   O_ST0,   O_NONE,  P_none },
  /* 22 */  { UD_Ifsubr,       O_ST2,   O_ST0,   O_NONE,  P_none },
  /* 23 */  { UD_Ifsubr,       O_ST3,   O_ST0,   O_NONE,  P_none },
  /* 24 */  { UD_Ifsubr,       O_ST4,   O_ST0,   O_NONE,  P_none },
  /* 25 */  { UD_Ifsubr,       O_ST5,   O_ST0,   O_NONE,  P_none },
  /* 26 */  { UD_Ifsubr,       O_ST6,   O_ST0,   O_NONE,  P_none },
  /* 27 */  { UD_Ifsubr,       O_ST7,   O_ST0,   O_NONE,  P_none },
  /* 28 */  { UD_Ifsub,        O_ST0,   O_ST0,   O_NONE,  P_none },
  /* 29 */  { UD_Ifsub,        O_ST1,   O_ST0,   O_NONE,  P_none },
  /* 2A */  { UD_Ifsub,        O_ST2,   O_ST0,   O_NONE,  P_none },
  /* 2B */  { UD_Ifsub,        O_ST3,   O_ST0,   O_NONE,  P_none },
  /* 2C */  { UD_Ifsub,        O_ST4,   O_ST0,   O_NONE,  P_none },
  /* 2D */  { UD_Ifsub,        O_ST5,   O_ST0,   O_NONE,  P_none },
  /* 2E */  { UD_Ifsub,        O_ST6,   O_ST0,   O_NONE,  P_none },
  /* 2F */  { UD_Ifsub,        O_ST7,   O_ST0,   O_NONE,  P_none },
  /* 30 */  { UD_Ifdivr,       O_ST0,   O_ST0,   O_NONE,  P_none },
  /* 31 */  { UD_Ifdivr,       O_ST1,   O_ST0,   O_NONE,  P_none },
  /* 32 */  { UD_Ifdivr,       O_ST2,   O_ST0,   O_NONE,  P_none },
  /* 33 */  { UD_Ifdivr,       O_ST3,   O_ST0,   O_NONE,  P_none },
  /* 34 */  { UD_Ifdivr,       O_ST4,   O_ST0,   O_NONE,  P_none },
  /* 35 */  { UD_Ifdivr,       O_ST5,   O_ST0,   O_NONE,  P_none },
  /* 36 */  { UD_Ifdivr,       O_ST6,   O_ST0,   O_NONE,  P_none },
  /* 37 */  { UD_Ifdivr,       O_ST7,   O_ST0,   O_NONE,  P_none },
  /* 38 */  { UD_Ifdiv,        O_ST0,   O_ST0,   O_NONE,  P_none },
  /* 39 */  { UD_Ifdiv,        O_ST1,   O_ST0,   O_NONE,  P_none },
  /* 3A */  { UD_Ifdiv,        O_ST2,   O_ST0,   O_NONE,  P_none },
  /* 3B */  { UD_Ifdiv,        O_ST3,   O_ST0,   O_NONE,  P_none },
  /* 3C */  { UD_Ifdiv,        O_ST4,   O_ST0,   O_NONE,  P_none },
  /* 3D */  { UD_Ifdiv,        O_ST5,   O_ST0,   O_NONE,  P_none },
  /* 3E */  { UD_Ifdiv,        O_ST6,   O_ST0,   O_NONE,  P_none },
  /* 3F */  { UD_Ifdiv,        O_ST7,   O_ST0,   O_NONE,  P_none },
};

static struct ud_itab_entry itab__1byte__op_dd__mod[2] = {
  /* 00 */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_DD__MOD__OP_00__REG },
  /* 01 */  { UD_Igrp_x87,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_DD__MOD__OP_01__X87 },
};

static struct ud_itab_entry itab__1byte__op_dd__mod__op_00__reg[8] = {
  /* 00 */  { UD_Ifld,         O_Mq,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Ifisttp,      O_Mq,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 02 */  { UD_Ifst,         O_Mq,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 03 */  { UD_Ifstp,        O_Mq,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 04 */  { UD_Ifrstor,      O_M,     O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 05 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 06 */  { UD_Ifnsave,      O_M,     O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 07 */  { UD_Ifnstsw,      O_Mw,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
};

static struct ud_itab_entry itab__1byte__op_dd__mod__op_01__x87[64] = {
  /* 00 */  { UD_Iffree,       O_ST0,   O_NONE,  O_NONE,  P_none },
  /* 01 */  { UD_Iffree,       O_ST1,   O_NONE,  O_NONE,  P_none },
  /* 02 */  { UD_Iffree,       O_ST2,   O_NONE,  O_NONE,  P_none },
  /* 03 */  { UD_Iffree,       O_ST3,   O_NONE,  O_NONE,  P_none },
  /* 04 */  { UD_Iffree,       O_ST4,   O_NONE,  O_NONE,  P_none },
  /* 05 */  { UD_Iffree,       O_ST5,   O_NONE,  O_NONE,  P_none },
  /* 06 */  { UD_Iffree,       O_ST6,   O_NONE,  O_NONE,  P_none },
  /* 07 */  { UD_Iffree,       O_ST7,   O_NONE,  O_NONE,  P_none },
  /* 08 */  { UD_Ifxch4,       O_ST0,   O_NONE,  O_NONE,  P_none },
  /* 09 */  { UD_Ifxch4,       O_ST1,   O_NONE,  O_NONE,  P_none },
  /* 0A */  { UD_Ifxch4,       O_ST2,   O_NONE,  O_NONE,  P_none },
  /* 0B */  { UD_Ifxch4,       O_ST3,   O_NONE,  O_NONE,  P_none },
  /* 0C */  { UD_Ifxch4,       O_ST4,   O_NONE,  O_NONE,  P_none },
  /* 0D */  { UD_Ifxch4,       O_ST5,   O_NONE,  O_NONE,  P_none },
  /* 0E */  { UD_Ifxch4,       O_ST6,   O_NONE,  O_NONE,  P_none },
  /* 0F */  { UD_Ifxch4,       O_ST7,   O_NONE,  O_NONE,  P_none },
  /* 10 */  { UD_Ifst,         O_ST0,   O_NONE,  O_NONE,  P_none },
  /* 11 */  { UD_Ifst,         O_ST1,   O_NONE,  O_NONE,  P_none },
  /* 12 */  { UD_Ifst,         O_ST2,   O_NONE,  O_NONE,  P_none },
  /* 13 */  { UD_Ifst,         O_ST3,   O_NONE,  O_NONE,  P_none },
  /* 14 */  { UD_Ifst,         O_ST4,   O_NONE,  O_NONE,  P_none },
  /* 15 */  { UD_Ifst,         O_ST5,   O_NONE,  O_NONE,  P_none },
  /* 16 */  { UD_Ifst,         O_ST6,   O_NONE,  O_NONE,  P_none },
  /* 17 */  { UD_Ifst,         O_ST7,   O_NONE,  O_NONE,  P_none },
  /* 18 */  { UD_Ifstp,        O_ST0,   O_NONE,  O_NONE,  P_none },
  /* 19 */  { UD_Ifstp,        O_ST1,   O_NONE,  O_NONE,  P_none },
  /* 1A */  { UD_Ifstp,        O_ST2,   O_NONE,  O_NONE,  P_none },
  /* 1B */  { UD_Ifstp,        O_ST3,   O_NONE,  O_NONE,  P_none },
  /* 1C */  { UD_Ifstp,        O_ST4,   O_NONE,  O_NONE,  P_none },
  /* 1D */  { UD_Ifstp,        O_ST5,   O_NONE,  O_NONE,  P_none },
  /* 1E */  { UD_Ifstp,        O_ST6,   O_NONE,  O_NONE,  P_none },
  /* 1F */  { UD_Ifstp,        O_ST7,   O_NONE,  O_NONE,  P_none },
  /* 20 */  { UD_Ifucom,       O_ST0,   O_NONE,  O_NONE,  P_none },
  /* 21 */  { UD_Ifucom,       O_ST1,   O_NONE,  O_NONE,  P_none },
  /* 22 */  { UD_Ifucom,       O_ST2,   O_NONE,  O_NONE,  P_none },
  /* 23 */  { UD_Ifucom,       O_ST3,   O_NONE,  O_NONE,  P_none },
  /* 24 */  { UD_Ifucom,       O_ST4,   O_NONE,  O_NONE,  P_none },
  /* 25 */  { UD_Ifucom,       O_ST5,   O_NONE,  O_NONE,  P_none },
  /* 26 */  { UD_Ifucom,       O_ST6,   O_NONE,  O_NONE,  P_none },
  /* 27 */  { UD_Ifucom,       O_ST7,   O_NONE,  O_NONE,  P_none },
  /* 28 */  { UD_Ifucomp,      O_ST0,   O_NONE,  O_NONE,  P_none },
  /* 29 */  { UD_Ifucomp,      O_ST1,   O_NONE,  O_NONE,  P_none },
  /* 2A */  { UD_Ifucomp,      O_ST2,   O_NONE,  O_NONE,  P_none },
  /* 2B */  { UD_Ifucomp,      O_ST3,   O_NONE,  O_NONE,  P_none },
  /* 2C */  { UD_Ifucomp,      O_ST4,   O_NONE,  O_NONE,  P_none },
  /* 2D */  { UD_Ifucomp,      O_ST5,   O_NONE,  O_NONE,  P_none },
  /* 2E */  { UD_Ifucomp,      O_ST6,   O_NONE,  O_NONE,  P_none },
  /* 2F */  { UD_Ifucomp,      O_ST7,   O_NONE,  O_NONE,  P_none },
  /* 30 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 31 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 32 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 33 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 34 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 35 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 36 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 37 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 38 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 39 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__1byte__op_de__mod[2] = {
  /* 00 */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_DE__MOD__OP_00__REG },
  /* 01 */  { UD_Igrp_x87,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_DE__MOD__OP_01__X87 },
};

static struct ud_itab_entry itab__1byte__op_de__mod__op_00__reg[8] = {
  /* 00 */  { UD_Ifiadd,       O_Mw,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Ifimul,       O_Mw,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 02 */  { UD_Ificom,       O_Mw,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 03 */  { UD_Ificomp,      O_Mw,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 04 */  { UD_Ifisub,       O_Mw,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 05 */  { UD_Ifisubr,      O_Mw,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 06 */  { UD_Ifidiv,       O_Mw,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 07 */  { UD_Ifidivr,      O_Mw,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
};

static struct ud_itab_entry itab__1byte__op_de__mod__op_01__x87[64] = {
  /* 00 */  { UD_Ifaddp,       O_ST0,   O_ST0,   O_NONE,  P_none },
  /* 01 */  { UD_Ifaddp,       O_ST1,   O_ST0,   O_NONE,  P_none },
  /* 02 */  { UD_Ifaddp,       O_ST2,   O_ST0,   O_NONE,  P_none },
  /* 03 */  { UD_Ifaddp,       O_ST3,   O_ST0,   O_NONE,  P_none },
  /* 04 */  { UD_Ifaddp,       O_ST4,   O_ST0,   O_NONE,  P_none },
  /* 05 */  { UD_Ifaddp,       O_ST5,   O_ST0,   O_NONE,  P_none },
  /* 06 */  { UD_Ifaddp,       O_ST6,   O_ST0,   O_NONE,  P_none },
  /* 07 */  { UD_Ifaddp,       O_ST7,   O_ST0,   O_NONE,  P_none },
  /* 08 */  { UD_Ifmulp,       O_ST0,   O_ST0,   O_NONE,  P_none },
  /* 09 */  { UD_Ifmulp,       O_ST1,   O_ST0,   O_NONE,  P_none },
  /* 0A */  { UD_Ifmulp,       O_ST2,   O_ST0,   O_NONE,  P_none },
  /* 0B */  { UD_Ifmulp,       O_ST3,   O_ST0,   O_NONE,  P_none },
  /* 0C */  { UD_Ifmulp,       O_ST4,   O_ST0,   O_NONE,  P_none },
  /* 0D */  { UD_Ifmulp,       O_ST5,   O_ST0,   O_NONE,  P_none },
  /* 0E */  { UD_Ifmulp,       O_ST6,   O_ST0,   O_NONE,  P_none },
  /* 0F */  { UD_Ifmulp,       O_ST7,   O_ST0,   O_NONE,  P_none },
  /* 10 */  { UD_Ifcomp5,      O_ST0,   O_NONE,  O_NONE,  P_none },
  /* 11 */  { UD_Ifcomp5,      O_ST1,   O_NONE,  O_NONE,  P_none },
  /* 12 */  { UD_Ifcomp5,      O_ST2,   O_NONE,  O_NONE,  P_none },
  /* 13 */  { UD_Ifcomp5,      O_ST3,   O_NONE,  O_NONE,  P_none },
  /* 14 */  { UD_Ifcomp5,      O_ST4,   O_NONE,  O_NONE,  P_none },
  /* 15 */  { UD_Ifcomp5,      O_ST5,   O_NONE,  O_NONE,  P_none },
  /* 16 */  { UD_Ifcomp5,      O_ST6,   O_NONE,  O_NONE,  P_none },
  /* 17 */  { UD_Ifcomp5,      O_ST7,   O_NONE,  O_NONE,  P_none },
  /* 18 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 19 */  { UD_Ifcompp,      O_NONE,  O_NONE,  O_NONE,  P_none },
  /* 1A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 1B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 1C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 1D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 1E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 1F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 20 */  { UD_Ifsubrp,      O_ST0,   O_ST0,   O_NONE,  P_none },
  /* 21 */  { UD_Ifsubrp,      O_ST1,   O_ST0,   O_NONE,  P_none },
  /* 22 */  { UD_Ifsubrp,      O_ST2,   O_ST0,   O_NONE,  P_none },
  /* 23 */  { UD_Ifsubrp,      O_ST3,   O_ST0,   O_NONE,  P_none },
  /* 24 */  { UD_Ifsubrp,      O_ST4,   O_ST0,   O_NONE,  P_none },
  /* 25 */  { UD_Ifsubrp,      O_ST5,   O_ST0,   O_NONE,  P_none },
  /* 26 */  { UD_Ifsubrp,      O_ST6,   O_ST0,   O_NONE,  P_none },
  /* 27 */  { UD_Ifsubrp,      O_ST7,   O_ST0,   O_NONE,  P_none },
  /* 28 */  { UD_Ifsubp,       O_ST0,   O_ST0,   O_NONE,  P_none },
  /* 29 */  { UD_Ifsubp,       O_ST1,   O_ST0,   O_NONE,  P_none },
  /* 2A */  { UD_Ifsubp,       O_ST2,   O_ST0,   O_NONE,  P_none },
  /* 2B */  { UD_Ifsubp,       O_ST3,   O_ST0,   O_NONE,  P_none },
  /* 2C */  { UD_Ifsubp,       O_ST4,   O_ST0,   O_NONE,  P_none },
  /* 2D */  { UD_Ifsubp,       O_ST5,   O_ST0,   O_NONE,  P_none },
  /* 2E */  { UD_Ifsubp,       O_ST6,   O_ST0,   O_NONE,  P_none },
  /* 2F */  { UD_Ifsubp,       O_ST7,   O_ST0,   O_NONE,  P_none },
  /* 30 */  { UD_Ifdivrp,      O_ST0,   O_ST0,   O_NONE,  P_none },
  /* 31 */  { UD_Ifdivrp,      O_ST1,   O_ST0,   O_NONE,  P_none },
  /* 32 */  { UD_Ifdivrp,      O_ST2,   O_ST0,   O_NONE,  P_none },
  /* 33 */  { UD_Ifdivrp,      O_ST3,   O_ST0,   O_NONE,  P_none },
  /* 34 */  { UD_Ifdivrp,      O_ST4,   O_ST0,   O_NONE,  P_none },
  /* 35 */  { UD_Ifdivrp,      O_ST5,   O_ST0,   O_NONE,  P_none },
  /* 36 */  { UD_Ifdivrp,      O_ST6,   O_ST0,   O_NONE,  P_none },
  /* 37 */  { UD_Ifdivrp,      O_ST7,   O_ST0,   O_NONE,  P_none },
  /* 38 */  { UD_Ifdivp,       O_ST0,   O_ST0,   O_NONE,  P_none },
  /* 39 */  { UD_Ifdivp,       O_ST1,   O_ST0,   O_NONE,  P_none },
  /* 3A */  { UD_Ifdivp,       O_ST2,   O_ST0,   O_NONE,  P_none },
  /* 3B */  { UD_Ifdivp,       O_ST3,   O_ST0,   O_NONE,  P_none },
  /* 3C */  { UD_Ifdivp,       O_ST4,   O_ST0,   O_NONE,  P_none },
  /* 3D */  { UD_Ifdivp,       O_ST5,   O_ST0,   O_NONE,  P_none },
  /* 3E */  { UD_Ifdivp,       O_ST6,   O_ST0,   O_NONE,  P_none },
  /* 3F */  { UD_Ifdivp,       O_ST7,   O_ST0,   O_NONE,  P_none },
};

static struct ud_itab_entry itab__1byte__op_df__mod[2] = {
  /* 00 */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_DF__MOD__OP_00__REG },
  /* 01 */  { UD_Igrp_x87,     O_NONE, O_NONE, O_NONE,    ITAB__1BYTE__OP_DF__MOD__OP_01__X87 },
};

static struct ud_itab_entry itab__1byte__op_df__mod__op_00__reg[8] = {
  /* 00 */  { UD_Ifild,        O_Mw,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Ifisttp,      O_Mw,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 02 */  { UD_Ifist,        O_Mw,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 03 */  { UD_Ifistp,       O_Mw,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 04 */  { UD_Ifbld,        O_Mt,    O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 05 */  { UD_Ifild,        O_Mq,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 06 */  { UD_Ifbstp,       O_Mt,    O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 07 */  { UD_Ifistp,       O_Mq,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
};

static struct ud_itab_entry itab__1byte__op_df__mod__op_01__x87[64] = {
  /* 00 */  { UD_Iffreep,      O_ST0,   O_NONE,  O_NONE,  P_none },
  /* 01 */  { UD_Iffreep,      O_ST1,   O_NONE,  O_NONE,  P_none },
  /* 02 */  { UD_Iffreep,      O_ST2,   O_NONE,  O_NONE,  P_none },
  /* 03 */  { UD_Iffreep,      O_ST3,   O_NONE,  O_NONE,  P_none },
  /* 04 */  { UD_Iffreep,      O_ST4,   O_NONE,  O_NONE,  P_none },
  /* 05 */  { UD_Iffreep,      O_ST5,   O_NONE,  O_NONE,  P_none },
  /* 06 */  { UD_Iffreep,      O_ST6,   O_NONE,  O_NONE,  P_none },
  /* 07 */  { UD_Iffreep,      O_ST7,   O_NONE,  O_NONE,  P_none },
  /* 08 */  { UD_Ifxch7,       O_ST0,   O_NONE,  O_NONE,  P_none },
  /* 09 */  { UD_Ifxch7,       O_ST1,   O_NONE,  O_NONE,  P_none },
  /* 0A */  { UD_Ifxch7,       O_ST2,   O_NONE,  O_NONE,  P_none },
  /* 0B */  { UD_Ifxch7,       O_ST3,   O_NONE,  O_NONE,  P_none },
  /* 0C */  { UD_Ifxch7,       O_ST4,   O_NONE,  O_NONE,  P_none },
  /* 0D */  { UD_Ifxch7,       O_ST5,   O_NONE,  O_NONE,  P_none },
  /* 0E */  { UD_Ifxch7,       O_ST6,   O_NONE,  O_NONE,  P_none },
  /* 0F */  { UD_Ifxch7,       O_ST7,   O_NONE,  O_NONE,  P_none },
  /* 10 */  { UD_Ifstp8,       O_ST0,   O_NONE,  O_NONE,  P_none },
  /* 11 */  { UD_Ifstp8,       O_ST1,   O_NONE,  O_NONE,  P_none },
  /* 12 */  { UD_Ifstp8,       O_ST2,   O_NONE,  O_NONE,  P_none },
  /* 13 */  { UD_Ifstp8,       O_ST3,   O_NONE,  O_NONE,  P_none },
  /* 14 */  { UD_Ifstp8,       O_ST4,   O_NONE,  O_NONE,  P_none },
  /* 15 */  { UD_Ifstp8,       O_ST5,   O_NONE,  O_NONE,  P_none },
  /* 16 */  { UD_Ifstp8,       O_ST6,   O_NONE,  O_NONE,  P_none },
  /* 17 */  { UD_Ifstp8,       O_ST7,   O_NONE,  O_NONE,  P_none },
  /* 18 */  { UD_Ifstp9,       O_ST0,   O_NONE,  O_NONE,  P_none },
  /* 19 */  { UD_Ifstp9,       O_ST1,   O_NONE,  O_NONE,  P_none },
  /* 1A */  { UD_Ifstp9,       O_ST2,   O_NONE,  O_NONE,  P_none },
  /* 1B */  { UD_Ifstp9,       O_ST3,   O_NONE,  O_NONE,  P_none },
  /* 1C */  { UD_Ifstp9,       O_ST4,   O_NONE,  O_NONE,  P_none },
  /* 1D */  { UD_Ifstp9,       O_ST5,   O_NONE,  O_NONE,  P_none },
  /* 1E */  { UD_Ifstp9,       O_ST6,   O_NONE,  O_NONE,  P_none },
  /* 1F */  { UD_Ifstp9,       O_ST7,   O_NONE,  O_NONE,  P_none },
  /* 20 */  { UD_Ifnstsw,      O_AX,    O_NONE,  O_NONE,  P_none },
  /* 21 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 22 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 23 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 24 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 25 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 26 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 27 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 28 */  { UD_Ifucomip,     O_ST0,   O_ST0,   O_NONE,  P_none },
  /* 29 */  { UD_Ifucomip,     O_ST0,   O_ST1,   O_NONE,  P_none },
  /* 2A */  { UD_Ifucomip,     O_ST0,   O_ST2,   O_NONE,  P_none },
  /* 2B */  { UD_Ifucomip,     O_ST0,   O_ST3,   O_NONE,  P_none },
  /* 2C */  { UD_Ifucomip,     O_ST0,   O_ST4,   O_NONE,  P_none },
  /* 2D */  { UD_Ifucomip,     O_ST0,   O_ST5,   O_NONE,  P_none },
  /* 2E */  { UD_Ifucomip,     O_ST0,   O_ST6,   O_NONE,  P_none },
  /* 2F */  { UD_Ifucomip,     O_ST0,   O_ST7,   O_NONE,  P_none },
  /* 30 */  { UD_Ifcomip,      O_ST0,   O_ST0,   O_NONE,  P_none },
  /* 31 */  { UD_Ifcomip,      O_ST0,   O_ST1,   O_NONE,  P_none },
  /* 32 */  { UD_Ifcomip,      O_ST0,   O_ST2,   O_NONE,  P_none },
  /* 33 */  { UD_Ifcomip,      O_ST0,   O_ST3,   O_NONE,  P_none },
  /* 34 */  { UD_Ifcomip,      O_ST0,   O_ST4,   O_NONE,  P_none },
  /* 35 */  { UD_Ifcomip,      O_ST0,   O_ST5,   O_NONE,  P_none },
  /* 36 */  { UD_Ifcomip,      O_ST0,   O_ST6,   O_NONE,  P_none },
  /* 37 */  { UD_Ifcomip,      O_ST0,   O_ST7,   O_NONE,  P_none },
  /* 38 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 39 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__1byte__op_e3__asize[3] = {
  /* 00 */  { UD_Ijcxz,        O_Jb,    O_NONE,  O_NONE,  P_aso },
  /* 01 */  { UD_Ijecxz,       O_Jb,    O_NONE,  O_NONE,  P_aso },
  /* 02 */  { UD_Ijrcxz,       O_Jb,    O_NONE,  O_NONE,  P_aso },
};

static struct ud_itab_entry itab__1byte__op_f6__reg[8] = {
  /* 00 */  { UD_Itest,        O_Eb,    O_Ib,    O_NONE,  P_c1|P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Itest,        O_Eb,    O_Ib,    O_NONE,  P_c1|P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 02 */  { UD_Inot,         O_Eb,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 03 */  { UD_Ineg,         O_Eb,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 04 */  { UD_Imul,         O_Eb,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 05 */  { UD_Iimul,        O_Eb,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 06 */  { UD_Idiv,         O_Eb,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 07 */  { UD_Iidiv,        O_Eb,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
};

static struct ud_itab_entry itab__1byte__op_f7__reg[8] = {
  /* 00 */  { UD_Itest,        O_Ev,    O_Iz,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Itest,        O_Ev,    O_Iz,    O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 02 */  { UD_Inot,         O_Ev,    O_NONE,  O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 03 */  { UD_Ineg,         O_Ev,    O_NONE,  O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 04 */  { UD_Imul,         O_Ev,    O_NONE,  O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 05 */  { UD_Iimul,        O_Ev,    O_NONE,  O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 06 */  { UD_Idiv,         O_Ev,    O_NONE,  O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 07 */  { UD_Iidiv,        O_Ev,    O_NONE,  O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
};

static struct ud_itab_entry itab__1byte__op_fe__reg[8] = {
  /* 00 */  { UD_Iinc,         O_Eb,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Idec,         O_Eb,    O_NONE,  O_NONE,  P_c1|P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 02 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 03 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 04 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 05 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 06 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 07 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__1byte__op_ff__reg[8] = {
  /* 00 */  { UD_Iinc,         O_Ev,    O_NONE,  O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 01 */  { UD_Idec,         O_Ev,    O_NONE,  O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 02 */  { UD_Icall,        O_Ev,    O_NONE,  O_NONE,  P_c1|P_def64|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 03 */  { UD_Icall,        O_Ep,    O_NONE,  O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 04 */  { UD_Ijmp,         O_Ev,    O_NONE,  O_NONE,  P_c1|P_def64|P_depM|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 05 */  { UD_Ijmp,         O_Ep,    O_NONE,  O_NONE,  P_c1|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 06 */  { UD_Ipush,        O_Ev,    O_NONE,  O_NONE,  P_c1|P_def64|P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 07 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__3dnow[256] = {
  /* 00 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 01 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 02 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 03 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 04 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 05 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 06 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 07 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 08 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 09 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 0A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 0B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 0C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 0D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 0E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 0F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 10 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 11 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 12 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 13 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 14 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 15 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 16 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 17 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 18 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 19 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 1A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 1B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 1C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 1D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 1E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 1F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 20 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 21 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 22 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 23 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 24 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 25 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 26 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 27 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 28 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 29 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 2A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 2B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 2C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 2D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 2E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 2F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 30 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 31 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 32 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 33 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 34 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 35 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 36 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 37 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 38 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 39 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 40 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 41 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 42 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 43 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 44 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 45 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 46 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 47 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 48 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 49 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 4A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 4B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 4C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 4D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 4E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 4F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 50 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 51 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 52 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 53 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 54 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 55 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 56 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 57 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 58 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 59 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 5A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 5B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 5C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 5D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 5E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 5F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 60 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 61 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 62 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 63 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 64 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 65 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 66 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 67 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 68 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 69 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 6A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 6B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 6C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 6D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 6E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 6F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 70 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 71 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 72 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 73 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 74 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 75 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 76 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 77 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 78 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 79 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 7A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 7B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 7C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 7D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 7E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 7F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 80 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 81 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 82 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 83 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 84 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 85 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 86 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 87 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 88 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 89 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 8A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 8B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 8C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 8D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 8E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 8F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 90 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 91 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 92 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 93 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 94 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 95 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 96 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 97 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 98 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 99 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 9A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 9B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 9C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 9D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 9E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 9F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A0 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A1 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A2 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A3 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A4 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A5 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A6 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A7 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A8 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A9 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* AA */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* AB */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* AC */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* AD */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* AE */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* AF */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B0 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B1 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B2 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B3 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B4 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B5 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B6 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B7 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B8 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B9 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* BA */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* BB */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* BC */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* BD */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* BE */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* BF */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* C0 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* C1 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* C2 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* C3 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* C4 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* C5 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* C6 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* C7 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* C8 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* C9 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* CA */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* CB */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* CC */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* CD */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* CE */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* CF */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* D0 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* D1 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* D2 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* D3 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* D4 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* D5 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* D6 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* D7 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* D8 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* D9 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* DA */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* DB */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* DC */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* DD */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* DE */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* DF */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* E0 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* E1 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* E2 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* E3 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* E4 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* E5 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* E6 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* E7 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* E8 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* E9 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* EA */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* EB */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* EC */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* ED */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* EE */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* EF */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* F0 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* F1 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* F2 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* F3 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* F4 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* F5 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* F6 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* F7 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* F8 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* F9 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* FA */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* FB */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* FC */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* FD */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* FE */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* FF */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__pfx_sse66__0f[256] = {
  /* 00 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 01 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 02 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 03 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 04 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 05 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 06 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 07 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 08 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 09 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 0A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 0B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 0C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 0D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 0E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 0F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 10 */  { UD_Imovupd,      O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 11 */  { UD_Imovupd,      O_W,     O_V,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 12 */  { UD_Imovlpd,      O_V,     O_M,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 13 */  { UD_Imovlpd,      O_M,     O_V,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 14 */  { UD_Iunpcklpd,    O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 15 */  { UD_Iunpckhpd,    O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 16 */  { UD_Imovhpd,      O_V,     O_M,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 17 */  { UD_Imovhpd,      O_M,     O_V,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 18 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 19 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 1A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 1B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 1C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 1D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 1E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 1F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 20 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 21 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 22 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 23 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 24 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 25 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 26 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 27 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 28 */  { UD_Imovapd,      O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 29 */  { UD_Imovapd,      O_W,     O_V,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 2A */  { UD_Icvtpi2pd,    O_V,     O_Q,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 2B */  { UD_Imovntpd,     O_M,     O_V,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 2C */  { UD_Icvttpd2pi,   O_P,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 2D */  { UD_Icvtpd2pi,    O_P,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 2E */  { UD_Iucomisd,     O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 2F */  { UD_Icomisd,      O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 30 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 31 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 32 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 33 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 34 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 35 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 36 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 37 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 38 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 39 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 40 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 41 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 42 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 43 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 44 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 45 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 46 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 47 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 48 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 49 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 4A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 4B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 4C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 4D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 4E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 4F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 50 */  { UD_Imovmskpd,    O_Gd,    O_VR,    O_NONE,  P_oso|P_rexr|P_rexb },
  /* 51 */  { UD_Isqrtpd,      O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 52 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 53 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 54 */  { UD_Iandpd,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 55 */  { UD_Iandnpd,      O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 56 */  { UD_Iorpd,        O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 57 */  { UD_Ixorpd,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 58 */  { UD_Iaddpd,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 59 */  { UD_Imulpd,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 5A */  { UD_Icvtpd2ps,    O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 5B */  { UD_Icvtps2dq,    O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 5C */  { UD_Isubpd,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 5D */  { UD_Iminpd,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 5E */  { UD_Idivpd,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 5F */  { UD_Imaxpd,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 60 */  { UD_Ipunpcklbw,   O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 61 */  { UD_Ipunpcklwd,   O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 62 */  { UD_Ipunpckldq,   O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 63 */  { UD_Ipacksswb,    O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 64 */  { UD_Ipcmpgtb,     O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 65 */  { UD_Ipcmpgtw,     O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 66 */  { UD_Ipcmpgtd,     O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 67 */  { UD_Ipackuswb,    O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 68 */  { UD_Ipunpckhbw,   O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 69 */  { UD_Ipunpckhwd,   O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 6A */  { UD_Ipunpckhdq,   O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 6B */  { UD_Ipackssdw,    O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 6C */  { UD_Ipunpcklqdq,  O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 6D */  { UD_Ipunpckhqdq,  O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 6E */  { UD_Imovd,        O_V,     O_Ex,    O_NONE,  P_c2|P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 6F */  { UD_Imovqa,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 70 */  { UD_Ipshufd,      O_V,     O_W,     O_Ib,    P_aso|P_rexr|P_rexx|P_rexb },
  /* 71 */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__PFX_SSE66__0F__OP_71__REG },
  /* 72 */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__PFX_SSE66__0F__OP_72__REG },
  /* 73 */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__PFX_SSE66__0F__OP_73__REG },
  /* 74 */  { UD_Ipcmpeqb,     O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 75 */  { UD_Ipcmpeqw,     O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 76 */  { UD_Ipcmpeqd,     O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 77 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 78 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 79 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 7A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 7B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 7C */  { UD_Ihaddpd,      O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 7D */  { UD_Ihsubpd,      O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 7E */  { UD_Imovd,        O_Ex,    O_V,     O_NONE,  P_c1|P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 7F */  { UD_Imovdqa,      O_W,     O_V,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 80 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 81 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 82 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 83 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 84 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 85 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 86 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 87 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 88 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 89 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 8A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 8B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 8C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 8D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 8E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 8F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 90 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 91 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 92 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 93 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 94 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 95 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 96 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 97 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 98 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 99 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 9A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 9B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 9C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 9D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 9E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 9F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A0 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A1 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A2 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A3 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A4 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A5 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A6 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A7 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A8 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A9 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* AA */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* AB */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* AC */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* AD */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* AE */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* AF */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B0 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B1 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B2 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B3 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B4 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B5 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B6 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B7 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B8 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B9 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* BA */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* BB */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* BC */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* BD */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* BE */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* BF */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* C0 */  { UD_Ixadd,        O_Eb,    O_Gb,    O_NONE,  P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* C1 */  { UD_Ixadd,        O_Ev,    O_Gv,    O_NONE,  P_aso|P_oso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* C2 */  { UD_Icmppd,       O_V,     O_W,     O_Ib,    P_aso|P_rexr|P_rexx|P_rexb },
  /* C3 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* C4 */  { UD_Ipinsrw,      O_V,     O_Ew,    O_Ib,    P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* C5 */  { UD_Ipextrw,      O_Gd,    O_VR,    O_Ib,    P_aso|P_rexr|P_rexb },
  /* C6 */  { UD_Ishufpd,      O_V,     O_W,     O_Ib,    P_aso|P_rexr|P_rexx|P_rexb },
  /* C7 */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__PFX_SSE66__0F__OP_C7__REG },
  /* C8 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* C9 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* CA */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* CB */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* CC */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* CD */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* CE */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* CF */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* D0 */  { UD_Iaddsubpd,    O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* D1 */  { UD_Ipsrlw,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* D2 */  { UD_Ipsrld,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* D3 */  { UD_Ipsrlq,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* D4 */  { UD_Ipaddq,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* D5 */  { UD_Ipmullw,      O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* D6 */  { UD_Imovq,        O_W,     O_V,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* D7 */  { UD_Ipmovmskb,    O_Gd,    O_VR,    O_NONE,  P_rexr|P_rexb },
  /* D8 */  { UD_Ipsubusb,     O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* D9 */  { UD_Ipsubusw,     O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* DA */  { UD_Ipminub,      O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* DB */  { UD_Ipand,        O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* DC */  { UD_Ipsubusb,     O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* DD */  { UD_Ipunpckhbw,   O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* DE */  { UD_Ipmaxub,      O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* DF */  { UD_Ipandn,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* E0 */  { UD_Ipavgb,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* E1 */  { UD_Ipsraw,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* E2 */  { UD_Ipsrad,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* E3 */  { UD_Ipavgw,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* E4 */  { UD_Ipmulhuw,     O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* E5 */  { UD_Ipmulhw,      O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* E6 */  { UD_Icvttpd2dq,   O_V,     O_W,     O_NONE,  P_none },
  /* E7 */  { UD_Imovntdq,     O_M,     O_V,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* E8 */  { UD_Ipsubsb,      O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* E9 */  { UD_Ipsubsw,      O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* EA */  { UD_Ipminsw,      O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* EB */  { UD_Ipor,         O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* EC */  { UD_Ipaddsb,      O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* ED */  { UD_Ipaddsw,      O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* EE */  { UD_Ipmaxsw,      O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* EF */  { UD_Ipxor,        O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* F0 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* F1 */  { UD_Ipsllw,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* F2 */  { UD_Ipslld,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* F3 */  { UD_Ipsllq,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* F4 */  { UD_Ipmuludq,     O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* F5 */  { UD_Ipmaddwd,     O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* F6 */  { UD_Ipsadbw,      O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* F7 */  { UD_Imaskmovq,    O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* F8 */  { UD_Ipsubb,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* F9 */  { UD_Ipsubw,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* FA */  { UD_Ipsubd,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* FB */  { UD_Ipsubq,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* FC */  { UD_Ipaddb,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* FD */  { UD_Ipaddw,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* FE */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* FF */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__pfx_sse66__0f__op_71__reg[8] = {
  /* 00 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 01 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 02 */  { UD_Ipsrlw,       O_VR,    O_Ib,    O_NONE,  P_rexb },
  /* 03 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 04 */  { UD_Ipsraw,       O_VR,    O_Ib,    O_NONE,  P_rexb },
  /* 05 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 06 */  { UD_Ipsllw,       O_VR,    O_Ib,    O_NONE,  P_rexb },
  /* 07 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__pfx_sse66__0f__op_72__reg[8] = {
  /* 00 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 01 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 02 */  { UD_Ipsrld,       O_VR,    O_Ib,    O_NONE,  P_rexb },
  /* 03 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 04 */  { UD_Ipsrad,       O_VR,    O_Ib,    O_NONE,  P_rexb },
  /* 05 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 06 */  { UD_Ipslld,       O_VR,    O_Ib,    O_NONE,  P_rexb },
  /* 07 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__pfx_sse66__0f__op_73__reg[8] = {
  /* 00 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 01 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 02 */  { UD_Ipsrlq,       O_VR,    O_Ib,    O_NONE,  P_rexb },
  /* 03 */  { UD_Ipsrldq,      O_VR,    O_Ib,    O_NONE,  P_rexb },
  /* 04 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 05 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 06 */  { UD_Ipsllq,       O_VR,    O_Ib,    O_NONE,  P_rexb },
  /* 07 */  { UD_Ipslldq,      O_VR,    O_Ib,    O_NONE,  P_rexb },
};

static struct ud_itab_entry itab__pfx_sse66__0f__op_c7__reg[8] = {
  /* 00 */  { UD_Igrp_vendor,  O_NONE, O_NONE, O_NONE,    ITAB__PFX_SSE66__0F__OP_C7__REG__OP_00__VENDOR },
  /* 01 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 02 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 03 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 04 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 05 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 06 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 07 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__pfx_sse66__0f__op_c7__reg__op_00__vendor[2] = {
  /* 00 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 01 */  { UD_Ivmclear,     O_Mq,    O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
};

static struct ud_itab_entry itab__pfx_ssef2__0f[256] = {
  /* 00 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 01 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 02 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 03 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 04 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 05 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 06 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 07 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 08 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 09 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 0A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 0B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 0C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 0D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 0E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 0F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 10 */  { UD_Imovsd,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 11 */  { UD_Imovsd,       O_W,     O_V,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 12 */  { UD_Imovddup,     O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 13 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 14 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 15 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 16 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 17 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 18 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 19 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 1A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 1B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 1C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 1D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 1E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 1F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 20 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 21 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 22 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 23 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 24 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 25 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 26 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 27 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 28 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 29 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 2A */  { UD_Icvtsi2sd,    O_V,     O_Ex,    O_NONE,  P_c2|P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* 2B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 2C */  { UD_Icvttsd2si,   O_Gvw,   O_W,     O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 2D */  { UD_Icvtsd2si,    O_Gvw,   O_W,     O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 2E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 2F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 30 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 31 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 32 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 33 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 34 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 35 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 36 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 37 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 38 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 39 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 40 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 41 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 42 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 43 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 44 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 45 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 46 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 47 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 48 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 49 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 4A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 4B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 4C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 4D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 4E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 4F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 50 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 51 */  { UD_Isqrtsd,      O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 52 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 53 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 54 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 55 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 56 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 57 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 58 */  { UD_Iaddsd,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 59 */  { UD_Imulsd,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 5A */  { UD_Icvtsd2ss,    O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 5B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 5C */  { UD_Isubsd,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 5D */  { UD_Iminsd,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 5E */  { UD_Idivsd,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 5F */  { UD_Imaxsd,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 60 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 61 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 62 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 63 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 64 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 65 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 66 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 67 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 68 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 69 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 6A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 6B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 6C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 6D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 6E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 6F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 70 */  { UD_Ipshuflw,     O_V,     O_W,     O_Ib,    P_aso|P_rexr|P_rexx|P_rexb },
  /* 71 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 72 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 73 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 74 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 75 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 76 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 77 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 78 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 79 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 7A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 7B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 7C */  { UD_Ihaddps,      O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 7D */  { UD_Ihsubps,      O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 7E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 7F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 80 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 81 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 82 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 83 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 84 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 85 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 86 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 87 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 88 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 89 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 8A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 8B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 8C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 8D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 8E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 8F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 90 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 91 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 92 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 93 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 94 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 95 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 96 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 97 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 98 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 99 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 9A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 9B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 9C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 9D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 9E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 9F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A0 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A1 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A2 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A3 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A4 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A5 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A6 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A7 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A8 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A9 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* AA */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* AB */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* AC */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* AD */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* AE */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* AF */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B0 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B1 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B2 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B3 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B4 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B5 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B6 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B7 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B8 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B9 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* BA */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* BB */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* BC */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* BD */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* BE */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* BF */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* C0 */  { UD_Ixadd,        O_Eb,    O_Gb,    O_NONE,  P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* C1 */  { UD_Ixadd,        O_Ev,    O_Gv,    O_NONE,  P_aso|P_oso|P_rexr|P_rexx|P_rexb },
  /* C2 */  { UD_Icmpsd,       O_V,     O_W,     O_Ib,    P_aso|P_rexr|P_rexx|P_rexb },
  /* C3 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* C4 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* C5 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* C6 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* C7 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* C8 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* C9 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* CA */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* CB */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* CC */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* CD */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* CE */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* CF */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* D0 */  { UD_Iaddsubps,    O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* D1 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* D2 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* D3 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* D4 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* D5 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* D6 */  { UD_Imovdq2q,     O_P,     O_VR,    O_NONE,  P_aso|P_rexb },
  /* D7 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* D8 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* D9 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* DA */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* DB */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* DC */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* DD */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* DE */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* DF */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* E0 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* E1 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* E2 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* E3 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* E4 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* E5 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* E6 */  { UD_Icvtpd2dq,    O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* E7 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* E8 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* E9 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* EA */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* EB */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* EC */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* ED */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* EE */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* EF */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* F0 */  { UD_Ilddqu,       O_V,     O_M,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* F1 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* F2 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* F3 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* F4 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* F5 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* F6 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* F7 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* F8 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* F9 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* FA */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* FB */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* FC */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* FD */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* FE */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* FF */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__pfx_ssef3__0f[256] = {
  /* 00 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 01 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 02 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 03 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 04 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 05 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 06 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 07 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 08 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 09 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 0A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 0B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 0C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 0D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 0E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 0F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 10 */  { UD_Imovss,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 11 */  { UD_Imovss,       O_W,     O_V,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 12 */  { UD_Imovsldup,    O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 13 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 14 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 15 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 16 */  { UD_Imovshdup,    O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 17 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 18 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 19 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 1A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 1B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 1C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 1D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 1E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 1F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 20 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 21 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 22 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 23 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 24 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 25 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 26 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 27 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 28 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 29 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 2A */  { UD_Icvtsi2ss,    O_V,     O_Ex,    O_NONE,  P_c2|P_aso|P_rexr|P_rexx|P_rexb },
  /* 2B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 2C */  { UD_Icvttss2si,   O_Gvw,   O_W,     O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 2D */  { UD_Icvtss2si,    O_Gvw,   O_W,     O_NONE,  P_c1|P_aso|P_rexr|P_rexx|P_rexb },
  /* 2E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 2F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 30 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 31 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 32 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 33 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 34 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 35 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 36 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 37 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 38 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 39 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 3F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 40 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 41 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 42 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 43 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 44 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 45 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 46 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 47 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 48 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 49 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 4A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 4B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 4C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 4D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 4E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 4F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 50 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 51 */  { UD_Isqrtss,      O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 52 */  { UD_Irsqrtss,     O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 53 */  { UD_Ircpss,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 54 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 55 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 56 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 57 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 58 */  { UD_Iaddss,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 59 */  { UD_Imulss,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 5A */  { UD_Icvtss2sd,    O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 5B */  { UD_Icvttps2dq,   O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 5C */  { UD_Isubss,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 5D */  { UD_Iminss,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 5E */  { UD_Idivss,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 5F */  { UD_Imaxss,       O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 60 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 61 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 62 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 63 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 64 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 65 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 66 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 67 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 68 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 69 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 6A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 6B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 6C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 6D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 6E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 6F */  { UD_Imovdqu,      O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 70 */  { UD_Ipshufhw,     O_V,     O_W,     O_Ib,    P_aso|P_rexr|P_rexx|P_rexb },
  /* 71 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 72 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 73 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 74 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 75 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 76 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 77 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 78 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 79 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 7A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 7B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 7C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 7D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 7E */  { UD_Imovq,        O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 7F */  { UD_Imovdqu,      O_W,     O_V,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* 80 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 81 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 82 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 83 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 84 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 85 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 86 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 87 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 88 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 89 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 8A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 8B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 8C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 8D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 8E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 8F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 90 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 91 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 92 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 93 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 94 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 95 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 96 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 97 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 98 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 99 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 9A */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 9B */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 9C */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 9D */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 9E */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 9F */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A0 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A1 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A2 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A3 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A4 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A5 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A6 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A7 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A8 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* A9 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* AA */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* AB */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* AC */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* AD */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* AE */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* AF */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B0 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B1 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B2 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B3 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B4 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B5 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B6 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B7 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B8 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* B9 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* BA */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* BB */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* BC */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* BD */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* BE */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* BF */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* C0 */  { UD_Ixadd,        O_Eb,    O_Gb,    O_NONE,  P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* C1 */  { UD_Ixadd,        O_Ev,    O_Gv,    O_NONE,  P_aso|P_rexw|P_rexr|P_rexx|P_rexb },
  /* C2 */  { UD_Icmpss,       O_V,     O_W,     O_Ib,    P_aso|P_rexr|P_rexx|P_rexb },
  /* C3 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* C4 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* C5 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* C6 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* C7 */  { UD_Igrp_reg,     O_NONE, O_NONE, O_NONE,    ITAB__PFX_SSEF3__0F__OP_C7__REG },
  /* C8 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* C9 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* CA */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* CB */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* CC */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* CD */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* CE */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* CF */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* D0 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* D1 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* D2 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* D3 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* D4 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* D5 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* D6 */  { UD_Imovq2dq,     O_V,     O_PR,    O_NONE,  P_aso },
  /* D7 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* D8 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* D9 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* DA */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* DB */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* DC */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* DD */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* DE */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* DF */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* E0 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* E1 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* E2 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* E3 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* E4 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* E5 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* E6 */  { UD_Icvtdq2pd,    O_V,     O_W,     O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
  /* E7 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* E8 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* E9 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* EA */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* EB */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* EC */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* ED */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* EE */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* EF */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* F0 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* F1 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* F2 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* F3 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* F4 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* F5 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* F6 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* F7 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* F8 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* F9 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* FA */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* FB */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* FC */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* FD */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* FE */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* FF */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
};

static struct ud_itab_entry itab__pfx_ssef3__0f__op_c7__reg[8] = {
  /* 00 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 01 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 02 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 03 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 04 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 05 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 06 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 07 */  { UD_Igrp_vendor,  O_NONE, O_NONE, O_NONE,    ITAB__PFX_SSEF3__0F__OP_C7__REG__OP_07__VENDOR },
};

static struct ud_itab_entry itab__pfx_ssef3__0f__op_c7__reg__op_07__vendor[2] = {
  /* 00 */  { UD_Iinvalid,     O_NONE, O_NONE, O_NONE,    P_none },
  /* 01 */  { UD_Ivmxon,       O_Mq,    O_NONE,  O_NONE,  P_aso|P_rexr|P_rexx|P_rexb },
};

/* the order of this table matches enum ud_itab_index */
struct ud_itab_entry * ud_itab_list[] = {
  itab__0f,
  itab__0f__op_00__reg,
  itab__0f__op_01__reg,
  itab__0f__op_01__reg__op_00__mod,
  itab__0f__op_01__reg__op_00__mod__op_01__rm,
  itab__0f__op_01__reg__op_00__mod__op_01__rm__op_01__vendor,
  itab__0f__op_01__reg__op_00__mod__op_01__rm__op_03__vendor,
  itab__0f__op_01__reg__op_00__mod__op_01__rm__op_04__vendor,
  itab__0f__op_01__reg__op_01__mod,
  itab__0f__op_01__reg__op_01__mod__op_01__rm,
  itab__0f__op_01__reg__op_02__mod,
  itab__0f__op_01__reg__op_03__mod,
  itab__0f__op_01__reg__op_03__mod__op_01__rm,
  itab__0f__op_01__reg__op_03__mod__op_01__rm__op_00__vendor,
  itab__0f__op_01__reg__op_03__mod__op_01__rm__op_01__vendor,
  itab__0f__op_01__reg__op_03__mod__op_01__rm__op_02__vendor,
  itab__0f__op_01__reg__op_03__mod__op_01__rm__op_03__vendor,
  itab__0f__op_01__reg__op_03__mod__op_01__rm__op_04__vendor,
  itab__0f__op_01__reg__op_03__mod__op_01__rm__op_05__vendor,
  itab__0f__op_01__reg__op_03__mod__op_01__rm__op_06__vendor,
  itab__0f__op_01__reg__op_03__mod__op_01__rm__op_07__vendor,
  itab__0f__op_01__reg__op_04__mod,
  itab__0f__op_01__reg__op_06__mod,
  itab__0f__op_01__reg__op_07__mod,
  itab__0f__op_01__reg__op_07__mod__op_01__rm,
  itab__0f__op_01__reg__op_07__mod__op_01__rm__op_01__vendor,
  itab__0f__op_0d__reg,
  itab__0f__op_18__reg,
  itab__0f__op_71__reg,
  itab__0f__op_72__reg,
  itab__0f__op_73__reg,
  itab__0f__op_ae__reg,
  itab__0f__op_ae__reg__op_05__mod,
  itab__0f__op_ae__reg__op_05__mod__op_01__rm,
  itab__0f__op_ae__reg__op_06__mod,
  itab__0f__op_ae__reg__op_06__mod__op_01__rm,
  itab__0f__op_ae__reg__op_07__mod,
  itab__0f__op_ae__reg__op_07__mod__op_01__rm,
  itab__0f__op_ba__reg,
  itab__0f__op_c7__reg,
  itab__0f__op_c7__reg__op_00__vendor,
  itab__0f__op_c7__reg__op_07__vendor,
  itab__0f__op_d9__mod,
  itab__0f__op_d9__mod__op_01__x87,
  itab__1byte,
  itab__1byte__op_60__osize,
  itab__1byte__op_61__osize,
  itab__1byte__op_63__mode,
  itab__1byte__op_6d__osize,
  itab__1byte__op_6f__osize,
  itab__1byte__op_80__reg,
  itab__1byte__op_81__reg,
  itab__1byte__op_82__reg,
  itab__1byte__op_83__reg,
  itab__1byte__op_8f__reg,
  itab__1byte__op_98__osize,
  itab__1byte__op_99__osize,
  itab__1byte__op_9c__mode,
  itab__1byte__op_9c__mode__op_00__osize,
  itab__1byte__op_9c__mode__op_01__osize,
  itab__1byte__op_9d__mode,
  itab__1byte__op_9d__mode__op_00__osize,
  itab__1byte__op_9d__mode__op_01__osize,
  itab__1byte__op_a5__osize,
  itab__1byte__op_a7__osize,
  itab__1byte__op_ab__osize,
  itab__1byte__op_ad__osize,
  itab__1byte__op_ae__mod,
  itab__1byte__op_ae__mod__op_00__reg,
  itab__1byte__op_af__osize,
  itab__1byte__op_c0__reg,
  itab__1byte__op_c1__reg,
  itab__1byte__op_c6__reg,
  itab__1byte__op_c7__reg,
  itab__1byte__op_cf__osize,
  itab__1byte__op_d0__reg,
  itab__1byte__op_d1__reg,
  itab__1byte__op_d2__reg,
  itab__1byte__op_d3__reg,
  itab__1byte__op_d8__mod,
  itab__1byte__op_d8__mod__op_00__reg,
  itab__1byte__op_d8__mod__op_01__x87,
  itab__1byte__op_d9__mod,
  itab__1byte__op_d9__mod__op_00__reg,
  itab__1byte__op_d9__mod__op_01__x87,
  itab__1byte__op_da__mod,
  itab__1byte__op_da__mod__op_00__reg,
  itab__1byte__op_da__mod__op_01__x87,
  itab__1byte__op_db__mod,
  itab__1byte__op_db__mod__op_00__reg,
  itab__1byte__op_db__mod__op_01__x87,
  itab__1byte__op_dc__mod,
  itab__1byte__op_dc__mod__op_00__reg,
  itab__1byte__op_dc__mod__op_01__x87,
  itab__1byte__op_dd__mod,
  itab__1byte__op_dd__mod__op_00__reg,
  itab__1byte__op_dd__mod__op_01__x87,
  itab__1byte__op_de__mod,
  itab__1byte__op_de__mod__op_00__reg,
  itab__1byte__op_de__mod__op_01__x87,
  itab__1byte__op_df__mod,
  itab__1byte__op_df__mod__op_00__reg,
  itab__1byte__op_df__mod__op_01__x87,
  itab__1byte__op_e3__asize,
  itab__1byte__op_f6__reg,
  itab__1byte__op_f7__reg,
  itab__1byte__op_fe__reg,
  itab__1byte__op_ff__reg,
  itab__3dnow,
  itab__pfx_sse66__0f,
  itab__pfx_sse66__0f__op_71__reg,
  itab__pfx_sse66__0f__op_72__reg,
  itab__pfx_sse66__0f__op_73__reg,
  itab__pfx_sse66__0f__op_c7__reg,
  itab__pfx_sse66__0f__op_c7__reg__op_00__vendor,
  itab__pfx_ssef2__0f,
  itab__pfx_ssef3__0f,
  itab__pfx_ssef3__0f__op_c7__reg,
  itab__pfx_ssef3__0f__op_c7__reg__op_07__vendor,
};
/* -----------------------------------------------------------------------------
 * syn-intel.c
 *
 * Copyright (c) 2002, 2003, 2004 Vivek Mohan <vivek@sig9.com>
 * All rights reserved. See (LICENSE)
 * -----------------------------------------------------------------------------
 */

#if USE_PTS
#else
#include "types.h"
#include "extern.h"
#include "itab.h"
#include "decode.h"
#include "syn.h"
#endif

/* -----------------------------------------------------------------------------
 * opr_cast() - Prints an operand cast.
 * -----------------------------------------------------------------------------
 */
static void 
opr_cast(struct ud* u, struct ud_operand* op)
{
  switch(op->size) {
	case  8: mkasm_str1(u, "byte " ); break;
	case 16: mkasm_str1(u, "word " ); break;
	case 32: mkasm_str1(u, "dword "); break;
	case 64: mkasm_str1(u, "qword "); break;
	case 80: mkasm_str1(u, "tword "); break;
	default: break;
  }
  if (u->br_far)
	mkasm_str1(u, "far "); 
  else if (u->br_near)
	mkasm_str1(u, "near ");
}

/* -----------------------------------------------------------------------------
 * gen_operand() - Generates assembly output for each operand.
 * -----------------------------------------------------------------------------
 */
static void gen_operand(struct ud* u, struct ud_operand* op, int syn_cast)
{
  switch(op->type) {
	case UD_OP_REG:
		mkasm_str1(u, ud_reg_tab[op->base - UD_R_AL]);
		break;

	case UD_OP_MEM: {

		int op_f = 0;

		if (syn_cast) 
			opr_cast(u, op);

		mkasm_str1(u, "[");

		if (u->pfx_seg) {
			mkasm_str1(u, ud_reg_tab[u->pfx_seg - UD_R_AL]);
			mkasm_str1(u, ":");
		}

		if (op->base) {
			mkasm_str1(u, ud_reg_tab[op->base - UD_R_AL]);
			op_f = 1;
		}

		if (op->index) {
			if (op_f)
				mkasm_str1(u, "+");
			mkasm_str1(u, ud_reg_tab[op->index - UD_R_AL]);
			op_f = 1;
		}

		if (op->scale) {
			mkasm_str1(u, "*");
			mkasm_dec32(u, op->scale);
		}

		if (op->offset == 8) {
			if (op->lval.sbyte < 0) {
				mkasm_str1(u, "-0x");
				mkasm_hex1(u, -op->lval.sbyte);
			} else {
				mkasm_str1(u, op_f ? "+0x" : "0x");
				mkasm_hex1(u, op->lval.sbyte);
			}
		}
		else if (op->offset == 16) {
			mkasm_str1(u, op_f ? "+0x" : "0x");
			mkasm_hex1(u, op->lval.uword);
		} else if (op->offset == 32) {
			if (u->adr_mode == 64) {
				if (op->lval.sdword < 0) {
					mkasm_str1(u, "-0x");
					mkasm_hex1(u, -op->lval.sdword);
				} else {
					mkasm_str1(u, op_f ? "+0x" : "0x");
					mkasm_hex1(u, op->lval.sdword);
				}
			} else {
				mkasm_str1(u, op_f ? "+0x" : "0x");
				mkasm_hex1(u, op->lval.udword);
			}
		} else if (op->offset == 64) {
			mkasm_str1(u, op_f ? "+0x" : "0x");
			mkasm_hex1(u, op->lval.uqword);
		}
		mkasm_str1(u, "]");
		break;
	}
			
	case UD_OP_IMM:
		if (syn_cast) opr_cast(u, op);
		mkasm_str1(u, "0x");
		switch (op->size) {
			case  8: mkasm_hex1(u, op->lval.ubyte);    break;
			case 16: mkasm_hex1(u, op->lval.uword);    break;
			case 32: mkasm_hex1(u, op->lval.udword);  break;
			case 64: mkasm_hex1(u, op->lval.uqword); break;
			default: break;
		}
		break;

	case UD_OP_JIMM:
		if (syn_cast) opr_cast(u, op);
		mkasm_str1(u, "0x");
		switch (op->size) {
			case  8:
				mkasm_hex1(u, u->pc + op->lval.sbyte); 
				break;
			case 16:
				mkasm_hex1(u, u->pc + op->lval.sword);
				break;
			case 32:
				mkasm_hex1(u, u->pc + op->lval.sdword);
				break;
			default:break;
		}
		break;

	case UD_OP_PTR:
		switch (op->size) {
			case 32:
				mkasm_str1(u, "word 0x");
				mkasm_hex1(u, op->lval.ptr.seg);
				mkasm_str1(u, ":0x");
				mkasm_hex1(u, op->lval.ptr.off & 0xFFFF);
				break;
			case 48:
				mkasm_str1(u, "dword 0x");
				mkasm_hex1(u, op->lval.ptr.seg);
				mkasm_str1(u, ":0x");
				mkasm_hex1(u, op->lval.ptr.off);
				break;
		}
		break;

	case UD_OP_CONST:
		if (syn_cast) opr_cast(u, op);
		mkasm_dec32(u, op->lval.udword);
		break;

	default: return;
  }
}

/* =============================================================================
 * translates to intel syntax 
 * =============================================================================
 */
extern void ud_translate_intel(struct ud* u)
{
  /* -- prefixes -- */

  /* check if P_OSO prefix is used */
  if (! P_OSO(u->itab_entry->prefix) && u->pfx_opr) {
	switch (u->dis_mode) {
		case 16: 
			mkasm_str1(u, "o32 ");
			break;
		case 32:
		case 64:
 			mkasm_str1(u, "o16 ");
			break;
	}
  }

  /* check if P_ASO prefix was used */
  if (! P_ASO(u->itab_entry->prefix) && u->pfx_adr) {
	switch (u->dis_mode) {
		case 16: 
			mkasm_str1(u, "a32 ");
			break;
		case 32:
 			mkasm_str1(u, "a16 ");
			break;
		case 64:
 			mkasm_str1(u, "a32 ");
			break;
	}
  }

  if (u->pfx_lock)
	mkasm_str1(u, "lock ");
  if (u->pfx_rep)
	mkasm_str1(u, "rep ");
  if (u->pfx_repne)
	mkasm_str1(u, "repne ");
  if (u->implicit_addr && u->pfx_seg) {
	mkasm_str1(u, ud_reg_tab[u->pfx_seg - UD_R_AL]);
	mkasm_str1(u, " ");
  }

  /* print the instruction mnemonic */
  mkasm_str1(u, ud_lookup_mnemonic(u->mnemonic));
  mkasm_str1(u, " ");

  /* operand 1 */
  if (u->operand[0].type != UD_NONE) {
	gen_operand(u, &u->operand[0], u->c1);
  }
  /* operand 2 */
  if (u->operand[1].type != UD_NONE) {
	mkasm_str1(u, ", ");
	gen_operand(u, &u->operand[1], u->c2);
  }

  /* operand 3 */
  if (u->operand[2].type != UD_NONE) {
	mkasm_str1(u, ", ");
	gen_operand(u, &u->operand[2], u->c3);
  }
}
/* -----------------------------------------------------------------------------
 * syn.c
 *
 * Copyright (c) 2002, 2003, 2004 Vivek Mohan <vivek@sig9.com>
 * All rights reserved. See (LICENSE)
 * -----------------------------------------------------------------------------
 */

/* -----------------------------------------------------------------------------
 * Intel Register Table - Order Matters (types.h)!
 * -----------------------------------------------------------------------------
 */
const char* ud_reg_tab[] = 
{
  "al",		"cl",		"dl",		"bl",
  "ah",		"ch",		"dh",		"bh",
  "spl",	"bpl",		"sil",		"dil",
  "r8b",	"r9b",		"r10b",		"r11b",
  "r12b",	"r13b",		"r14b",		"r15b",

  "ax",		"cx",		"dx",		"bx",
  "sp",		"bp",		"si",		"di",
  "r8w",	"r9w",		"r10w",		"r11w",
  "r12w",	"r13W"	,	"r14w",		"r15w",
	
  "eax",	"ecx",		"edx",		"ebx",
  "esp",	"ebp",		"esi",		"edi",
  "r8d",	"r9d",		"r10d",		"r11d",
  "r12d",	"r13d",		"r14d",		"r15d",
	
  "rax",	"rcx",		"rdx",		"rbx",
  "rsp",	"rbp",		"rsi",		"rdi",
  "r8",		"r9",		"r10",		"r11",
  "r12",	"r13",		"r14",		"r15",

  "es",		"cs",		"ss",		"ds",
  "fs",		"gs",	

  "cr0",	"cr1",		"cr2",		"cr3",
  "cr4",	"cr5",		"cr6",		"cr7",
  "cr8",	"cr9",		"cr10",		"cr11",
  "cr12",	"cr13",		"cr14",		"cr15",
	
  "dr0",	"dr1",		"dr2",		"dr3",
  "dr4",	"dr5",		"dr6",		"dr7",
  "dr8",	"dr9",		"dr10",		"dr11",
  "dr12",	"dr13",		"dr14",		"dr15",

  "mm0",	"mm1",		"mm2",		"mm3",
  "mm4",	"mm5",		"mm6",		"mm7",

  "st0",	"st1",		"st2",		"st3",
  "st4",	"st5",		"st6",		"st7", 

  "xmm0",	"xmm1",		"xmm2",		"xmm3",
  "xmm4",	"xmm5",		"xmm6",		"xmm7",
  "xmm8",	"xmm9",		"xmm10",	"xmm11",
  "xmm12",	"xmm13",	"xmm14",	"xmm15",

  "rip"
};
/* -----------------------------------------------------------------------------
 * udis86.c
 *
 * Copyright (c) 2004, 2005, 2006, Vivek Mohan <vivek@sig9.com>
 * All rights reserved. See LICENSE
 * -----------------------------------------------------------------------------
 */


#if USE_PTS
#else
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "extern.h"
#include "input.h"
#endif

/* =============================================================================
 * ud_init() - Initializes ud_t object.
 * =============================================================================
 */
extern void 
ud_init(struct ud* u)
{
  char *msp; unsigned mslen;
  for (msp = (char*)u, mslen = sizeof *u; mslen > 0; --mslen) {
    *msp++ = 0;
  }
  ud_set_mode(u, 16);
  u->mnemonic = UD_Iinvalid;
  ud_set_pc(u, 0);
#ifndef __UD_STANDALONE__
  ud_set_input_file(u, stdin);
#endif /* __UD_STANDALONE__ */
}

/* =============================================================================
 * ud_disassemble() - disassembles one instruction and returns the number of 
 * bytes disassembled. A zero means end of disassembly.
 * =============================================================================
 */
extern unsigned int
ud_disassemble(struct ud* u)
{
  if (ud_input_end(u))
	return 0;

 
  u->insn_buffer[0] = u->insn_hexcode[0] = 0;

 
  if (ud_decode(u) == 0)
	return 0;
  if (u->translator)
	u->translator(u);
  return ud_insn_len(u);
}

/* =============================================================================
 * ud_set_mode() - Set Disassemly Mode.
 * =============================================================================
 */
extern void 
ud_set_mode(struct ud* u, uint8_t m)
{
  switch(m) {
	case 16:
	case 32:
	case 64: u->dis_mode = m ; return;
	default: u->dis_mode = 16; return;
  }
}

/* =============================================================================
 * ud_set_vendor() - Set vendor.
 * =============================================================================
 */
extern void 
ud_set_vendor(struct ud* u, unsigned v)
{
  switch(v) {
	case UD_VENDOR_INTEL:
		u->vendor = v;
		break;
	default:
		u->vendor = UD_VENDOR_AMD;
  }
}

/* =============================================================================
 * ud_set_pc() - Sets code origin. 
 * =============================================================================
 */
extern void 
ud_set_pc(struct ud* u, uint64_t o)
{
  u->pc = o;
}

/* =============================================================================
 * ud_set_syntax() - Sets the output syntax.
 * =============================================================================
 */
extern void 
ud_set_syntax(struct ud* u, void (*t)(struct ud*))
{
  u->translator = t;
}

/* =============================================================================
 * ud_insn() - returns the disassembled instruction
 * =============================================================================
 */
extern char* 
ud_insn_asm(struct ud* u) 
{
  return u->insn_buffer;
}

/* =============================================================================
 * ud_insn_offset() - Returns the offset.
 * =============================================================================
 */
extern uint64_t
ud_insn_off(struct ud* u) 
{
  return u->insn_offset;
}


#if USE_PTS
#else
/* =============================================================================
 * ud_insn_hex() - Returns hex form of disassembled instruction.
 * =============================================================================
 */
extern char* 
ud_insn_hex(struct ud* u) 
{
  return u->insn_hexcode;
}
#endif

/* =============================================================================
 * ud_insn_ptr() - Returns code disassembled.
 * =============================================================================
 */
extern uint8_t* 
ud_insn_ptr(struct ud* u) 
{
  return u->inp_sess;
}

/* =============================================================================
 * ud_insn_len() - Returns the count of bytes disassembled.
 * =============================================================================
 */
extern unsigned int 
ud_insn_len(struct ud* u) 
{
  return u->inp_ctr;
}
