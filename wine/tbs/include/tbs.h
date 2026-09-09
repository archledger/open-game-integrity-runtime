/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * TPM Base Services definitions (extended for the per-prefix vTPM).
 *
 * Extends upstream Wine's include/tbs.h with the documented TBS
 * surface needed by the compat layer (M10-049): the return codes,
 * TBS_CONTEXT_PARAMS2, the locality and priority enums, and
 * TPM_DEVICE_INFO. Values are from Microsoft Learn's tbs.h API
 * reference (function pages and structure pages, 2026-09-08).
 *
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef _TBS_H_
#define _TBS_H_

/*
 * OGIR standalone-build shim (the dev-host gate): when compiled
 * without Wine's headers, provide the minimal base types this
 * header needs. An upstream submission drops this block; there
 * the includer has already pulled in windef.h.
 */
#ifdef OGIR_TBS_STANDALONE
#include <stdint.h>
typedef uint32_t UINT32;
typedef uint32_t *PUINT32;
typedef unsigned char BYTE;
typedef BYTE *PBYTE;
typedef const BYTE *PCBYTE;
typedef int BOOL;
typedef unsigned short WCHAR;
#ifndef WINAPI
#define WINAPI
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef UINT32 TBS_RESULT;

typedef void *TBS_HCONTEXT, **PTBS_HCONTEXT;

#define TBS_SUCCESS 0

/* Documented TBS return codes (Microsoft Learn, tbs.h). */
#define TBS_E_INTERNAL_ERROR          0x80284001
#define TBS_E_BAD_PARAMETER           0x80284002
#define TBS_E_INVALID_OUTPUT_POINTER  0x80284003
#define TBS_E_INVALID_CONTEXT         0x80284004
#define TBS_E_INSUFFICIENT_BUFFER     0x80284005
#define TBS_E_IOERROR                 0x80284006
#define TBS_E_INVALID_CONTEXT_PARAM   0x80284007
#define TBS_E_SERVICE_NOT_RUNNING     0x80284008
#define TBS_E_TOO_MANY_TBS_CONTEXTS   0x80284009
#define TBS_E_SERVICE_START_PENDING   0x8028400B
#define TBS_E_SERVICE_DISABLED        0x80284010
#define TBS_E_BUFFER_TOO_LARGE        0x8028400E
#define TBS_E_TPM_NOT_FOUND           0x8028400F

#define TPM_VERSION_12 1
#define TPM_VERSION_20 2

typedef struct tdTBS_CONTEXT_PARAMS
{
    UINT32 version;
} TBS_CONTEXT_PARAMS, *PTBS_CONTEXT_PARAMS;

/* Version-2 context parameters: bitfields per TBS_CONTEXT_PARAMS2. */
typedef struct tdTBS_CONTEXT_PARAMS2
{
    UINT32 version;
    union
    {
        struct
        {
            UINT32 requestRaw : 1;
            UINT32 includeTpm12 : 1;
            UINT32 includeTpm20 : 1;
        };
        UINT32 asUINT32;
    };
} TBS_CONTEXT_PARAMS2, *PTBS_CONTEXT_PARAMS2;

typedef enum tdTBS_COMMAND_LOCALITY
{
    TBS_COMMAND_LOCALITY_ZERO = 0,
    TBS_COMMAND_LOCALITY_ONE = 1,
    TBS_COMMAND_LOCALITY_TWO = 2,
    TBS_COMMAND_LOCALITY_THREE = 3,
    TBS_COMMAND_LOCALITY_FOUR = 4
} TBS_COMMAND_LOCALITY;

typedef enum tdTBS_COMMAND_PRIORITY
{
    TBS_COMMAND_PRIORITY_LOW = 100,
    TBS_COMMAND_PRIORITY_NORMAL = 200,
    TBS_COMMAND_PRIORITY_HIGH = 300,
    TBS_COMMAND_PRIORITY_SYSTEM = 400,
    TBS_COMMAND_PRIORITY_MAX = 0x80000000
} TBS_COMMAND_PRIORITY;

/* TPM_DEVICE_INFO: four UINT32s; the last two fields are reserved. */
typedef struct _TPM_DEVICE_INFO
{
    UINT32 structVersion;
    UINT32 tpmVersion;
    UINT32 tpmInterfaceType;
    UINT32 tpmImpRevision;
} TPM_DEVICE_INFO, *PTPM_DEVICE_INFO;

TBS_RESULT WINAPI Tbsi_Context_Create(const TBS_CONTEXT_PARAMS *params, TBS_HCONTEXT *out);
TBS_RESULT WINAPI Tbsip_Submit_Command(TBS_HCONTEXT context, TBS_COMMAND_LOCALITY locality,
                                       TBS_COMMAND_PRIORITY priority, PCBYTE command, UINT32 command_size,
                                       PBYTE result, UINT32 *result_size);
TBS_RESULT WINAPI Tbsip_Cancel_Commands(TBS_HCONTEXT context);
TBS_RESULT WINAPI Tbsip_Context_Close(TBS_HCONTEXT context);
TBS_RESULT WINAPI Tbsi_GetDeviceInfo(UINT32 size, void *info);

#ifdef __cplusplus
}
#endif

#endif
