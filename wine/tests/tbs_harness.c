/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Scenario harness for the TBS compat layer (M10-049; attack
 * scenarios added in M10-050). Compiled with wine/tbs/tbs.c in
 * standalone mode by the dev-host gates (wine/tests/test-tbs.py,
 * wine/tests/test-tbs-attacks.py); each scenario exercises one
 * behavior and prints machine-readable lines the gate asserts
 * on. The harness never fabricates outcomes: TBS codes and TPM
 * response bytes are printed exactly as the layer returned them.
 *
 * Usage: tbs_harness <scenario> [arg]
 */

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tbs.h"

/* The layer's transport cap (wine/tbs/tbs.c TBS_MAX_BUFFER). */
#define HARNESS_BUFFER 4096

static void store_be16(unsigned char *p, unsigned int v)
{
    p[0] = (unsigned char)(v >> 8);
    p[1] = (unsigned char)v;
}

static void store_be32(unsigned char *p, unsigned int v)
{
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)v;
}

/* TPM2_GetRandom: tag(2)=0x8001 size(4)=12 cc(4)=0x017B then a
 * UINT16 octet count. */
static void make_getrandom(unsigned char *cmd, unsigned int count, unsigned int declared_size)
{
    store_be16(cmd, 0x8001);
    store_be32(cmd + 2, declared_size);
    store_be32(cmd + 6, 0x017b);
    store_be16(cmd + 10, count);
}

static TBS_HCONTEXT create_v2(unsigned int flags)
{
    TBS_CONTEXT_PARAMS2 params;
    TBS_HCONTEXT context = NULL;
    memset(&params, 0, sizeof(params));
    params.version = TPM_VERSION_20;
    params.asUINT32 = flags;
    if (Tbsi_Context_Create((TBS_CONTEXT_PARAMS *)&params, &context) != TBS_SUCCESS)
        return NULL;
    return context;
}

static void print_code(const char *label, TBS_RESULT code)
{
    printf("%s 0x%08x\n", label, code);
}

static void print_response(const char *label, const unsigned char *buf, UINT32 size)
{
    printf("%s", label);
    for (UINT32 i = 0; i < size; i++)
        printf("%02x", buf[i]);
    printf("\n");
}

/* Open-descriptor count via /proc/self/fd (dev-host Linux): the
 * fd-stability attack asserts submits do not leak descriptors. */
static long count_open_fds(void)
{
    DIR *dir = opendir("/proc/self/fd");
    struct dirent *entry;
    long count = 0;

    if (!dir)
        return -1;
    while ((entry = readdir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, ".."))
            count++;
    }
    closedir(dir);
    return count;
}

static int run_submit(TBS_HCONTEXT context, unsigned int count, unsigned int declared_size,
                      TBS_COMMAND_LOCALITY locality, TBS_COMMAND_PRIORITY priority,
                      unsigned char *result, UINT32 result_capacity, UINT32 *result_size)
{
    unsigned char command[16];
    make_getrandom(command, count, declared_size);
    *result_size = result_capacity;
    return Tbsip_Submit_Command(context, locality, priority, command, declared_size, result, result_size);
}

int main(int argc, char **argv)
{
    const char *scenario = argc > 1 ? argv[1] : "";
    TBS_HCONTEXT context;
    unsigned char result[HARNESS_BUFFER];
    UINT32 result_size;
    TBS_RESULT code;

    if (!strcmp(scenario, "create-null-out"))
    {
        TBS_CONTEXT_PARAMS params;
        memset(&params, 0, sizeof(params));
        params.version = TPM_VERSION_20;
        print_code("CODE", Tbsi_Context_Create(&params, NULL));
        return 0;
    }
    if (!strcmp(scenario, "create-null-params"))
    {
        TBS_HCONTEXT out = NULL;
        print_code("CODE", Tbsi_Context_Create(NULL, &out));
        return 0;
    }
    if (!strcmp(scenario, "create-v1"))
    {
        TBS_CONTEXT_PARAMS params;
        TBS_HCONTEXT out = NULL;
        memset(&params, 0, sizeof(params));
        params.version = TPM_VERSION_12;
        print_code("CODE", Tbsi_Context_Create(&params, &out));
        return 0;
    }
    if (!strcmp(scenario, "create-v3"))
    {
        TBS_CONTEXT_PARAMS2 params;
        TBS_HCONTEXT out = NULL;
        memset(&params, 0, sizeof(params));
        params.version = 3;
        params.asUINT32 = 4; /* includeTpm20 */
        print_code("CODE", Tbsi_Context_Create((TBS_CONTEXT_PARAMS *)&params, &out));
        return 0;
    }
    if (!strcmp(scenario, "create-v2-no20"))
    {
        TBS_CONTEXT_PARAMS2 params;
        TBS_HCONTEXT out = NULL;
        memset(&params, 0, sizeof(params));
        params.version = TPM_VERSION_20;
        params.asUINT32 = 2; /* includeTpm12 only */
        print_code("CODE", Tbsi_Context_Create((TBS_CONTEXT_PARAMS *)&params, &out));
        return 0;
    }
    if (!strcmp(scenario, "deviceinfo"))
    {
        TPM_DEVICE_INFO info;
        memset(&info, 0xaa, sizeof(info));
        code = Tbsi_GetDeviceInfo(sizeof(info), &info);
        printf("CODE 0x%08x STRUCTVERSION %u TPMVERSION %u IFACE %u IMPL %u\n", code,
               info.structVersion, info.tpmVersion, info.tpmInterfaceType, info.tpmImpRevision);
        return 0;
    }
    if (!strcmp(scenario, "deviceinfo-small"))
    {
        TPM_DEVICE_INFO info;
        print_code("CODE", Tbsi_GetDeviceInfo(8, &info));
        return 0;
    }
    if (!strcmp(scenario, "deviceinfo-null"))
    {
        print_code("CODE", Tbsi_GetDeviceInfo(sizeof(TPM_DEVICE_INFO), NULL));
        return 0;
    }
    if (!strcmp(scenario, "cancel-invalid"))
    {
        print_code("CODE", Tbsip_Cancel_Commands((TBS_HCONTEXT)0xdeadbeef));
        return 0;
    }
    if (!strcmp(scenario, "close-invalid"))
    {
        print_code("CODE", Tbsip_Context_Close((TBS_HCONTEXT)0xdeadbeef));
        return 0;
    }
    if (!strcmp(scenario, "submit-invalid-context"))
    {
        unsigned char command[16];
        UINT32 size = sizeof(result);
        make_getrandom(command, 4, 12);
        print_code("CODE", Tbsip_Submit_Command((TBS_HCONTEXT)0xdeadbeef, TBS_COMMAND_LOCALITY_ZERO,
                                                 TBS_COMMAND_PRIORITY_NORMAL, command, 12, result, &size));
        return 0;
    }

    /* Everything below needs a real context. */
    context = create_v2(4);
    if (!context)
    {
        print_code("CREATE", (TBS_RESULT)-1);
        return 0;
    }

    if (!strcmp(scenario, "create-basic"))
    {
        /* create_v2 succeeded; report close too. */
        print_code("CODE", Tbsip_Context_Close(context));
        return 0;
    }
    if (!strcmp(scenario, "submit-random"))
    {
        unsigned int count = argc > 2 ? (unsigned int)atoi(argv[2]) : 16;
        code = run_submit(context, count, 12, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL,
                          result, sizeof(result), &result_size);
        printf("CODE 0x%08x SIZE %u\n", code, result_size);
        print_response("RESPONSE ", result, result_size);
        Tbsip_Context_Close(context);
        return 0;
    }
    if (!strcmp(scenario, "submit-small-result"))
    {
        code = run_submit(context, 16, 12, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL,
                          result, 8, &result_size);
        printf("CODE 0x%08x SIZE %u\n", code, result_size);
        Tbsip_Context_Close(context);
        return 0;
    }
    if (!strcmp(scenario, "submit-inplace"))
    {
        unsigned char buf[64];
        make_getrandom(buf, 16, 12);
        result_size = sizeof(buf);
        code = Tbsip_Submit_Command(context, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL,
                                    buf, 12, buf, &result_size);
        printf("CODE 0x%08x SIZE %u\n", code, result_size);
        print_response("RESPONSE ", buf, result_size);
        Tbsip_Context_Close(context);
        return 0;
    }
    if (!strcmp(scenario, "submit-short"))
    {
        unsigned char command[5] = {0};
        result_size = sizeof(result);
        print_code("CODE", Tbsip_Submit_Command(context, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL,
                                                command, 5, result, &result_size));
        Tbsip_Context_Close(context);
        return 0;
    }
    if (!strcmp(scenario, "submit-null-command"))
    {
        result_size = sizeof(result);
        print_code("CODE", Tbsip_Submit_Command(context, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL,
                                                NULL, 12, result, &result_size));
        Tbsip_Context_Close(context);
        return 0;
    }
    if (!strcmp(scenario, "submit-null-resultsize"))
    {
        unsigned char command[16];
        make_getrandom(command, 4, 12);
        print_code("CODE", Tbsip_Submit_Command(context, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL,
                                                command, 12, result, NULL));
        Tbsip_Context_Close(context);
        return 0;
    }
    if (!strcmp(scenario, "submit-oversize"))
    {
        unsigned char command[HARNESS_BUFFER + 1] = {0};
        make_getrandom(command, 4, 12);
        result_size = sizeof(result);
        /* cbCommand above the transport cap: refused before IO. */
        print_code("CODE", Tbsip_Submit_Command(context, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL,
                                                command, HARNESS_BUFFER + 1, result, &result_size));
        Tbsip_Context_Close(context);
        return 0;
    }
    if (!strcmp(scenario, "submit-tpm-error"))
    {
        /* GetRandom with the parameter truncated away: the TPM's
         * own error must arrive verbatim (transport success). */
        code = run_submit(context, 16, 10, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL,
                          result, sizeof(result), &result_size);
        printf("CODE 0x%08x SIZE %u\n", code, result_size);
        print_response("RESPONSE ", result, result_size);
        Tbsip_Context_Close(context);
        return 0;
    }
    if (!strcmp(scenario, "submit-bad-locality"))
    {
        code = run_submit(context, 4, 12, TBS_COMMAND_LOCALITY_TWO, TBS_COMMAND_PRIORITY_NORMAL,
                          result, sizeof(result), &result_size);
        printf("CODE 0x%08x\n", code);
        Tbsip_Context_Close(context);
        return 0;
    }
    if (!strcmp(scenario, "submit-bad-priority"))
    {
        code = run_submit(context, 4, 12, TBS_COMMAND_LOCALITY_ZERO, (TBS_COMMAND_PRIORITY)999,
                          result, sizeof(result), &result_size);
        printf("CODE 0x%08x\n", code);
        Tbsip_Context_Close(context);
        return 0;
    }
    if (!strcmp(scenario, "cancel-basic"))
    {
        print_code("CODE", Tbsip_Cancel_Commands(context));
        print_code("CLOSE", Tbsip_Context_Close(context));
        return 0;
    }
    if (!strcmp(scenario, "close-twice"))
    {
        print_code("CODE", Tbsip_Context_Close(context));
        print_code("SECOND", Tbsip_Context_Close(context));
        return 0;
    }
    if (!strcmp(scenario, "submit-after-close"))
    {
        unsigned char command[16];
        Tbsip_Context_Close(context);
        make_getrandom(command, 4, 12);
        result_size = sizeof(result);
        print_code("CODE", Tbsip_Submit_Command(context, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL,
                                                command, 12, result, &result_size));
        return 0;
    }
    if (!strcmp(scenario, "cycle"))
    {
        for (int i = 0; i < 5; i++)
        {
            TBS_HCONTEXT c = create_v2(4);
            printf("CREATE%d %s\n", i + 1, c ? "ok" : "fail");
            if (c)
                printf("CLOSE%d 0x%08x\n", i + 1, Tbsip_Context_Close(c));
        }
        code = run_submit(context, 4, 12, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL,
                          result, sizeof(result), &result_size);
        printf("CODE 0x%08x SIZE %u\n", code, result_size);
        Tbsip_Context_Close(context);
        return 0;
    }
    if (!strcmp(scenario, "two-contexts"))
    {
        TBS_HCONTEXT other = create_v2(4);
        printf("OTHER %s\n", other ? "ok" : "fail");
        code = run_submit(other, 4, 12, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL,
                          result, sizeof(result), &result_size);
        printf("OTHERSUBMIT 0x%08x SIZE %u\n", code, result_size);
        code = run_submit(context, 4, 12, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL,
                          result, sizeof(result), &result_size);
        printf("FIRSTSUBMIT 0x%08x SIZE %u\n", code, result_size);
        printf("CLOSE1 0x%08x\n", Tbsip_Context_Close(context));
        printf("CLOSE2 0x%08x\n", Tbsip_Context_Close(other));
        return 0;
    }

    /* ===== M10-050 attack scenarios ===== */

    if (!strcmp(scenario, "exhaust-contexts"))
    {
        TBS_HCONTEXT held[256];
        unsigned int created = 0;
        TBS_RESULT last = TBS_SUCCESS;
        while (created < 256)
        {
            TBS_HCONTEXT c = create_v2(4);
            if (!c)
            {
                /* Report the failure code by recreating with the
                 * raw call so the exact code is observable. */
                TBS_CONTEXT_PARAMS2 params;
                memset(&params, 0, sizeof(params));
                params.version = TPM_VERSION_20;
                params.asUINT32 = 4;
                TBS_HCONTEXT probe = NULL;
                last = Tbsi_Context_Create((TBS_CONTEXT_PARAMS *)&params, &probe);
                break;
            }
            held[created++] = c;
        }
        printf("CREATED %u\n", created);
        printf("EXHAUSTED 0x%08x\n", last);
        for (unsigned int i = 0; i < created; i++)
            Tbsip_Context_Close(held[i]);
        printf("RECOVERY %s\n", create_v2(4) ? "ok" : "fail");
        return 0;
    }
    if (!strcmp(scenario, "fd-stability"))
    {
        int iterations = argc > 2 ? atoi(argv[2]) : 50;
        unsigned int ok = 0;
        long before = count_open_fds();
        for (int i = 0; i < iterations; i++)
        {
            code = run_submit(context, 4, 12, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL,
                              result, sizeof(result), &result_size);
            if (code == TBS_SUCCESS)
                ok++;
        }
        long after = count_open_fds();
        printf("FDSTART %ld\n", before);
        printf("FDEND %ld\n", after);
        printf("SUBMITS %u/%d\n", ok, iterations);
        Tbsip_Context_Close(context);
        return 0;
    }
    if (!strcmp(scenario, "submit-bad-tag"))
    {
        unsigned char command[16];
        make_getrandom(command, 16, 12);
        store_be16(command, 0x1234); /* a tag no TPM accepts */
        result_size = sizeof(result);
        code = Tbsip_Submit_Command(context, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL,
                                    command, 12, result, &result_size);
        printf("CODE 0x%08x SIZE %u\n", code, result_size);
        print_response("RESPONSE ", result, result_size);
        Tbsip_Context_Close(context);
        return 0;
    }
    if (!strcmp(scenario, "submit-size-mismatch"))
    {
        unsigned char command[16];
        make_getrandom(command, 16, 12);
        /* The header declares 12 octets but 14 are submitted:
         * the TPM's own inconsistency error must arrive verbatim. */
        result_size = sizeof(result);
        code = Tbsip_Submit_Command(context, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL,
                                    command, 14, result, &result_size);
        printf("CODE 0x%08x SIZE %u\n", code, result_size);
        print_response("RESPONSE ", result, result_size);
        Tbsip_Context_Close(context);
        return 0;
    }
    if (!strcmp(scenario, "cancel-storm"))
    {
        unsigned int ok = 0;
        for (int i = 0; i < 25; i++)
            if (Tbsip_Cancel_Commands(context) == TBS_SUCCESS)
                ok++;
        printf("CANCELS %u/25\n", ok);
        code = run_submit(context, 4, 12, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL,
                          result, sizeof(result), &result_size);
        printf("CODE 0x%08x SIZE %u\n", code, result_size);
        Tbsip_Context_Close(context);
        return 0;
    }
    if (!strcmp(scenario, "cancel-stdin"))
    {
        char line[64];
        printf("READY\n");
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin))
        {
            print_code("CODE", (TBS_RESULT)-1);
            return 0;
        }
        /* The gate stops the vTPM between READY and this line. */
        print_code("CODE", Tbsip_Cancel_Commands(context));
        return 0;
    }
    if (!strcmp(scenario, "submit-loop"))
    {
        int iterations = argc > 2 ? atoi(argv[2]) : 50;
        unsigned int ok = 0;
        for (int i = 0; i < iterations; i++)
        {
            code = run_submit(context, 4, 12, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL,
                              result, sizeof(result), &result_size);
            if (code == TBS_SUCCESS)
                ok++;
        }
        printf("SUBMITS %u/%d\n", ok, iterations);
        Tbsip_Context_Close(context);
        return 0;
    }
    if (!strcmp(scenario, "cancel-loop"))
    {
        int iterations = argc > 2 ? atoi(argv[2]) : 25;
        unsigned int ok = 0;
        for (int i = 0; i < iterations; i++)
            if (Tbsip_Cancel_Commands(context) == TBS_SUCCESS)
                ok++;
        printf("CANCELS %u/%d\n", ok, iterations);
        Tbsip_Context_Close(context);
        return 0;
    }
    if (!strcmp(scenario, "vendor-identity"))
    {
        /* GetCapability(TPM_CAP_TPM_PROPERTIES=6, property=0x105
         * (PT_MANUFACTURER), count=2): manufacturer and vendor
         * string 1 arrive through the layer, verbatim. */
        unsigned char command[22];
        store_be16(command, 0x8001);
        store_be32(command + 2, 22);
        store_be32(command + 6, 0x017a);
        store_be32(command + 10, 6);
        store_be32(command + 14, 0x105);
        store_be32(command + 18, 2);
        result_size = sizeof(result);
        code = Tbsip_Submit_Command(context, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL,
                                    command, 22, result, &result_size);
        printf("CODE 0x%08x SIZE %u\n", code, result_size);
        print_response("RESPONSE ", result, result_size);
        Tbsip_Context_Close(context);
        return 0;
    }

    fprintf(stderr, "unknown scenario: %s\n", scenario);
    return 2;
}
