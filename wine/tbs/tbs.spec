# SPDX-License-Identifier: LGPL-2.1-or-later
# The upstream Wine tbs.spec with the three M10-049 promotions:
# Submit/Cancel/Close move from @stub to @stdcall against the
# per-prefix vTPM implementation (wine/tbs/tbs.c, ADR-0045).
# Everything else stays stubbed. Kept here as the spec portion of
# the upstream patch; not part of the standalone gate build.

@ stdcall GetDeviceIDString(ptr long ptr ptr)
@ stdcall Tbsi_Context_Create(ptr ptr)
@ stdcall Tbsi_GetDeviceInfo(long ptr)
@ stdcall Tbsip_Cancel_Commands(ptr)
@ stdcall Tbsip_Context_Close(ptr)
@ stdcall Tbsip_Submit_Command(ptr long long ptr long ptr ptr)
@ stub Tbsi_Create_Attestation_From_Log
@ stub Tbsi_Create_Windows_Key
@ stub Tbsi_FilterLog
@ stub Tbsi_Get_OwnerAuth
@ stub Tbsi_Get_TCG_Log
@ stub Tbsi_Get_TCG_Log_Ex
@ stub Tbsi_Get_TCG_Logs
@ stub Tbsi_Physical_Presence_Command
@ stub Tbsi_Revoke_Attestation
@ stub Tbsi_ShaHash
@ stub Tbsip_Submit_Command_NonBlocking
@ stub Tbsip_TestInterruptInformation
@ stub Tbsip_TestMorBit
