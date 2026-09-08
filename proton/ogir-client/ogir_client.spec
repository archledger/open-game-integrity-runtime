# The PE export table for ogir-client.dll (winelib form). Every
# entry binds to the ms_abi wrapper in ogir_client_dll.c; the
# wrappers forward to the native implementations unchanged.
@ cdecl ogir_client_open(ptr) ogir_client_open_msabi
@ cdecl ogir_client_close(ptr) ogir_client_close_msabi
@ cdecl ogir_session_begin(ptr ptr ptr) ogir_session_begin_msabi
@ cdecl ogir_session_get_permit(ptr ptr) ogir_session_get_permit_msabi
@ cdecl ogir_session_sign_binding(ptr ptr ptr ptr) ogir_session_sign_binding_msabi
@ cdecl ogir_session_close(ptr) ogir_session_close_msabi
