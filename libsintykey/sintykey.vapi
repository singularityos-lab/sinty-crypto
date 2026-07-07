/* Vala binding for libsintykey (C ABI). Link the compiled lib and pass this vapi
 * to valac; the desktop UIs (installer OOBE, shell Settings) call it from Vala. */
[CCode (cheader_filename = "libsintykey.h")]
namespace Sintykey {
    [CCode (cname = "sintykey_key", has_type_id = false)]
    public struct Key {
        public uint8 bytes[32];
    }

    [CCode (cname = "sintykey_generate")]
    public int generate (out Key k);

    /* buf must be >= 40 bytes; on success it holds a NUL-terminated savable code. */
    [CCode (cname = "sintykey_recovery_generate")]
    public int recovery_generate ([CCode (array_length = false)] uint8[] buf, size_t len);

    [CCode (cname = "sintykey_recovery_wrap")]
    public int recovery_wrap (ref Key k, string secret,
                              [CCode (array_length = false)] uint8[] blob, out size_t blob_len);

    [CCode (cname = "sintykey_recovery_unwrap")]
    public int recovery_unwrap ([CCode (array_length = false)] uint8[] blob, size_t blob_len,
                                string secret, out Key k);

    [CCode (cname = "sintykey_tpm_seal")]
    public int tpm_seal (ref Key k, string pin, string blob_path);
    [CCode (cname = "sintykey_tpm_unseal")]
    public int tpm_unseal (string blob_path, string pin, out Key k);
    [CCode (cname = "sintykey_verify_pin")]
    public int verify_pin (string blob_path, string pin);
    [CCode (cname = "sintykey_change_pin")]
    public int change_pin (string blob_path, string old_pin, string new_pin);
}
