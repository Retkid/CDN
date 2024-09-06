#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef enum OutwardCommExceptions {
  NoException,
  FailedToWriteMessage,
  ExpectedPrivateKeyGotPublic,
  FailedToParseKeyPublic,
  FailedToParseKeyPrivate,
  FailedToParseKey,
  CertRevoked,
  CertMaybeRevoked,
  FailedToConvertCString,
  NoKeyMeetsSelection,
  FailedToParseMessage,
  PackedParserFailedToRecurse,
  FailedToReadFromBuffer,
  CertGenerationFailed,
  FailedToRevokeSubkey,
  FailedToRevokePrimaryKey,
  FailedToEncryptKey,
  FoundEncryptedSecretButNoPasswordHandler,
  PasswordSetToAtomicButMissingEncryptedKeyid,
  IncorrectPasswordForSecretKey,
  IncorrectKeyFlags,
  CertIsInvalid,
} OutwardCommExceptions;

typedef struct GenerationOutput {
  char *private_key;
  char *public_key;
  char *keyids;
  uint64_t *subkey_valid_length;
  uint64_t *creation_times;
  uint8_t *key_flags;
  enum OutwardCommExceptions error_code;
  uint8_t key_count;
  uint8_t user_id_count;
  char *const *user_ids;
  char *cert_fingerprint;
} GenerationOutput;

typedef struct GenerateKey {
  uint8_t key_flags_bitfield;
  const char *const *user_ids;
  uint8_t user_ids_length;
  uint8_t cipher;
  bool expires;
  bool has_user_ids;
  uint32_t expire_length_seconds;
} GenerateKey;

typedef struct SimpleResponse {
  enum OutwardCommExceptions error_code;
  char *message;
} SimpleResponse;

typedef struct PasswordHandlerInput {
  const char *global_password;
  bool use_atomic_password;
  uint8_t key_count;
  const char *const *keyids;
  const char *const *password_by_keyid;
  bool initialized;
} PasswordHandlerInput;

typedef struct ValidationOutput {
  enum OutwardCommExceptions error_code;
  bool is_valid;
  char *literal_body;
} ValidationOutput;

typedef struct DecryptOutput {
  enum OutwardCommExceptions error_code;
  bool success;
  char *decrypted_data;
} DecryptOutput;

typedef struct MutatedCert {
  char *private_key;
  char *public_key;
  enum OutwardCommExceptions error_code;
} MutatedCert;

typedef struct RevokeStatus {
  uint8_t status;
  enum OutwardCommExceptions error_code;
} RevokeStatus;

char *get_version(void);

void free_rust_pointer(uint8_t *a);

void free_rust_array(uint8_t *pointer, uint64_t size_in_bytes);

struct GenerationOutput create_new_pgp(const struct GenerateKey *keys,
                                       uint8_t key_length,
                                       uint8_t primary_cipher,
                                       const char *const *user_ids,
                                       uint8_t user_ids_length,
                                       bool cert_has_expiration_length,
                                       uint32_t cert_valid_length_seconds);

struct SimpleResponse sign_message(const char *private_key,
                                   const char *message,
                                   const char *keyid,
                                   bool use_keyid,
                                   bool has_password,
                                   struct PasswordHandlerInput password_handler);

struct SimpleResponse send_message(const char *const *to_public_keys,
                                   uint8_t key_count,
                                   const char *message);

struct ValidationOutput verify_signature(const char *const *from_public_keys,
                                         uint8_t key_count,
                                         const char *message);

struct DecryptOutput decrypt_message(const char *const *private_keys,
                                     uint8_t key_count,
                                     const char *message,
                                     bool has_password,
                                     struct PasswordHandlerInput handler);

struct SimpleResponse get_recipients(const char *message);

struct MutatedCert revoke_cert(const char *private_key,
                               bool has_password,
                               struct PasswordHandlerInput password_handler,
                               bool revoke_subkey,
                               const char *keyid,
                               uint8_t reason,
                               bool has_message,
                               const char *message);

struct RevokeStatus is_revoked(const char *key, bool check_subkey, const char *keyid);

struct MutatedCert encrypt_key(const char *private_key,
                               const char *keyid,
                               const char *new_password,
                               bool has_old_password,
                               const char *old_password);

struct GenerationOutput scaffold_key(const char *key);
