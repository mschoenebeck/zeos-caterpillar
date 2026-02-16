#include <cstddef>
#include <cstdint>

extern "C" {

typedef struct wallet wallet_t;

extern const char* wallet_last_error();
extern void free_string(const char* ptr);
extern bool wallet_create(const char* seed, bool is_ivk, const char* chain_id, const char* protocol_contract, const char* vault_contract, const char* alias_authority, wallet_t*& out_p_wallet);
extern void wallet_close(wallet_t* p_wallet);
extern bool wallet_seed_hex(wallet_t* p_wallet, const char** out_seed_hex);
extern bool wallet_size(wallet_t* p_wallet, uint64_t* out_size);
extern bool wallet_is_ivk(wallet_t* p_wallet, bool* out_is_ivk);
extern bool wallet_chain_id(wallet_t* p_wallet, const char** out_chain_id);
extern bool wallet_protocol_contract(wallet_t* p_wallet, const char** out_protocol_contract);
extern bool wallet_vault_contract(wallet_t* p_wallet, const char** out_vault_contract);
extern bool wallet_alias_authority(wallet_t* p_wallet, const char** out_alias_authority);
extern bool wallet_block_num(wallet_t* p_wallet, uint32_t* out_block_num);
extern bool wallet_leaf_count(wallet_t* p_wallet, uint64_t* out_leaf_count);
extern bool wallet_auth_count(wallet_t* p_wallet, uint64_t* out_auth_count);
extern bool wallet_set_auth_count(wallet_t* p_wallet, uint64_t count);
extern bool wallet_write(wallet_t* p_wallet, char* out_bytes);
extern bool wallet_read(const char* p_bytes, size_t len, wallet_t*& out_p_wallet);
extern bool wallet_is_encrypted(const char* p_bytes, size_t len, bool* out_is_encrypted);
extern bool wallet_encrypt_size(uint64_t plain_len, uint64_t* out_size);
extern bool wallet_encrypt_bytes(const char* p_plain, size_t plain_len, const char* password, char* out_bytes);
extern bool wallet_decrypt_size(const char* p_enc, size_t enc_len, uint64_t* out_size);
extern bool wallet_decrypt_bytes(const char* p_enc, size_t enc_len, const char* password, char* out_plain);
extern bool wallet_json(wallet_t* p_wallet, bool pretty, const char** out_json);
extern bool wallet_balances_json(wallet_t* p_wallet, bool pretty, const char** out_json);
extern bool wallet_unspent_notes_json(wallet_t* p_wallet, bool pretty, const char** out_json);
extern bool wallet_fungible_tokens_json(wallet_t* p_wallet, uint64_t symbol, uint64_t contract, bool pretty, const char** out_json);
extern bool wallet_non_fungible_tokens_json(wallet_t* p_wallet, uint64_t contract, bool pretty, const char** out_json);
extern bool wallet_authentication_tokens_json(wallet_t* p_wallet, uint64_t contract, bool spent, bool seed, bool pretty, const char** out_json);
extern bool wallet_unpublished_notes_json(wallet_t* p_wallet, bool pretty, const char** out_json);
extern bool wallet_transaction_history_json(wallet_t* p_wallet, bool pretty, const char** out_json);
extern bool wallet_addresses_json(wallet_t* p_wallet, bool pretty, const char** out_json);
extern bool wallet_derive_address(wallet_t* p_wallet, const char** out_address);
extern bool wallet_add_leaves(wallet_t* p_wallet, const char* leaves);
extern bool wallet_add_notes(wallet_t* p_wallet, const char* notes);
extern bool wallet_add_unpublished_notes(wallet_t* p_wallet, const char* unpublished_notes);
extern bool wallet_create_unpublished_auth_note(wallet_t* p_wallet, const char* seed, uint64_t contract, const char* address, const char** out_unpublished_notes);
extern bool wallet_resolve(wallet_t* p_wallet, const char* ztx_json, const char* fee_token_contract_json, const char* fees_json, const char** out_rztx_json);
extern bool wallet_zsign(wallet_t* p_wallet, const char* rztx_json, const char* p_mint_params_bytes, size_t mint_params_bytes_len, const char* p_spendoutput_params_bytes, size_t spendoutput_params_bytes_len, const char* p_spend_params_bytes, size_t spend_params_bytes_len, const char* p_output_params_bytes, size_t output_params_bytes_len, const char** out_tx_json);
extern bool wallet_zverify_spend(const char* tx_json, const char* p_spendoutput_params_bytes, size_t spendoutput_params_bytes_len, const char* p_spend_params_bytes, size_t spend_params_bytes_len, const char* p_output_params_bytes, size_t output_params_bytes_len, bool* out_is_valid);
extern bool wallet_transact(wallet_t* p_wallet, const char* ztx_json, const char* fee_token_contract_json, const char* fees_json, const char* p_mint_params_bytes, size_t mint_params_bytes_len, const char* p_spendoutput_params_bytes, size_t spendoutput_params_bytes_len, const char* p_spend_params_bytes, size_t spend_params_bytes_len, const char* p_output_params_bytes, size_t output_params_bytes_len, const char** out_tx_json);
extern bool wallet_digest_block(wallet_t* p_wallet, const char* block, uint64_t* out_digest);
extern bool wallet_reset_chain_state(wallet_t* pWallet);

} // extern "C"
