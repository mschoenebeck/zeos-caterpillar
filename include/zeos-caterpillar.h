#include <cstddef>
#include <cstdint>

extern "C" {

typedef struct wallet wallet_t;

extern bool wallet_create(const char* seed, bool is_ivk, const char* chain_id, const char* protocol_contract, const char* alias_authority, wallet_t*& p_wallet);
extern void wallet_close(wallet_t* p_wallet);
extern uint64_t wallet_size(wallet_t* p_wallet);
extern bool wallet_is_ivk(wallet_t* p_wallet);
extern const char* wallet_chain_id(wallet_t* p_wallet);
extern const char* wallet_protocol_contract(wallet_t* p_wallet);
extern const char* wallet_alias_authority(wallet_t* p_wallet);
extern uint32_t wallet_block_num(wallet_t* p_wallet);
extern uint64_t wallet_leaf_count(wallet_t* p_wallet);
extern int64_t wallet_write(wallet_t* p_wallet, char* p_bytes);
extern bool wallet_read(const char* p_bytes, size_t len, wallet_t*& p_wallet);
extern const char* wallet_json(wallet_t* p_wallet, bool pretty);
extern const char* wallet_balances_json(wallet_t* p_wallet, bool pretty);
extern const char* wallet_unspent_notes_json(wallet_t* p_wallet, bool pretty);
extern const char* wallet_fungible_tokens_json(wallet_t* p_wallet, uint64_t symbol, uint64_t contract, bool pretty);
extern const char* wallet_non_fungible_tokens_json(wallet_t* p_wallet, uint64_t contract, bool pretty);
extern const char* wallet_authentication_tokens_json(wallet_t* p_wallet, uint64_t contract, bool spent, bool pretty);
extern const char* wallet_unpublished_notes_json(wallet_t* p_wallet, bool pretty);
extern const char* wallet_transaction_history_json(wallet_t* p_wallet, bool pretty);
extern const char* wallet_addresses_json(wallet_t* p_wallet, bool pretty);
extern const char* wallet_derive_address(wallet_t* p_wallet);
extern void free_string(const char* ptr);
extern void wallet_add_leaves(wallet_t* p_wallet, const char* leaves);
extern void wallet_add_notes(wallet_t* p_wallet, const char* notes);
extern void wallet_add_unpublished_notes(wallet_t* p_wallet, const char* unpublished_notes);
extern const char* wallet_resolve(wallet_t* p_wallet, const char* ztx_json, const char* fee_token_contract_json, const char* fees_json);
extern const char* wallet_zsign(wallet_t* p_wallet, const char* rztx_json, const char* p_mint_params_bytes, size_t mint_params_bytes_len, const char* p_spendoutput_params_bytes, size_t spendoutput_params_bytes_len, const char* p_spend_params_bytes, size_t spend_params_bytes_len, const char* p_output_params_bytes, size_t output_params_bytes_len);
extern const char* wallet_zverify_spend(const char* tx_json, const char* p_spendoutput_params_bytes, size_t spendoutput_params_bytes_len, const char* p_spend_params_bytes, size_t spend_params_bytes_len, const char* p_output_params_bytes, size_t output_params_bytes_len);
extern const char* wallet_transact(wallet_t* p_wallet, const char* ztx_json, const char* fee_token_contract_json, const char* fees_json, char* p_mint_params_bytes, size_t mint_params_bytes_len, char* p_spendoutput_params_bytes, size_t spendoutput_params_bytes_len, char* p_spend_params_bytes, size_t spend_params_bytes_len, char* p_output_params_bytes, size_t output_params_bytes_len);
extern uint64_t wallet_digest_block(wallet_t* p_wallet, const char* block);

} // extern "C"