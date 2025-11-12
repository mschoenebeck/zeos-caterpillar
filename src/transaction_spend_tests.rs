#[cfg(test)]
mod tests
{
    use crate::{transaction::{ZTransaction, resolve_ztransaction, zsign_transaction, zverify_spend_transaction}, note::{Note, Rseed}, eosio::{Name, ExtendedAsset, Asset, Authorization}, wallet::Wallet, keys::{SpendingKey, FullViewingKey}, note_encryption::{NoteEncryption, derive_esk, ka_derive_public, TransmittedNoteCiphertext}};
    use rand::rngs::OsRng;
    use bellman::groth16::Parameters;
    use bls12_381::Bls12;
    use std::fs::File;
    use std::collections::HashMap;

    #[test]
    fn test_spend()
    {
        println!("read params...");
        let mut params = HashMap::new();
        let f = File::open("params_mint.bin").unwrap();
        params.insert(Name::from_string(&"mint".to_string()).unwrap(), Parameters::<Bls12>::read(f, false).unwrap());
        let f = File::open("params_spendoutput.bin").unwrap();
        params.insert(Name::from_string(&"spendoutput".to_string()).unwrap(), Parameters::<Bls12>::read(f, false).unwrap());
        let f = File::open("params_spend.bin").unwrap();
        params.insert(Name::from_string(&"spend".to_string()).unwrap(), Parameters::<Bls12>::read(f, false).unwrap());
        let f = File::open("params_output.bin").unwrap();
        params.insert(Name::from_string(&"output".to_string()).unwrap(), Parameters::<Bls12>::read(f, false).unwrap());

        let mut rng = OsRng.clone();
        let seed = b"this is a sample seed which should be at least 32 bytes long...";
        let fvk = FullViewingKey::from_spending_key(&SpendingKey::from_seed(seed));
        let mut w = Wallet::create(
            seed,
            false,
            [0; 32],
            Name::from_string(&format!("zeos4privacy")).unwrap(),
            Name::from_string(&format!("thezeosvault")).unwrap(),
            Authorization::from_string(&format!("thezeosalias@public")).unwrap()
        ).unwrap();

        let notes = vec![
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"7.0000 ZEOS@thezeostoken".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"17.0000 ZEOS@thezeostoken".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"10.0000 EOS@eosio.token".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"5.0000 EOS@eosio.token".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"4.0000 EOS@eosio.token".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"4.0000 EOS@eosio.token".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"3.0000 EOS@eosio.token".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"3.0000 EOS@eosio.token".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"20.0000 EOS@eosio.token".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"2.0000 EOS@eosio.token".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"2.0000 EOS@eosio.token".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"2.0000 EOS@eosio.token".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"12345678987654321@atomicassets".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"99999999998765431@atomicassets".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"88888888887654321@atomicassets".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512]),
            Note::from_parts(0, w.default_address().unwrap(), Name(0), ExtendedAsset::from_string(&"12345677777777321@atomicassets".to_string()).unwrap(), Rseed::new(&mut rng), [0; 512])
        ];

        for n in notes.iter()
        {
            let esk = derive_esk(n).unwrap();
            let epk = ka_derive_public(n, &esk);
            let ne = NoteEncryption::new(Some(fvk.ovk), n.clone());
            let encrypted_note = TransmittedNoteCiphertext {
                epk_bytes: epk.to_bytes().0,
                enc_ciphertext: ne.encrypt_note_plaintext(),
                out_ciphertext: ne.encrypt_outgoing_plaintext(&mut rng),
            };
            w.add_leaves(&n.commitment().to_bytes());
            w.add_notes(&vec![encrypted_note.to_base64()], 0, 0);
        }

        let fee_token_contract = Name::from_string(&"thezeostoken".to_string()).unwrap();
        let mut fees = HashMap::new();
        fees.insert(Name::from_string(&"begin".to_string()).unwrap(), Asset::from_string(&"1.0000 ZEOS".to_string()).unwrap());
        fees.insert(Name::from_string(&"mint".to_string()).unwrap(), Asset::from_string(&"1.0000 ZEOS".to_string()).unwrap());
        fees.insert(Name::from_string(&"spendoutput".to_string()).unwrap(), Asset::from_string(&"1.0000 ZEOS".to_string()).unwrap());
        fees.insert(Name::from_string(&"spend".to_string()).unwrap(), Asset::from_string(&"1.0000 ZEOS".to_string()).unwrap());
        fees.insert(Name::from_string(&"output".to_string()).unwrap(), Asset::from_string(&"1.0000 ZEOS".to_string()).unwrap());
        fees.insert(Name::from_string(&"authenticate".to_string()).unwrap(), Asset::from_string(&"1.0000 ZEOS".to_string()).unwrap());
        fees.insert(Name::from_string(&"publishnotes".to_string()).unwrap(), Asset::from_string(&"1.0000 ZEOS".to_string()).unwrap());
        //fees.insert(Name::from_string(&"withdraw".to_string()).unwrap(), Asset::from_string(&"1.0000 ZEOS".to_string()).unwrap());

        let json = r#"{
            "chain_id": "aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906",
            "protocol_contract": "zeos4privacy",
            "vault_contract": "thezeosvault",
            "alias_authority": "thezeosalias@public",
            "add_fee": true,
            "publish_fee_note": true,
            "zactions": [
                {
                    "name": "spend",
                    "data": {
                        "contract": "eosio.token",
                        "change_to": "$SELF",
                        "publish_change_note": true,
                        "to": [
                            {
                                "to": "mschoenebeck",
                                "quantity": "10.0000 EOS",
                                "memo": "",
                                "publish_note": true
                            },
                            {
                                "to": "mschoenebeck",
                                "quantity": "10.0000 EOS",
                                "memo": "",
                                "publish_note": true
                            },
                            {
                                "to": "za1myffclyc7d5k05q9tpd9kn74el0uljwhfycm0kxnqmpvv5qzcm8wezc70855rlsmlehmwv87k5c",
                                "quantity": "2.0000 EOS",
                                "memo": "",
                                "publish_note": true
                            },
                            {
                                "to": "za1myffclyc7d5k05q9tpd9kn74el0uljwhfycm0kxnqmpvv5qzcm8wezc70855rlsmlehmwv87k5c",
                                "quantity": "2.0000 EOS",
                                "memo": "",
                                "publish_note": true
                            },
                            {
                                "to": "za1myffclyc7d5k05q9tpd9kn74el0uljwhfycm0kxnqmpvv5qzcm8wezc70855rlsmlehmwv87k5c",
                                "quantity": "1.0000 EOS",
                                "memo": "",
                                "publish_note": true
                            },
                            {
                                "to": "za1myffclyc7d5k05q9tpd9kn74el0uljwhfycm0kxnqmpvv5qzcm8wezc70855rlsmlehmwv87k5c",
                                "quantity": "1.0000 EOS",
                                "memo": "",
                                "publish_note": true
                            }
                        ]
                    }
                }
            ]
        }"#;

        let ztx: ZTransaction = serde_json::from_str(&json).unwrap();
        let rztx = resolve_ztransaction(&w, &fee_token_contract, &fees, &ztx);
        let rztx = match rztx {
            Err(e) => panic!("Error: {:?}", e),
            Ok(x) => x
        };
        println!("{}", serde_json::to_string_pretty(&rztx).unwrap());
        println!("zsign...");
        let tx = zsign_transaction(&w, &rztx, &params);
        let tx = match tx {
            Err(e) => panic!("Error: {:?}", e),
            Ok(x) => x
        };
        println!("{}", serde_json::to_string_pretty(&tx).unwrap());
        println!("zverify...");
        assert!(zverify_spend_transaction(&tx.0, &params).is_ok());

        let json = r#"{
            "chain_id": "aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906",
            "protocol_contract": "zeos4privacy",
            "vault_contract": "thezeosvault",
            "alias_authority": "thezeosalias@public",
            "add_fee": true,
            "publish_fee_note": true,
            "zactions": [
                {
                    "name": "spend",
                    "data": {
                        "contract": "eosio.token",
                        "change_to": "$SELF",
                        "publish_change_note": true,
                        "to": [
                            {
                                "to": "za1myffclyc7d5k05q9tpd9kn74el0uljwhfycm0kxnqmpvv5qzcm8wezc70855rlsmlehmwv87k5c",
                                "quantity": "1.0000 EOS"
                                "memo": "",
                                "publish_note": true
                            },
                            {
                                "to": "za1myffclyc7d5k05q9tpd9kn74el0uljwhfycm0kxnqmpvv5qzcm8wezc70855rlsmlehmwv87k5c",
                                "quantity": "1.0000 EOS"
                                "memo": "",
                                "publish_note": true
                            },
                            {
                                "to": "za1myffclyc7d5k05q9tpd9kn74el0uljwhfycm0kxnqmpvv5qzcm8wezc70855rlsmlehmwv87k5c",
                                "quantity": "1.0000 EOS"
                                "memo": "",
                                "publish_note": true
                            },
                            {
                                "to": "za1myffclyc7d5k05q9tpd9kn74el0uljwhfycm0kxnqmpvv5qzcm8wezc70855rlsmlehmwv87k5c",
                                "quantity": "1.0000 EOS"
                                "memo": "",
                                "publish_note": true
                            },
                            {
                                "to": "za1myffclyc7d5k05q9tpd9kn74el0uljwhfycm0kxnqmpvv5qzcm8wezc70855rlsmlehmwv87k5c",
                                "quantity": "1.0000 EOS"
                                "memo": "",
                                "publish_note": true
                            },
                            {
                                "to": "za1myffclyc7d5k05q9tpd9kn74el0uljwhfycm0kxnqmpvv5qzcm8wezc70855rlsmlehmwv87k5c",
                                "quantity": "1.0000 EOS"
                                "memo": "",
                                "publish_note": true
                            },
                            {
                                "to": "za1myffclyc7d5k05q9tpd9kn74el0uljwhfycm0kxnqmpvv5qzcm8wezc70855rlsmlehmwv87k5c",
                                "quantity": "1.0000 EOS"
                                "memo": "",
                                "publish_note": true
                            }
                        ]
                    }
                }
            ]
        }"#;

        let ztx: ZTransaction = serde_json::from_str(&json).unwrap();
        let rztx = resolve_ztransaction(&w, &fee_token_contract, &fees, &ztx);
        let rztx = match rztx {
            Err(e) => panic!("Error: {:?}", e),
            Ok(x) => x
        };
        println!("{}", serde_json::to_string_pretty(&rztx).unwrap());
        println!("zsign...");
        let tx = zsign_transaction(&w, &rztx, &params);
        let tx = match tx {
            Err(e) => panic!("Error: {:?}", e),
            Ok(x) => x
        };
        println!("{}", serde_json::to_string_pretty(&tx).unwrap());
        println!("zverify...");
        assert!(zverify_spend_transaction(&tx.0, &params).is_ok());

        let json = r#"{
            "chain_id": "aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906",
            "protocol_contract": "zeos4privacy",
            "vault_contract": "thezeosvault",
            "alias_authority": "thezeosalias@public",
            "add_fee": true,
            "publish_fee_note": true,
            "zactions": [
                {
                    "name": "spend",
                    "data": {
                        "contract": "eosio.token",
                        "change_to": "$SELF",
                        "publish_change_note": true,
                        "to": [
                            {
                                "to": "za1myffclyc7d5k05q9tpd9kn74el0uljwhfycm0kxnqmpvv5qzcm8wezc70855rlsmlehmwv87k5c",
                                "quantity": "50.0000 EOS",
                                "memo": "",
                                "publish_note": true
                            }
                        ]
                    }
                }
            ]
        }"#;

        let ztx: ZTransaction = serde_json::from_str(&json).unwrap();
        let rztx = resolve_ztransaction(&w, &fee_token_contract, &fees, &ztx);
        let rztx = match rztx {
            Err(e) => panic!("Error: {:?}", e),
            Ok(x) => x
        };
        println!("{}", serde_json::to_string_pretty(&rztx).unwrap());
        println!("zsign...");
        let tx = zsign_transaction(&w, &rztx, &params);
        let tx = match tx {
            Err(e) => panic!("Error: {:?}", e),
            Ok(x) => x
        };
        println!("{}", serde_json::to_string_pretty(&tx).unwrap());
        println!("zverify...");
        assert!(zverify_spend_transaction(&tx.0, &params).is_ok());

        let json = r#"{
            "chain_id": "aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906",
            "protocol_contract": "zeos4privacy",
            "vault_contract": "thezeosvault",
            "alias_authority": "thezeosalias@public",
            "add_fee": true,
            "publish_fee_note": true,
            "zactions": [
                {
                    "name": "spend",
                    "data": {
                        "contract": "atomicassets",
                        "change_to": "$SELF",
                        "publish_change_note": true,
                        "to": [
                            {
                                "to": "mschoenebeck",
                                "quantity": "12345678987654321",
                                "memo": "",
                                "publish_note": true
                            },
                            {
                                "to": "za1myffclyc7d5k05q9tpd9kn74el0uljwhfycm0kxnqmpvv5qzcm8wezc70855rlsmlehmwv87k5c",
                                "quantity": "99999999998765431",
                                "memo": "",
                                "publish_note": true
                            },
                            {
                                "to": "za1myffclyc7d5k05q9tpd9kn74el0uljwhfycm0kxnqmpvv5qzcm8wezc70855rlsmlehmwv87k5c",
                                "quantity": "88888888887654321",
                                "memo": "",
                                "publish_note": true
                            },
                            {
                                "to": "mschoenebeck",
                                "quantity": "12345677777777321",
                                "memo": "",
                                "publish_note": true
                            }
                        ]
                    }
                }
            ]
        }"#;

        let ztx: ZTransaction = serde_json::from_str(&json).unwrap();
        let rztx = resolve_ztransaction(&w, &fee_token_contract, &fees, &ztx);
        let rztx = match rztx {
            Err(e) => panic!("Error: {:?}", e),
            Ok(x) => x
        };
        println!("{}", serde_json::to_string_pretty(&rztx).unwrap());
        println!("zsign...");
        let tx = zsign_transaction(&w, &rztx, &params);
        let tx = match tx {
            Err(e) => panic!("Error: {:?}", e),
            Ok(x) => x
        };
        println!("{}", serde_json::to_string_pretty(&tx).unwrap());
        println!("zverify...");
        assert!(zverify_spend_transaction(&tx.0, &params).is_ok());
    }
}