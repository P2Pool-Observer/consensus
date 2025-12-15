# Carrot and FCMP++ notes for StressNet

## Blocks


### New fields
Blocks contain two additional fields after `tx_hashes`:
```go
FCMPTreeLayers uint8      `json:"fcmp_pp_n_tree_layers,omitzero"`
FCMPTreeRoot   types.Hash `json:"fcmp_pp_tree_root,omitzero"`
```
These fields are serialized directly after `tx_hashes` as uint8 and hash, no varint is required.

The fields are also sent in miner data responses.

### CHANGE: Hashing blob

Previously the block hashing blob merkle root hash (calculated on `get_block_content_hash`) was calculated from this data:
```
#0 miner_tx_id
#... [other txs]
```

After Hardfork 17 `HF_VERSION_FCMP_PLUS_PLUS`, it is now calculated like this
```
#0 fcmp_pp_n_tree_layers + 31 zero bytes
#1 fcmp_pp_tree_root
#2 miner_tx_id
#... [other txs]
```

This causes some performance issues on how the merkle tree is calculated efficiently for miner proxies. Most calculate the "main branch", leaving slot _#0 miner_tx_id_ empty.
This allows an efficient calculation of the merkle root after coinbase id changes (new template, merge mining, different tx extra nonce) by just replacing `miner_tx_id` and running few hashes.

Without major changes, this is no longer possible. This change is suggested:
```
#0 miner_tx_id
#... [other txs]
# fcmp_pp_n_tree_layers + 31 zero bytes
# fcmp_pp_tree_root
```

Or alternatively:
```
#0 miner_tx_id
#1 fcmp_pp_n_tree_layers + 31 zero bytes
#2 fcmp_pp_tree_root
#... [other txs]
```

Any of the above would allow an efficient calculation and reduce the number of changes that need to be made across all miners, pools, proxies to a trivial one.

See relevant logs:
```
14:30:20 <DataHoarder> suggestion from sech1 and me: move fcmp_pp_n_tree_layers + 31 zero bytes, fcmp_pp_tree_root in the merkle root in hashing to the end
14:30:30 <sech1> yes
14:30:36 <DataHoarder> or at least have coinbase id at the front (index 0)
14:30:40 <sech1> so much code depends on miner tx hash being first in the list
14:31:36 <DataHoarder> in monero code this is in get_block_content_hash
14:31:41 <sech1> Updating miner tx (changing extra nonce, for example, when pools need to do it) is so simple right now - just hash the left-most tree branch
14:31:48 <sech1> after FCMP++ it will get complicated
14:32:21 <DataHoarder> order wise it makes sense to have them at the end, as in block header it's miner tx -> tx hashes -> fcmp layers/root
14:32:32 <sech1> it will require unneded changes in all pool software (including p2pool and xmrig-proxy)
14:32:36 <DataHoarder> so merkle tree is made in the same orders
14:32:52 <DataHoarder> sech1: and all pools that handle their own templates
14:32:56 <sech1> yes
14:32:59 <DataHoarder> node proxy etc.
14:33:10 <DataHoarder> if moved changes are needed, but they are minimal
```


> **NOTE**: [PR seraphis-migration/monero#137](https://github.com/seraphis-migration/monero/pull/137) has changed the order to put _miner_tx_id_ at 0, _fcmp_pp_n_tree_layers_ at 1, _fcmp_pp_tree_root_ at 2, then _tx_hashes_


## Miner Transaction

### Output types
Hardfork 17 implements `HF_VERSION_FCMP_PLUS_PLUS`.

All coinbase outputs must be `carrot_v1`.

This is checked on `prevalidate_miner_transaction`:
```cpp
CHECK_AND_ASSERT_MES(check_output_types(b.miner_tx, hf_version), false, "miner transaction has invalid output type(s) in block " << get_block_hash(b));
```

### Output count limit
Hardfork 17 implements `HF_VERSION_REJECT_MANY_MINER_OUTPUTS`.

Miner output count must be less or equal to `FCMP_PLUS_PLUS_MAX_MINER_OUTPUTS = 10000`.

This is checked on `prevalidate_miner_transaction`:
```cpp
// from v17, require number of tx outputs to be within limit
if (hf_version >= HF_VERSION_REJECT_MANY_MINER_OUTPUTS) {
    CHECK_AND_ASSERT_MES(b.miner_tx.vout.size() <= FCMP_PLUS_PLUS_MAX_MINER_OUTPUTS,
        false, "too many miner transaction outputs");
}
```

### Sorted outputs
Hardfork 17 implements `HF_VERSION_FCMP_PLUS_PLUS`.

Transactions must have their outputs sorted based on the _key_, lowest to highest, following `memcmp` memory ordering.

Ephemeral public keys included in tx extra MUST also be in the same order or scanning will break.

This is checked on `prevalidate_miner_transaction`:
```cpp
CHECK_AND_ASSERT_MES(check_transaction_output_pubkeys_order(b.miner_tx, hf_version),
  false, "FCMP++ miner transaction has unsorted outputs in block " << get_block_hash(b));
```

### CHANGE: No subaddresses allowed

In `try_scan_carrot_coinbase_enote_checked` the code does the following check:
```cpp
if (!is_main_address_spend_pubkey(address_spend_pubkey_out, main_addresss_spend_pubkeys))
    return false;
```

This entirely removes subaddresses as valid targets in coinbase outputs.

Note that reference calls via RPC or code to `get_miner_template` / `construct_miner_tx` only allowed a main address to be passed.

Alternative miners that generated their own block templates and coinbase transactions could pay to subaddresses as there
was no technical limitation in the past, as long as derivations and relevant public keys in tx extra were included.

To reduce the number of public keys in tx extra, P2Pool instead allows users to specify their main address and subaddress and pay to `{subaddress_spend_pub, main_view_pub}` abusing the Janus trick.

See relevant explanation logs:
```
21:18:31 <DataHoarder> curious, on both implementations I have seen subaddresses are explicitly disallowed to be created on coinbase (though they could technically be derived?)
21:18:46 <DataHoarder> monero explicitly does if (!is_main_address_spend_pubkey(address_spend_pubkey_out, main_addresss_spend_pubkeys)) for the valid subaddress coinbase outputs I mined :)
21:19:58 <DataHoarder> given that having the tx pub / tx additional pubs is now required p2pool can basically mine to subaddresses without users doing effectively Janus attack to themselves
21:20:19 <DataHoarder> the price of having multiple tx pubs is paid already

22:26:48 <jeffro256:monero.social> 
    DataHoarder: the reason that only main addresses are used for coinbase transactions is so that outputs can be marked as "probably" owned or not without a subaddress table loaded.
    In non-coinbase transactions, the amount commitment acts as a "hard target" for marking outputs as probably owned if the amount commitment can be recomputed since its a function of your view key.
    A coinbase transaction doesn't have that so everyone can scan coinbase enoes to some sub address pubkey and the only way to tell it doesn't belong to you is checking a sub address table and assuming that it is populated
22:35:19 <jeffro256:monero.social> Let me look into seeing if we can use a shared pubkey optimization for coinbase in Carrot while still maintaining Janus security and without introducing additional fields
```

> **NOTE**: [Later changes](https://github.com/jeffro256/carrot/pull/6) to improve PQ turnstile proving requires also commiting to main address.
> 
> It's not expected to support subaddresses on carrot Coinbase outputs without a custom derivation method.

### CHANGE: Allow relatively large _tx.extra_ for Miner transactions
Hardfork 17 implements `HF_VERSION_REJECT_LARGE_EXTRA`. This rejects any transactions with `tx.extra.size() > MAX_TX_EXTRA_SIZE`.

This limit is defined as:
```cpp
//The limit is enough for the mandatory transaction content with 16 outputs (547 bytes),
//a custom tag (1 byte) and up to 32 bytes of custom data for each recipient.
// (1+32) + (1+1+16*32) + (1+16*32) = 1060
#define MAX_TX_EXTRA_SIZE                       1060
```

This is checked on `prevalidate_miner_transaction`:
```cpp
// from v17, require tx.extra size be within limit
if (hf_version >= HF_VERSION_REJECT_LARGE_EXTRA) {
    CHECK_AND_ASSERT_MES(b.miner_tx.extra.size() <= MAX_TX_EXTRA_SIZE, false, "miner transaction extra too big");
}
```

However, due to Carrot, one ephemeral pub key (D_e) of 32 bytes is required to be added on tx extra for each output.

This leaves about ~32 possible outputs due to limited tx extra size.

P2Pool produces 700-800+ outputs regularly, with current bounds on public P2Pool pools on ~2200 outputs. Additionally `FCMP_PLUS_PLUS_MAX_MINER_OUTPUTS = 10000` allows up to 10000 miner outputs.

A suggestion is to change `MAX_TX_EXTRA_SIZE` to be dynamic, if not for all at least for miner transactions.
```
// allow 256 bytes of custom data (merge mining / nonce / padding / other), then 32 bytes per recipient for additional pub key.
maxMinerTxExtraSize = 256 + (1+1+miner_tx.vout.size() * 32)
// allow 1+32 bytes, then N pubkeys, then N 32 bytes of custom data per output.
maxTxExtraSize = (1+32) + (1+1+tx.vout.size()*32) + (1+tx.vout.size()*32)
```

This would allow a maximum of `256 + (1 + 1 + 10000*32) = 320258` bytes (~312 KiB) of upper limit, dynamically set based on miner outputs.

A regular P2Pool Mini block with ~750 outputs `(1+1+14 /* max extra nonce*/) + (1+1+36 /* reasonable merge mine tag size */) + (1 + 1 + 750*32) = 24056` bytes (~24 KiB) of tx extra data, besides miner outputs themselves.



See relevant logs:
```
21:33:30 <DataHoarder> ouch prevalidate_miner_transaction kills effectively p2pool outputs
21:33:47 <DataHoarder> CHECK_AND_ASSERT_MES(b.miner_tx.extra.size() <= MAX_TX_EXTRA_SIZE, false, "miner transaction extra too big");
21:34:11 <DataHoarder> each p2pool output now requires one tx pub on tx extra (either on tx pub or on additional pubs)
21:34:37 <DataHoarder> that's +32 bytes per output
22:00:44 <DataHoarder> I suggest for miner tx extra max size is set instead to MAX_TX_EXTRA_SIZE + b.miner_tx.vout.size() * 32 to account for the output pubkeys
22:01:04 <DataHoarder> it's later checked for FCMP_PLUS_PLUS_MAX_MINER_OUTPUTS which is 10000
22:28:43 <jeffro256:monero.social> DataHoarder: how many p2pool outputs do you need ? Is p2pool currently limited to 64 bytes ?
22:29:06 <DataHoarder> p2pool outputs as discussed in an MRL meeting can be +2000
22:29:12 <DataHoarder> limit is set to 10000 which is fine
22:29:34 <jeffro256:monero.social> I thought in practice it caps to 64?
22:29:34 <DataHoarder> however, tx extra with carrot requires adding pubkeys for each output
22:29:42 <DataHoarder> no, that's just main due to hashrate
22:29:48 <DataHoarder> mini/nano has 800+ outputs
22:30:17 <DataHoarder> one with 700+ here https://mini.p2pool.observer/share/3440b5630534243d6ce3003ba43c05aa92389132cc1bae494586774bc9716012
22:31:11 <DataHoarder> so yeah besides each coinbase output now taking 16 + 3 + 32 + 1 + varint amount, there's an extra ~32 bytes in tx extra for each
22:31:40 <DataHoarder> it's only in the case of p2pools that have high hashrate where they start reducing PPLNS window size dynamically
22:32:00 <DataHoarder> to about ~2 blocks found per pplns window size
22:32:58 <jeffro256:monero.social> Hmm yeah perhaps we relax the coinbase tx extra cap b4 mainnet
22:33:15 <DataHoarder> next stressnet fork test maybe?
22:33:23 <jeffro256:monero.social> For sure
22:35:08 <ofrnxmr:xmr.mx> I thought coinbase txextra wasnt capped? Or is the cap new
22:35:12 <DataHoarder> new cap
22:35:40 <jeffro256:monero.social> Yes new cap
22:35:49 <DataHoarder> for a mini block, it'd be ~22 KiB of tx extra with 700 outputs
22:36:01 <jeffro256:monero.social> Can be removed easily after this iteration of stressnet
```


> **NOTE**: [PR seraphis-migration/monero#138](https://github.com/seraphis-migration/monero/pull/138) has increased the limit of miner_tx extra size to `MAX_TX_EXTRA_SIZE + b.miner_tx.vout.size() * 32` and leaves `MAX_TX_EXTRA_SIZE at 1060`