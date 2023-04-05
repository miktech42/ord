use {
  super::*,
  crate::wallet::Wallet,
  bitcoin::{
    blockdata::{opcodes, script},
    policy::MAX_STANDARD_TX_WEIGHT,
    schnorr::{TapTweak, TweakedKeyPair, TweakedPublicKey, UntweakedKeyPair},
    secp256k1::{
      self, constants::SCHNORR_SIGNATURE_SIZE, rand, schnorr::Signature, Secp256k1, XOnlyPublicKey,
    },
    util::key::PrivateKey,
    util::sighash::{Prevouts, SighashCache},
    util::taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootBuilder},
    PackedLockTime, SchnorrSighashType, Witness,
  },
  bitcoincore_rpc::bitcoincore_rpc_json::{ImportDescriptors, Timestamp},
  bitcoincore_rpc::Client,
  std::collections::BTreeSet,
};

#[derive(Serialize)]
struct Output {
  satpoint: SatPoint,
  commit: Txid,
  inscriptions: Vec<InscriptionId>,
  reveals: Vec<Txid>,
  fees: u64,
}

#[derive(Debug, Parser)]
pub(crate) struct Inscribe {
  #[clap(long, help = "Inscribe <SATPOINT>")]
  pub(crate) satpoint: Option<SatPoint>,
  #[clap(long, help = "Consider spending unconfirmed outpoint <UTXO>")]
  pub(crate) utxo: Vec<OutPoint>,
  #[clap(long, help = "Use fee rate of <FEE_RATE> sats/vB")]
  pub(crate) fee_rate: FeeRate,
  #[clap(
    long,
    help = "Use <COMMIT_FEE_RATE> sats/vbyte for commit transaction.\nDefaults to <FEE_RATE> if unset."
  )]
  pub(crate) commit_fee_rate: Option<FeeRate>,
  #[clap(help = "Inscribe sat with contents of <FILE>")]
  pub(crate) files: Vec<PathBuf>,
  #[clap(long, help = "Do not back up recovery key.")]
  pub(crate) no_backup: bool,
  #[clap(
    long,
    help = "Do not check that transactions are equal to or below the MAX_STANDARD_TX_WEIGHT of 400,000 weight units. Transactions over this limit are currently nonstandard and will not be relayed by bitcoind in its default configuration. Do not use this flag unless you understand the implications."
  )]
  pub(crate) no_limit: bool,
  #[clap(long, help = "Don't sign or broadcast transactions.")]
  pub(crate) dry_run: bool,
  #[clap(long, help = "Send inscription to <DESTINATION>.")]
  pub(crate) destination: Option<Address>,
  #[clap(long, help = "Send any alignment output to <ALIGNMENT>.")]
  pub(crate) alignment: Option<Address>,
  #[clap(
    long,
    help = "Amount of postage to include in the inscription. Default `10000 sats`"
  )]
  pub(crate) postage: Option<Amount>,
}

impl Inscribe {
  pub(crate) fn run(self, options: Options) -> Result {
    let mut inscription = Vec::new();
    for file in self.files {
      inscription.push(Inscription::from_file(options.chain(), file)?);
    }

    let index = Index::open(&options)?;
    index.update()?;

    let client = options.bitcoin_rpc_client_for_wallet_command(false)?;

    let mut utxos = index.get_unspent_outputs(Wallet::load(&options)?)?;

    for outpoint in &self.utxo {
      utxos.insert(
        *outpoint,
        Amount::from_sat(
          client.get_raw_transaction(&outpoint.txid, None)?.output[outpoint.vout as usize].value,
        ),
      );
    }

    let inscriptions = index.get_inscriptions(None)?;

    let commit_tx_change = [get_change_address(&client)?, get_change_address(&client)?];

    let reveal_tx_destination = self
      .destination
      .map(Ok)
      .unwrap_or_else(|| get_change_address(&client))?;

    let (satpoint, unsigned_commit_tx, reveal_txs, recovery_key_pairs) =
      Inscribe::create_inscription_transactions(
        self.satpoint,
        inscription,
        inscriptions,
        options.chain().network(),
        utxos.clone(),
        commit_tx_change,
        reveal_tx_destination,
        self.alignment,
        self.commit_fee_rate.unwrap_or(self.fee_rate),
        self.fee_rate,
        self.no_limit,
        match self.postage {
          Some(postage) => postage,
          _ => TransactionBuilder::DEFAULT_TARGET_POSTAGE,
        },
      )?;

    for reveal_tx in reveal_txs.clone() {
      utxos.insert(
        reveal_tx.input[0].previous_output,
        Amount::from_sat(
          unsigned_commit_tx.output[reveal_tx.input[0].previous_output.vout as usize].value,
        ),
      );
    }

    let fees = Self::calculate_fee(&unsigned_commit_tx, &utxos)
      + reveal_txs
        .iter()
        .map(|reveal_tx| Self::calculate_fee(&reveal_tx, &utxos))
        .sum::<u64>();

    if self.dry_run {
      print_json(Output {
        satpoint,
        commit: unsigned_commit_tx.txid(),
        reveals: reveal_txs
          .iter()
          .map(|reveal_tx| reveal_tx.txid())
          .collect(),
        inscriptions: reveal_txs
          .iter()
          .map(|reveal_tx| reveal_tx.txid().into())
          .collect(),
        fees,
      })?;
    } else {
      if !self.no_backup {
        for recovery_key_pair in recovery_key_pairs {
          Inscribe::backup_recovery_key(&client, recovery_key_pair, options.chain().network())?;
        }
      }

      let signed_raw_commit_tx = client
        .sign_raw_transaction_with_wallet(&unsigned_commit_tx, None, None)?
        .hex;

      let commit = client
        .send_raw_transaction(&signed_raw_commit_tx)
        .context("Failed to send commit transaction")?;

      let mut reveals = Vec::new();
      for reveal_tx in reveal_txs {
        let reveal = client
          .send_raw_transaction(&reveal_tx)
          .context("Failed to send reveal transaction")?;
        reveals.push(reveal);
      }

      print_json(Output {
        satpoint,
        commit,
        reveals: reveals.iter().map(|reveal| *reveal).collect(),
        inscriptions: reveals.iter().map(|reveal| (*reveal).into()).collect(),
        fees,
      })?;
    };

    Ok(())
  }

  fn calculate_fee(tx: &Transaction, utxos: &BTreeMap<OutPoint, Amount>) -> u64 {
    tprintln!("calculate_fee on a tx");
    tprintln!("  with {} inputs", tx.input.len());
    let mut sum_in = 0;
    for i in &tx.input {
      tprintln!(
        "    value {} {}",
        utxos.get(&i.previous_output).unwrap().to_sat(),
        i.previous_output
      );
      sum_in += utxos.get(&i.previous_output).unwrap().to_sat()
    }
    tprintln!("      total: {}", sum_in);
    tprintln!("  and {} outputs:", tx.output.len());

    let mut sum_out = 0;
    for o in &tx.output {
      tprintln!("    value {}", o.value);
      sum_out += o.value;
    }
    tprintln!("      total: {}", sum_out);
    tprintln!("  fee: {} - {} = {}", sum_in, sum_out, sum_in - sum_out);
    tprintln!("");

    tx.input
      .iter()
      .map(|txin| utxos.get(&txin.previous_output).unwrap().to_sat())
      .sum::<u64>()
      .checked_sub(tx.output.iter().map(|txout| txout.value).sum::<u64>())
      .unwrap()
  }

  fn create_inscription_transactions(
    satpoint: Option<SatPoint>,
    inscription: Vec<Inscription>,
    inscriptions: BTreeMap<SatPoint, InscriptionId>,
    network: Network,
    utxos: BTreeMap<OutPoint, Amount>,
    change: [Address; 2],
    destination: Address,
    alignment: Option<Address>,
    commit_fee_rate: FeeRate,
    reveal_fee_rate: FeeRate,
    no_limit: bool,
    postage: Amount,
  ) -> Result<(SatPoint, Transaction, Vec<Transaction>, Vec<TweakedKeyPair>)> {
    let satpoint = if let Some(satpoint) = satpoint {
      satpoint
    } else {
      let inscribed_utxos = inscriptions
        .keys()
        .map(|satpoint| satpoint.outpoint)
        .collect::<BTreeSet<OutPoint>>();

      utxos
        .keys()
        .find(|outpoint| !inscribed_utxos.contains(outpoint))
        .map(|outpoint| SatPoint {
          outpoint: *outpoint,
          offset: 0,
        })
        .ok_or_else(|| anyhow!("wallet contains no cardinal utxos"))?
    };

    for (inscribed_satpoint, inscription_id) in &inscriptions {
      if inscribed_satpoint == &satpoint {
        return Err(anyhow!("sat at {} already inscribed", satpoint));
      }

      if inscribed_satpoint.outpoint == satpoint.outpoint {
        return Err(anyhow!(
          "utxo {} already inscribed with inscription {inscription_id} on sat {inscribed_satpoint}",
          satpoint.outpoint,
        ));
      }
    }

    let mut commit_tx_addresses = Vec::new();
    let mut reveal_fees = Vec::new();
    let mut control_blocks = Vec::new();
    let mut reveal_scripts = Vec::new();
    let mut key_pairs = Vec::new();
    let mut taproot_spend_infos = Vec::new();

    for inscription in inscription {
      let secp256k1 = Secp256k1::new();
      let key_pair = UntweakedKeyPair::new(&secp256k1, &mut rand::thread_rng());
      let (public_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);
      key_pairs.push(key_pair);

      let reveal_script = inscription.append_reveal_script(
        script::Builder::new()
          .push_slice(&public_key.serialize())
          .push_opcode(opcodes::all::OP_CHECKSIG),
      );

      let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, reveal_script.clone())
        .expect("adding leaf should work")
        .finalize(&secp256k1, public_key)
        .expect("finalizing taproot builder should work");

      let control_block = taproot_spend_info
        .control_block(&(reveal_script.clone(), LeafVersion::TapScript))
        .expect("should compute control block");

      commit_tx_addresses.push(Address::p2tr_tweaked(
        taproot_spend_info.output_key(),
        network,
      ));
      taproot_spend_infos.push(taproot_spend_info);

      let (_, reveal_fee) = Self::build_reveal_transaction(
        &control_block,
        reveal_fee_rate,
        OutPoint::null(),
        TxOut {
          script_pubkey: destination.script_pubkey(),
          value: 0,
        },
        &reveal_script,
      );
      reveal_scripts.push(reveal_script);
      control_blocks.push(control_block);
      reveal_fees.push(reveal_fee + postage);
    }

    let unsigned_commit_tx = TransactionBuilder::build_transaction_with_values(
      satpoint,
      inscriptions,
      utxos,
      commit_tx_addresses.clone(),
      alignment,
      change,
      commit_fee_rate,
      reveal_fees,
    )?;

    let mut reveal_txs = Vec::new();
    let mut recovery_key_pairs = Vec::new();

    for ((((control_block, reveal_script), key_pair), taproot_spend_info), commit_tx_address) in
      control_blocks
        .iter()
        .zip(reveal_scripts)
        .zip(key_pairs)
        .zip(taproot_spend_infos)
        .zip(commit_tx_addresses)
    {
      let (vout, output) = unsigned_commit_tx
        .output
        .iter()
        .enumerate()
        .find(|(_vout, output)| output.script_pubkey == commit_tx_address.script_pubkey())
        .expect("should find sat commit/inscription output");

      let (mut reveal_tx, fee) = Self::build_reveal_transaction(
        &control_block,
        reveal_fee_rate,
        OutPoint {
          txid: unsigned_commit_tx.txid(),
          vout: vout.try_into().unwrap(),
        },
        TxOut {
          script_pubkey: destination.script_pubkey(),
          value: output.value,
        },
        &reveal_script,
      );

      reveal_tx.output[0].value = reveal_tx.output[0]
        .value
        .checked_sub(fee.to_sat())
        .context("commit transaction output value insufficient to pay transaction fee")?;

      if reveal_tx.output[0].value < reveal_tx.output[0].script_pubkey.dust_value().to_sat() {
        bail!("commit transaction output would be dust");
      }

      let mut sighash_cache = SighashCache::new(&mut reveal_tx);

      let signature_hash = sighash_cache
        .taproot_script_spend_signature_hash(
          0,
          &Prevouts::All(&[output]),
          TapLeafHash::from_script(&reveal_script, LeafVersion::TapScript),
          SchnorrSighashType::Default,
        )
        .expect("signature hash should compute");

      let secp256k1 = Secp256k1::new();
      let signature = secp256k1.sign_schnorr(
        &secp256k1::Message::from_slice(signature_hash.as_inner())
          .expect("should be cryptographically secure hash"),
        &key_pair,
      );

      let witness = sighash_cache
        .witness_mut(0)
        .expect("getting mutable witness reference should work");
      witness.push(signature.as_ref());
      witness.push(reveal_script);
      witness.push(&control_block.serialize());

      let recovery_key_pair = key_pair.tap_tweak(&secp256k1, taproot_spend_info.merkle_root());
      recovery_key_pairs.push(recovery_key_pair);

      let (x_only_pub_key, _parity) = recovery_key_pair.to_inner().x_only_public_key();
      assert_eq!(
        Address::p2tr_tweaked(
          TweakedPublicKey::dangerous_assume_tweaked(x_only_pub_key),
          network,
        ),
        commit_tx_address
      );

      let reveal_weight = reveal_tx.weight();
      reveal_txs.push(reveal_tx);

      if !no_limit && reveal_weight > MAX_STANDARD_TX_WEIGHT.try_into().unwrap() {
        bail!(
          "reveal transaction weight greater than {MAX_STANDARD_TX_WEIGHT} (MAX_STANDARD_TX_WEIGHT): {reveal_weight}"
        );
      }
    }

    Ok((satpoint, unsigned_commit_tx, reveal_txs, recovery_key_pairs))
  }

  fn backup_recovery_key(
    client: &Client,
    recovery_key_pair: TweakedKeyPair,
    network: Network,
  ) -> Result {
    let recovery_private_key = PrivateKey::new(recovery_key_pair.to_inner().secret_key(), network);

    let info = client.get_descriptor_info(&format!("rawtr({})", recovery_private_key.to_wif()))?;

    let response = client.import_descriptors(ImportDescriptors {
      descriptor: format!("rawtr({})#{}", recovery_private_key.to_wif(), info.checksum),
      timestamp: Timestamp::Now,
      active: Some(false),
      range: None,
      next_index: None,
      internal: Some(false),
      label: Some("commit tx recovery key".to_string()),
    })?;

    for result in response {
      if !result.success {
        return Err(anyhow!("commit tx recovery key import failed"));
      }
    }

    Ok(())
  }

  fn build_reveal_transaction(
    control_block: &ControlBlock,
    fee_rate: FeeRate,
    input: OutPoint,
    output: TxOut,
    script: &Script,
  ) -> (Transaction, Amount) {
    let reveal_tx = Transaction {
      input: vec![TxIn {
        previous_output: input,
        script_sig: script::Builder::new().into_script(),
        witness: Witness::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
      }],
      output: vec![output],
      lock_time: PackedLockTime::ZERO,
      version: 1,
    };

    let fee = {
      let mut reveal_tx = reveal_tx.clone();

      reveal_tx.input[0].witness.push(
        Signature::from_slice(&[0; SCHNORR_SIGNATURE_SIZE])
          .unwrap()
          .as_ref(),
      );
      reveal_tx.input[0].witness.push(script);
      reveal_tx.input[0].witness.push(&control_block.serialize());

      fee_rate.fee(reveal_tx.weight() as f64 / 4.0)
    };

    (reveal_tx, fee)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn reveal_transaction_pays_fee() {
    let utxos = vec![(outpoint(1), Amount::from_sat(20000))];
    let inscription = inscription("text/plain", "ord");
    let commit_address = change(0);
    let reveal_address = recipient();

    let (_satpoint, commit_tx, reveal_tx, _private_key) =
      Inscribe::create_inscription_transactions(
        Some(satpoint(1, 0)),
        vec![inscription],
        BTreeMap::new(),
        Network::Bitcoin,
        utxos.into_iter().collect(),
        [commit_address, change(1)],
        reveal_address,
        None,
        FeeRate::try_from(1.0).unwrap(),
        FeeRate::try_from(1.0).unwrap(),
        false,
        TransactionBuilder::DEFAULT_TARGET_POSTAGE,
      )
      .unwrap();

    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_sign_loss)]
    let fee = Amount::from_sat((reveal_tx[0].weight() as f64 / 4.0).ceil() as u64);

    assert_eq!(
      reveal_tx[0].output[0].value,
      20000 - fee.to_sat() - (20000 - commit_tx.output[0].value),
    );
  }

  #[test]
  fn inscript_tansactions_opt_in_to_rbf() {
    let utxos = vec![(outpoint(1), Amount::from_sat(20000))];
    let inscription = inscription("text/plain", "ord");
    let commit_address = change(0);
    let reveal_address = recipient();

    let (_satpoint, commit_tx, reveal_tx, _) = Inscribe::create_inscription_transactions(
      Some(satpoint(1, 0)),
      vec![inscription],
      BTreeMap::new(),
      Network::Bitcoin,
      utxos.into_iter().collect(),
      [commit_address, change(1)],
      reveal_address,
      None,
      FeeRate::try_from(1.0).unwrap(),
      FeeRate::try_from(1.0).unwrap(),
      false,
      TransactionBuilder::DEFAULT_TARGET_POSTAGE,
    )
    .unwrap();

    assert!(commit_tx.is_explicitly_rbf());
    assert!(reveal_tx[0].is_explicitly_rbf());
  }

  #[test]
  fn inscribe_with_no_satpoint_and_no_cardinal_utxos() {
    let utxos = vec![(outpoint(1), Amount::from_sat(1000))];
    let mut inscriptions = BTreeMap::new();
    inscriptions.insert(
      SatPoint {
        outpoint: outpoint(1),
        offset: 0,
      },
      inscription_id(1),
    );

    let inscription = inscription("text/plain", "ord");
    let satpoint = None;
    let commit_address = change(0);
    let reveal_address = recipient();

    let error = Inscribe::create_inscription_transactions(
      satpoint,
      vec![inscription],
      inscriptions,
      Network::Bitcoin,
      utxos.into_iter().collect(),
      [commit_address, change(1)],
      reveal_address,
      None,
      FeeRate::try_from(1.0).unwrap(),
      FeeRate::try_from(1.0).unwrap(),
      false,
      TransactionBuilder::DEFAULT_TARGET_POSTAGE,
    )
    .unwrap_err()
    .to_string();

    assert!(
      error.contains("wallet contains no cardinal utxos"),
      "{}",
      error
    );
  }

  #[test]
  fn inscribe_with_no_satpoint_and_enough_cardinal_utxos() {
    let utxos = vec![
      (outpoint(1), Amount::from_sat(20_000)),
      (outpoint(2), Amount::from_sat(20_000)),
    ];
    let mut inscriptions = BTreeMap::new();
    inscriptions.insert(
      SatPoint {
        outpoint: outpoint(1),
        offset: 0,
      },
      inscription_id(1),
    );

    let inscription = inscription("text/plain", "ord");
    let satpoint = None;
    let commit_address = change(0);
    let reveal_address = recipient();

    assert!(Inscribe::create_inscription_transactions(
      satpoint,
      vec![inscription],
      inscriptions,
      Network::Bitcoin,
      utxos.into_iter().collect(),
      [commit_address, change(1)],
      reveal_address,
      None,
      FeeRate::try_from(1.0).unwrap(),
      FeeRate::try_from(1.0).unwrap(),
      false,
      TransactionBuilder::DEFAULT_TARGET_POSTAGE,
    )
    .is_ok())
  }

  #[test]
  fn inscribe_with_custom_fee_rate() {
    let utxos = vec![
      (outpoint(1), Amount::from_sat(10_000)),
      (outpoint(2), Amount::from_sat(20_000)),
    ];
    let mut inscriptions = BTreeMap::new();
    inscriptions.insert(
      SatPoint {
        outpoint: outpoint(1),
        offset: 0,
      },
      inscription_id(1),
    );

    let inscription = inscription("text/plain", "ord");
    let satpoint = None;
    let commit_address = change(0);
    let reveal_address = recipient();
    let fee_rate = 3.3;

    let (_satpoint, commit_tx, reveal_tx, _private_key) =
      Inscribe::create_inscription_transactions(
        satpoint,
        vec![inscription],
        inscriptions,
        bitcoin::Network::Signet,
        utxos.into_iter().collect(),
        [commit_address, change(1)],
        reveal_address,
        None,
        FeeRate::try_from(fee_rate).unwrap(),
        FeeRate::try_from(fee_rate).unwrap(),
        false,
        TransactionBuilder::DEFAULT_TARGET_POSTAGE,
      )
      .unwrap();

    let sig_vbytes = 17.0;
    let fee = FeeRate::try_from(fee_rate)
      .unwrap()
      .fee(commit_tx.weight() as f64 / 4.0 + sig_vbytes)
      .to_sat();

    let reveal_value = commit_tx
      .output
      .iter()
      .map(|o| o.value)
      .reduce(|acc, i| acc + i)
      .unwrap();

    assert_eq!(reveal_value, 20_000 - fee);

    let fee = FeeRate::try_from(fee_rate)
      .unwrap()
      .fee(reveal_tx[0].weight() as f64 / 4.0)
      .to_sat();

    assert_eq!(
      reveal_tx[0].output[0].value,
      20_000 - fee - (20_000 - commit_tx.output[0].value),
    );
  }

  #[test]
  fn inscribe_with_commit_fee_rate() {
    let utxos = vec![
      (outpoint(1), Amount::from_sat(10_000)),
      (outpoint(2), Amount::from_sat(20_000)),
    ];
    let mut inscriptions = BTreeMap::new();
    inscriptions.insert(
      SatPoint {
        outpoint: outpoint(1),
        offset: 0,
      },
      inscription_id(1),
    );

    let inscription = inscription("text/plain", "ord");
    let satpoint = None;
    let commit_address = change(0);
    let reveal_address = recipient();
    let commit_fee_rate = 3.3;
    let fee_rate = 1.0;

    let (_satpoint, commit_tx, reveal_tx, _private_key) =
      Inscribe::create_inscription_transactions(
        satpoint,
        vec![inscription],
        inscriptions,
        bitcoin::Network::Signet,
        utxos.into_iter().collect(),
        [commit_address, change(1)],
        reveal_address,
        None,
        FeeRate::try_from(commit_fee_rate).unwrap(),
        FeeRate::try_from(fee_rate).unwrap(),
        false,
        TransactionBuilder::DEFAULT_TARGET_POSTAGE,
      )
      .unwrap();

    let sig_vbytes = 17.0;
    let fee = FeeRate::try_from(commit_fee_rate)
      .unwrap()
      .fee(commit_tx.weight() as f64 / 4.0 + sig_vbytes)
      .to_sat();

    let reveal_value = commit_tx
      .output
      .iter()
      .map(|o| o.value)
      .reduce(|acc, i| acc + i)
      .unwrap();

    assert_eq!(reveal_value, 20_000 - fee);

    let fee = FeeRate::try_from(fee_rate)
      .unwrap()
      .fee(reveal_tx[0].weight() as f64 / 4.0)
      .to_sat();

    assert_eq!(
      reveal_tx[0].output[0].value,
      20_000 - fee - (20_000 - commit_tx.output[0].value),
    );
  }

  #[test]
  fn inscribe_over_max_standard_tx_weight() {
    let utxos = vec![(outpoint(1), Amount::from_sat(50 * COIN_VALUE))];

    let inscription = inscription("text/plain", [0; MAX_STANDARD_TX_WEIGHT as usize]);
    let satpoint = None;
    let commit_address = change(0);
    let reveal_address = recipient();

    let error = Inscribe::create_inscription_transactions(
      satpoint,
      vec![inscription],
      BTreeMap::new(),
      Network::Bitcoin,
      utxos.into_iter().collect(),
      [commit_address, change(1)],
      reveal_address,
      None,
      FeeRate::try_from(1.0).unwrap(),
      FeeRate::try_from(1.0).unwrap(),
      false,
      TransactionBuilder::DEFAULT_TARGET_POSTAGE,
    )
    .unwrap_err()
    .to_string();

    assert!(
      error.contains(&format!("reveal transaction weight greater than {MAX_STANDARD_TX_WEIGHT} (MAX_STANDARD_TX_WEIGHT): 402799")),
      "{}",
      error
    );
  }

  #[test]
  fn inscribe_with_no_max_standard_tx_weight() {
    let utxos = vec![(outpoint(1), Amount::from_sat(50 * COIN_VALUE))];

    let inscription = inscription("text/plain", [0; MAX_STANDARD_TX_WEIGHT as usize]);
    let satpoint = None;
    let commit_address = change(0);
    let reveal_address = recipient();

    let (_satpoint, _commit_tx, reveal_tx, _private_key) =
      Inscribe::create_inscription_transactions(
        satpoint,
        vec![inscription],
        BTreeMap::new(),
        Network::Bitcoin,
        utxos.into_iter().collect(),
        [commit_address, change(1)],
        reveal_address,
        None,
        FeeRate::try_from(1.0).unwrap(),
        FeeRate::try_from(1.0).unwrap(),
        true,
        TransactionBuilder::DEFAULT_TARGET_POSTAGE,
      )
      .unwrap();

    assert!(reveal_tx[0].size() >= MAX_STANDARD_TX_WEIGHT as usize);
  }
}
