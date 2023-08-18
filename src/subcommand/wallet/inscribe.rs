use {
  super::*,
  crate::wallet::Wallet,
  bitcoin::{
    blockdata::{opcodes, script},
    key::PrivateKey,
    key::{TapTweak, TweakedKeyPair, TweakedPublicKey, UntweakedKeyPair},
    locktime::absolute::LockTime,
    policy::MAX_STANDARD_TX_WEIGHT,
    secp256k1::{
      self, constants::SCHNORR_SIGNATURE_SIZE, rand, schnorr::Signature, Secp256k1, XOnlyPublicKey,
    },
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootBuilder},
    ScriptBuf, Witness,
  },
  bitcoincore_rpc::bitcoincore_rpc_json::{ImportDescriptors, SignRawTransactionInput, Timestamp},
  bitcoincore_rpc::Client,
  bitcoincore_rpc::RawTx,
  std::collections::BTreeSet,
  std::fs::File,
  std::io::Write,
  std::io::{BufRead, BufReader},
  // std::{thread, time},
};

#[derive(Deserialize)]
pub struct DecodeRawTransactionOutput {
  pub weight: bitcoin::Weight,
}

#[derive(Serialize)]
struct OutputDump {
  satpoint: SatPoint,
  inscriptions: Vec<InscriptionId>,
  filenames: Vec<PathBuf>,
  commit: String,
  commit_weight: bitcoin::Weight,
  reveals: Vec<String>,
  reveal_weights: Vec<bitcoin::Weight>,
  recovery_descriptors: Vec<String>,
  fees: u64,
}

#[derive(Serialize)]
struct Output {
  satpoint: SatPoint,
  inscriptions: Vec<InscriptionId>,
  commit: Txid,
  reveals: Vec<Txid>,
  fees: u64,
}

#[derive(Debug, Parser)]
pub(crate) struct Inscribe {
  #[clap(long, help = "Inscribe <SATPOINT>")]
  pub(crate) satpoint: Option<SatPoint>,
  #[clap(
    long,
    help = "Consider spending outpoint <UTXO>, even if it is unconfirmed or contains inscriptions"
  )]
  pub(crate) utxo: Vec<OutPoint>,
  #[clap(long, help = "Curse inscriptions by inscribing on the 2nd input")]
  pub(crate) cursed: bool,
  #[clap(long, help = "Only spend outpoints given with --utxo")]
  pub(crate) coin_control: bool,
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
  #[clap(long, help = "Do not broadcast any transactions.")]
  pub(crate) no_broadcast: bool,
  /*
    #[clap(
      long,
      help = "Wait for the commit tx to confirm before sending reveal txs."
    )]
    pub(crate) wait_after_commit: bool,
  */
  #[clap(
    long,
    help = "Do not check that transactions are equal to or below the MAX_STANDARD_TX_WEIGHT of 400,000 weight units. Transactions over this limit are currently nonstandard and will not be relayed by bitcoind in its default configuration. Do not use this flag unless you understand the implications."
  )]
  pub(crate) no_limit: bool,
  #[clap(long, help = "Don't sign or broadcast transactions.")]
  pub(crate) dry_run: bool,
  #[clap(
    long,
    help = "Dump raw hex transactions and recovery keys to standard output."
  )]
  pub(crate) dump: bool,
  #[clap(long, help = "Send inscription to <DESTINATION>.")]
  pub(crate) destination: Vec<Address<NetworkUnchecked>>,
  #[clap(long, help = "Send any alignment output to <ALIGNMENT>.")]
  pub(crate) alignment: Option<Address<NetworkUnchecked>>,
  #[clap(long, help = "Send any change output to <CHANGE>.")]
  pub(crate) change: Option<Address<NetworkUnchecked>>,
  #[clap(long, help = "Send the first output of any cursed reveal tx to <CURSED_DESTINATION>.")]
  pub(crate) cursed_destination: Option<Address<NetworkUnchecked>>,
  #[clap(long, help = "Use <CURSED_UTXO> as the first input of any cursed reveal tx.")]
  pub(crate) cursed_utxo: Option<OutPoint>,
  #[clap(
    long,
    help = "Amount of postage to include in the inscription. Default `10000 sats`"
  )]
  pub(crate) postage: Option<Amount>,
  #[clap(
    long,
    help = "Use at most <MAX_INPUTS> inputs to build the commit transaction."
  )]
  pub(crate) max_inputs: Option<usize>,
  #[clap(
    long,
    help = "Location of a CSV file to use for a combination of DESTINATION and FILE NAMES.  Should be structured `destination,file`."
  )]
  pub(crate) csv: Option<PathBuf>,
  #[clap(
    long,
    help = "Create a 'cursed' inscription (with an unknown even OP_66 tag)"
  )]
  pub(crate) cursed66: bool,
  #[clap(long, help = "Allow inscription on sats that are already inscribed.")]
  pub(crate) allow_reinscribe: bool,
  #[clap(long, help = "Allow inscription on utxos that are already inscribed.")]
  pub(crate) ignore_utxo_inscriptions: bool,
  #[clap(long, help = "Use the same recovery key for all inscriptions.")]
  pub(crate) single_key: bool,
}

impl Inscribe {
  pub(crate) fn run(self, options: Options) -> Result {
    let mut inscription = Vec::new();
    let mut filenames = Vec::new();
    let mut destinations = Vec::new();

    let mut client = options.bitcoin_rpc_client_for_wallet_command(false)?;

    if let Some(csv) = self.csv {
      if !self.files.is_empty() {
        return Err(anyhow!("Cannot use both --csv and provide files"));
      } else if !self.destination.is_empty() {
        return Err(anyhow!("Cannot use both --csv and --destination"));
      }

      let file = File::open(&csv)?;
      let reader = BufReader::new(file);
      let mut line_number = 1;
      for line in reader.lines() {
        let line = line?;
        let mut split = line.trim_start_matches('\u{feff}').split(',');
        let destination = split.next().ok_or_else(|| {
          anyhow!(
            "Destination CSV file '{}' is not formatted correctly",
            csv.display()
          )
        })?;
        let file = split.next().ok_or_else(|| {
          anyhow!(
            "Destination CSV file '{}' is not formatted correctly - no comma on line {line_number}",
            csv.display()
          )
        })?;

        let file = PathBuf::from(file);
        filenames.push(file.clone());

        let i = Inscription::from_file(options.chain(), &file);
        if i.is_ok() {
          inscription.push(i?);
        } else {
          i.context(format!(
            "Error with file '{}' in CSV file {} line {line_number}",
            file.display(),
            csv.display()
          ))?;
        }

        let address = Address::from_str(destination)?;
        destinations.push(address.require_network(options.chain().network())?);
        line_number += 1;
      }
    } else {
      for file in self.files.iter() {
        tprintln!("[open files]");
        inscription.push(Inscription::from_file(options.chain(), file)?);
        filenames.push(PathBuf::from(file));
      }
      if self.destination.is_empty() {
        tprintln!("[get destination addresses]");
        for (i, _) in self.files.iter().enumerate() {
          destinations.push(get_change_address(&client, &options)?);
          if (i + 1) % 100 == 0 {
            tprintln!("  [{}]", i + 1);
          }
        }
      } else {
        for destination in self.destination {
          destinations.push(destination.require_network(options.chain().network())?);
        }
      }
    }

    if inscription.is_empty() {
      return Err(anyhow!("Provide at least one file to inscribe"));
    }

    if self.cursed && inscription.len() != 1 {
      return Err(anyhow!(
        "Currently --cursed only works on one inscription at a time"
      ));
    }

    tprintln!("[update index]");
    let index = Index::open(&options)?;
    index.update()?;

    tprintln!("[get utxos]");
    let mut utxos = if self.coin_control {
      BTreeMap::new()
    } else {
      index.get_unspent_outputs(Wallet::load(&options)?)?
    };

    tprintln!("[insert utxos]");
    for outpoint in &self.utxo {
      utxos.insert(
        *outpoint,
        Amount::from_sat(
          client.get_raw_transaction(&outpoint.txid, None)?.output[outpoint.vout as usize].value,
        ),
      );
    }

    tprintln!("[get inscriptions]");
    let inscriptions = index.get_inscriptions(utxos.clone())?;

    tprintln!("[get change]");
    let commit_tx_change = [
      get_change_address(&client, &options)?,
      match self.change {
        Some(change) => change.require_network(options.chain().network()).unwrap(),
        None => get_change_address(&client, &options)?,
      },
    ];

    let alignment = self.alignment.map(|alignment| {
      alignment
        .require_network(options.chain().network())
        .unwrap()
    });

    let cursed_destination = self.cursed_destination.map(|cursed_destination| {
      cursed_destination
        .require_network(options.chain().network())
        .unwrap()
    });

    let (cursed_outpoint, cursed_txout, reveal_vin_from_commit) = if self.cursed {
      let inscribed_utxos = inscriptions
        .keys()
        .map(|satpoint| satpoint.outpoint)
        .collect::<BTreeSet<OutPoint>>();

      let mut smallest_value = 0;
      let mut cursed_outpoint = None;
      if let Some(cursed_utxo) = self.cursed_utxo {
        cursed_outpoint = Some(cursed_utxo);
      } else {
        for outpoint in utxos.keys().filter(|outpoint| {
          !inscribed_utxos.contains(outpoint)
            && (self.satpoint.is_none() || **outpoint != self.satpoint.unwrap().outpoint)
            && utxos[outpoint].to_sat() >= 546
        }) {
          if smallest_value == 0 || utxos[outpoint].to_sat() < smallest_value {
            smallest_value = utxos[outpoint].to_sat();
            cursed_outpoint = Some(*outpoint);
          }
        }

        if smallest_value == 0 {
          return Err(anyhow!("wallet contains no cardinal utxos"));
        }
      }

      let cursed_txout = index
        .get_transaction(cursed_outpoint.unwrap().txid)?
        .expect("not found")
        .output
        .into_iter()
        .nth(cursed_outpoint.unwrap().vout.try_into().unwrap())
        .expect("current transaction output");

      (cursed_outpoint, Some(cursed_txout), 1)
    } else {
      (None, None, 0)
    };

    tprintln!("[create_inscription_transactions]");
    let (satpoint, unsigned_commit_tx, reveal_txs, mut recovery_key_pairs) =
      Inscribe::create_inscription_transactions(
        self.satpoint,
        inscription,
        inscriptions,
        options.chain().network(),
        utxos.clone(),
        commit_tx_change,
        destinations,
        alignment,
        cursed_destination,
        cursed_outpoint,
        cursed_txout,
        self.commit_fee_rate.unwrap_or(self.fee_rate),
        self.fee_rate,
        self.max_inputs,
        self.no_limit,
        match self.postage {
          Some(postage) => postage,
          _ => TransactionBuilder::DEFAULT_TARGET_POSTAGE,
        },
        self.cursed66,
        self.allow_reinscribe,
        self.ignore_utxo_inscriptions,
        self.single_key,
      )?;

    tprintln!("[sign commit]");
    let signed_raw_commit_tx =
      client.sign_raw_transaction_with_wallet(&unsigned_commit_tx, None, None)?;

    if !signed_raw_commit_tx.complete {
      return Err(anyhow!(
        "error signing commit tx: {:?}",
        signed_raw_commit_tx.errors
      ));
    }

    let signed_raw_commit_tx = signed_raw_commit_tx.hex;

    #[cfg(test)]
    let commit_weight = Weight::from_wu(0);

    #[cfg(not(test))]
    let commit_weight = client
      .call::<DecodeRawTransactionOutput>(
        "decoderawtransaction",
        &[signed_raw_commit_tx.raw_hex().into()],
      )?
      .weight;

    if !self.no_limit && commit_weight > bitcoin::Weight::from_wu(MAX_STANDARD_TX_WEIGHT.into()) {
      bail!(
        "commit transaction weight greater than {MAX_STANDARD_TX_WEIGHT} (MAX_STANDARD_TX_WEIGHT): {commit_weight}"
      );
    }

    tprintln!("[insert values]");
    for reveal_tx in reveal_txs.clone() {
      utxos.insert(
        reveal_tx.input[reveal_vin_from_commit].previous_output,
        Amount::from_sat(
          unsigned_commit_tx.output
            [reveal_tx.input[reveal_vin_from_commit].previous_output.vout as usize]
            .value,
        ),
      );
    }

    let fees = Self::calculate_fee(&unsigned_commit_tx, &utxos)
      + reveal_txs
        .iter()
        .map(|reveal_tx| Self::calculate_fee(reveal_tx, &utxos))
        .sum::<u64>();

    if self.dry_run {
      print_json(Output {
        satpoint,
        inscriptions: reveal_txs
          .iter()
          .map(|reveal_tx| reveal_tx.txid().into())
          .collect(),
        commit: unsigned_commit_tx.txid(),
        reveals: reveal_txs
          .iter()
          .map(|reveal_tx| reveal_tx.txid())
          .collect(),
        fees,
      })?;
    } else {
      if self.single_key {
        recovery_key_pairs = [recovery_key_pairs[0]].to_vec();
      }

      tprintln!("[sign reveals]");
      let mut signed_reveal_txs = Vec::new();
      for reveal_tx in reveal_txs.iter() {
        let commit_output = reveal_tx.input[reveal_vin_from_commit].previous_output;
        let vout = commit_output.vout;
        let signed_reveal_tx = client.sign_raw_transaction_with_wallet(
          reveal_tx,
          Some(&[SignRawTransactionInput {
            txid: unsigned_commit_tx.txid(),
            vout,
            script_pub_key: unsigned_commit_tx.output[vout as usize]
              .script_pubkey
              .clone(),
            amount: Some(Amount::from_sat(
              unsigned_commit_tx.output[vout as usize].value,
            )),
            redeem_script: None,
          }]),
          None,
        )?;

        if !signed_reveal_tx.complete {
          return Err(anyhow!(
            "error signing reveal tx: {:?}",
            signed_reveal_tx.errors
          ));
        }

        let reveal_weight = client
          .call::<DecodeRawTransactionOutput>(
            "decoderawtransaction",
            &[signed_reveal_tx.hex.raw_hex().into()],
          )?
          .weight;

        if !self.no_limit && reveal_weight > bitcoin::Weight::from_wu(MAX_STANDARD_TX_WEIGHT.into())
        {
          bail!(
            "reveal transaction weight greater than {MAX_STANDARD_TX_WEIGHT} (MAX_STANDARD_TX_WEIGHT): {reveal_weight}"
          );
        }

        signed_reveal_txs.push((reveal_tx, signed_reveal_tx.hex));
      }

      if self.dump {
        tprintln!("[dump txs]");
        let commit = signed_raw_commit_tx.raw_hex();

        let mut reveals = Vec::new();
        let mut reveal_weights = Vec::new();
        let mut inscriptions = Vec::new();
        for (reveal_tx, signed_reveal_tx) in signed_reveal_txs.iter() {
          let reveal_weight = client
            .call::<DecodeRawTransactionOutput>(
              "decoderawtransaction",
              &[signed_reveal_tx.raw_hex().into()],
            )?
            .weight;

          reveal_weights.push(reveal_weight);
          reveals.push(signed_reveal_tx.raw_hex());
          inscriptions.push(reveal_tx.txid().into());
        }

        tprintln!("[recovery pairs]");
        let recovery_descriptors = recovery_key_pairs
          .iter()
          .map(|recovery_key_pair| {
            Inscribe::get_recovery_key(&client, *recovery_key_pair, options.chain().network())
              .unwrap()
          })
          .collect();

        print_json(OutputDump {
          satpoint,
          inscriptions,
          filenames,
          commit,
          commit_weight,
          reveals,
          reveal_weights,
          recovery_descriptors,
          fees,
        })?;
      }

      if !self.no_backup {
        tprintln!("[backup recovery keys]");
        for recovery_key_pair in recovery_key_pairs {
          Inscribe::backup_recovery_key(&client, recovery_key_pair, options.chain().network())?;
        }
      }

      if !self.no_broadcast {
        tprintln!("[broadcast txs]");

        // make sure before sending the commit tx that we can write to a file in the event that any of the reveals fail
        let failed_reveals_filename = format!(
          "failed-reveals-for-commit-{}.txt",
          unsigned_commit_tx.txid()
        );
        let file = fs::OpenOptions::new()
          .create(true)
          .write(true)
          .open(&failed_reveals_filename);

        if file.is_err() {
          return Err(anyhow!("cannot write to the current directory"));
        }

        let commit = client
          .send_raw_transaction(&signed_raw_commit_tx)
          .context("Failed to send commit transaction")?;
        /*
                if self.wait_after_commit {
                  let mut failed = false;
                  drop(index);
                  eprint!("[waiting for commit transaction {} to confirm] ", commit);
                  io::stdout().flush()?;
                  drop(client);
                  loop {
                    thread::sleep(time::Duration::from_secs(60));
                    match options.bitcoin_rpc_client_for_wallet_command(false) {
                      Ok(client) => {
                        if failed {
                          eprintln!("[reconnected]");
                          failed = false;
                        }

                        match client.get_transaction(&commit, Some(false)) {
                          Ok(tx) => {
                            if tx.info.confirmations > 0 {
                              eprintln!();
                              eprintln!("[confirmed]");
                              break;
                            }
                            eprint!(".");
                          }
                          Err(error) => {
                            eprintln!();
                            eprintln!("[error: {:?}]", error);
                            eprintln!("[trying to reconnect to bitcoin client]");
                            failed = true;
                          }
                        }
                      }
                      Err(error) => {
                        eprintln!();
                        eprintln!("[failed to connect to bitcoin client: {:?}]", error);
                        failed = true;
                        thread::sleep(time::Duration::from_secs(60));
                      }
                    }
                  }
                }
        */

        let mut file = file?;
        client = options.bitcoin_rpc_client_for_wallet_command(false)?;
        let mut reveals = Vec::new();
        let mut failed_reveals = Vec::new();
        for (_i, (reveal_tx, signed_reveal_tx)) in signed_reveal_txs.iter().enumerate() {
          match client.send_raw_transaction(signed_reveal_tx) {
            Ok(reveal) => {
              reveals.push(reveal);
            }
            Err(_error) => {
              failed_reveals.push(reveal_tx.raw_hex());
            }
          };
        }

        print_json(Output {
          satpoint,
          inscriptions: reveals.iter().map(|reveal| (*reveal).into()).collect(),
          commit,
          reveals,
          fees,
        })?;

        if failed_reveals.is_empty() {
          drop(file);
          fs::remove_file(failed_reveals_filename)?;
        } else {
          for tx in &failed_reveals {
            writeln!(file, "{tx}")?;
          }

          println!(
            "\n{} reveal{} failed - see {failed_reveals_filename}",
            failed_reveals.len(),
            if failed_reveals.len() == 1 { "" } else { "s" }
          );
        }
      }
    }

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
    destinations: Vec<Address>,
    alignment: Option<Address>,
    cursed_destination: Option<Address>,
    cursed_outpoint: Option<OutPoint>,
    cursed_txout: Option<TxOut>,
    commit_fee_rate: FeeRate,
    reveal_fee_rate: FeeRate,
    max_inputs: Option<usize>,
    no_limit: bool,
    postage: Amount,
    cursed66: bool,
    allow_reinscribe: bool,
    ignore_utxo_inscriptions: bool,
    single_key: bool,
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
        .find(|outpoint| {
          !inscribed_utxos.contains(outpoint)
            && (cursed_outpoint.is_none() || **outpoint != cursed_outpoint.unwrap())
        })
        .map(|outpoint| SatPoint {
          outpoint: *outpoint,
          offset: 0,
        })
        .ok_or_else(|| anyhow!("wallet contains no cardinal utxos"))?
    };

    for (inscribed_satpoint, inscription_id) in &inscriptions {
      if inscribed_satpoint == &satpoint {
        if !allow_reinscribe {
          return Err(anyhow!("sat at {} already inscribed", satpoint));
        }
      } else if inscribed_satpoint.outpoint == satpoint.outpoint {
        if !ignore_utxo_inscriptions {
          return Err(anyhow!(
            "utxo {} already inscribed with inscription {inscription_id} on sat {inscribed_satpoint}",
            satpoint.outpoint,
            ));
        }
      }
    }

    let reveal_vout_postage = if cursed_outpoint.is_some() { 1 } else { 0 };

    let mut commit_tx_addresses = Vec::new();
    let mut reveal_fees = Vec::new();
    let mut control_blocks = Vec::new();
    let mut reveal_scripts = Vec::new();
    let mut key_pairs = Vec::new();
    let mut taproot_spend_infos = Vec::new();

    tprintln!("[make reveals]");

    let secp256k1 = Secp256k1::new();
    let mut key_pair = UntweakedKeyPair::new(&secp256k1, &mut rand::thread_rng());

    // let key = secp256k1::SecretKey::from_str("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
    // let mut key_pair = secp256k1::KeyPair::from_secret_key(&secp256k1, &key);

    let (mut public_key, mut _parity) = XOnlyPublicKey::from_keypair(&key_pair);

    for (i, inscription) in inscription.iter().enumerate() {
      if !single_key && i != 0 {
        key_pair = UntweakedKeyPair::new(&secp256k1, &mut rand::thread_rng());
        (public_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);
      }
      key_pairs.push(key_pair);

      let reveal_script = inscription.append_reveal_script(
        ScriptBuf::builder()
          .push_slice(public_key.serialize())
          .push_opcode(opcodes::all::OP_CHECKSIG),
        cursed66,
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

      let mut inputs = vec![OutPoint::null()];
      let mut outputs = vec![TxOut {
        script_pubkey: destinations[i % destinations.len()].script_pubkey(),
        value: 0,
      }];

      if let Some(cursed_outpoint) = cursed_outpoint {
        let cursed_txout = cursed_txout.as_ref().unwrap();
        inputs.insert(0, cursed_outpoint);
        outputs.insert(
          0,
          TxOut {
            script_pubkey: match cursed_destination.clone() {
              Some(cursed_destination) => cursed_destination.script_pubkey(),
              None => cursed_txout.script_pubkey.clone(),
            },
            value: cursed_txout.value,
          },
        );
      }

      let (_, reveal_fee) = Self::build_reveal_transaction(
        &control_block,
        reveal_fee_rate,
        reveal_vout_postage,
        inputs,
        outputs,
        &reveal_script,
      );
      reveal_scripts.push(reveal_script);
      control_blocks.push(control_block);
      reveal_fees.push(reveal_fee + postage);
    }

    let mut utxos_clone = utxos.clone();
    if let Some(cursed_outpoint) = cursed_outpoint {
      utxos_clone.remove(&cursed_outpoint);
    }

    tprintln!("[make commit]");
    let unsigned_commit_tx = TransactionBuilder::build_transaction_with_values(
      satpoint,
      inscriptions,
      utxos_clone,
      commit_tx_addresses.clone(),
      alignment,
      change,
      commit_fee_rate,
      reveal_fees,
      max_inputs,
      ignore_utxo_inscriptions,
    )?;

    let mut reveal_txs = Vec::new();
    let mut recovery_key_pairs = Vec::new();

    // search the commit tx for the output that sends to the first reveal tx's taproot address, to use as an index
    let (first_vout, _output) = unsigned_commit_tx
      .output
      .iter()
      .enumerate()
      .find(|(_vout, output)| output.script_pubkey == commit_tx_addresses[0].script_pubkey())
      .expect("should find sat commit/inscription output");

    tprintln!("[remake reveals]");
    for (i, key_pair) in key_pairs.iter().enumerate() {
      let vout = i + first_vout;
      let output = &unsigned_commit_tx.output[vout];
      let reveal_script = &reveal_scripts[i];

      let mut inputs = vec![OutPoint {
        txid: unsigned_commit_tx.txid(),
        vout: vout.try_into().unwrap(),
      }];
      let mut outputs = vec![TxOut {
        script_pubkey: destinations[i % destinations.len()].script_pubkey(),
        value: output.value,
      }];

      if let Some(cursed_outpoint) = cursed_outpoint {
        let cursed_txout = cursed_txout.as_ref().unwrap();
        inputs.insert(0, cursed_outpoint);
        outputs.insert(
          0,
          TxOut {
            script_pubkey: match cursed_destination.clone() {
              Some(cursed_destination) => cursed_destination.script_pubkey(),
              None => cursed_txout.script_pubkey.clone(),
            },
            value: cursed_txout.value,
          },
        );
      }

      let (mut reveal_tx, fee) = Self::build_reveal_transaction(
        &control_blocks[i],
        reveal_fee_rate,
        reveal_vout_postage,
        inputs,
        outputs,
        reveal_script,
      );

      reveal_tx.output[reveal_vout_postage].value = reveal_tx.output[reveal_vout_postage]
        .value
        .checked_sub(fee.to_sat())
        .context("reveal transaction output value insufficient to pay transaction fee")?;

      if reveal_tx.output[reveal_vout_postage].value
        < reveal_tx.output[reveal_vout_postage]
          .script_pubkey
          .dust_value()
          .to_sat()
      {
        bail!("reveal transaction output would be dust");
      }

      let mut sighash_cache = SighashCache::new(&mut reveal_tx);

      let prevouts_all_inputs = &[output];
      let (prevouts, hash_ty) = if cursed_outpoint.is_some() {
        (
          Prevouts::One(1, output),
          TapSighashType::AllPlusAnyoneCanPay,
        )
      } else {
        (Prevouts::All(prevouts_all_inputs), TapSighashType::Default)
      };

      let signature_hash = sighash_cache
        .taproot_script_spend_signature_hash(
          reveal_vout_postage,
          &prevouts,
          TapLeafHash::from_script(reveal_script, LeafVersion::TapScript),
          hash_ty,
        )
        .expect("signature hash should compute");

      let signature = secp256k1.sign_schnorr(
        &secp256k1::Message::from_slice(signature_hash.as_ref())
          .expect("should be cryptographically secure hash"),
        key_pair,
      );

      let witness = sighash_cache
        .witness_mut(reveal_vout_postage)
        .expect("getting mutable witness reference should work");

      if cursed_outpoint.is_some() {
        let mut signature = signature.as_ref().to_vec();
        signature.push(hash_ty as u8);
        witness.push(signature);
      } else {
        witness.push(signature.as_ref());
      }

      witness.push(reveal_script);
      witness.push(control_blocks[i].serialize());

      let recovery_key_pair = key_pair.tap_tweak(&secp256k1, taproot_spend_infos[i].merkle_root());
      recovery_key_pairs.push(recovery_key_pair);

      let (x_only_pub_key, _parity) = recovery_key_pair.to_inner().x_only_public_key();
      assert_eq!(
        Address::p2tr_tweaked(
          TweakedPublicKey::dangerous_assume_tweaked(x_only_pub_key),
          network,
        ),
        commit_tx_addresses[i]
      );

      let reveal_weight = reveal_tx.weight();
      reveal_txs.push(reveal_tx);

      if !no_limit && reveal_weight > bitcoin::Weight::from_wu(MAX_STANDARD_TX_WEIGHT.into()) {
        bail!(
          "reveal transaction weight greater than {MAX_STANDARD_TX_WEIGHT} (MAX_STANDARD_TX_WEIGHT): {reveal_weight}"
        );
      }
      if (i + 1) % 100 == 0 {
        tprintln!("  [{}]", i + 1);
      }
    }

    Ok((satpoint, unsigned_commit_tx, reveal_txs, recovery_key_pairs))
  }

  fn get_recovery_key(
    client: &Client,
    recovery_key_pair: TweakedKeyPair,
    network: Network,
  ) -> Result<String> {
    let recovery_private_key =
      PrivateKey::new(recovery_key_pair.to_inner().secret_key(), network).to_wif();
    Ok(format!(
      "rawtr({})#{}",
      recovery_private_key,
      client
        .get_descriptor_info(&format!("rawtr({})", recovery_private_key))?
        .checksum
    ))
  }

  fn backup_recovery_key(
    client: &Client,
    recovery_key_pair: TweakedKeyPair,
    network: Network,
  ) -> Result {
    let descriptor = Self::get_recovery_key(client, recovery_key_pair, network)?;

    let response = client.import_descriptors(ImportDescriptors {
      descriptor,
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
    reveal_vout_postage: usize,
    inputs: Vec<OutPoint>,
    outputs: Vec<TxOut>,
    script: &Script,
  ) -> (Transaction, Amount) {
    let reveal_tx = Transaction {
      input: inputs
        .iter()
        .map(|outpoint| TxIn {
          previous_output: *outpoint,
          script_sig: script::Builder::new().into_script(),
          witness: Witness::new(),
          sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        })
        .collect(),
      output: outputs,
      lock_time: LockTime::ZERO,
      version: 1,
    };

    let fee = {
      let mut reveal_tx = reveal_tx.clone();

      for (current_index, txin) in reveal_tx.input.iter_mut().enumerate() {
        // add dummy inscription witness for reveal input/commit output
        if current_index == reveal_vout_postage {
          txin.witness.push(
            Signature::from_slice(&[0; SCHNORR_SIGNATURE_SIZE])
              .unwrap()
              .as_ref(),
          );
          txin.witness.push(script);
          txin.witness.push(&control_block.serialize());
        } else {
          txin.witness = Witness::from_slice(&[vec![0; SCHNORR_SIGNATURE_SIZE]]);
        }
      }

      fee_rate.fee(reveal_tx.weight() + Weight::from_wu(1)) // 1 for the sighash type?
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
    let reveal_address = vec![recipient()];

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
        None,
        None,
        None,
        FeeRate::try_from(1.0).unwrap(),
        FeeRate::try_from(1.0).unwrap(),
        None,
        false,
        TransactionBuilder::DEFAULT_TARGET_POSTAGE,
        false,
        false,
        false,
      )
      .unwrap();

    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_sign_loss)]
    let fee = Amount::from_sat(reveal_tx[0].weight().to_vbytes_ceil());

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
    let reveal_address = vec![recipient()];

    let (_satpoint, commit_tx, reveal_tx, _) = Inscribe::create_inscription_transactions(
      Some(satpoint(1, 0)),
      vec![inscription],
      BTreeMap::new(),
      Network::Bitcoin,
      utxos.into_iter().collect(),
      [commit_address, change(1)],
      reveal_address,
      None,
      None,
      None,
      None,
      FeeRate::try_from(1.0).unwrap(),
      FeeRate::try_from(1.0).unwrap(),
      None,
      false,
      TransactionBuilder::DEFAULT_TARGET_POSTAGE,
      false,
      false,
      false,
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
    let reveal_address = vec![recipient()];

    let error = Inscribe::create_inscription_transactions(
      satpoint,
      vec![inscription],
      inscriptions,
      Network::Bitcoin,
      utxos.into_iter().collect(),
      [commit_address, change(1)],
      reveal_address,
      None,
      None,
      None,
      None,
      FeeRate::try_from(1.0).unwrap(),
      FeeRate::try_from(1.0).unwrap(),
      None,
      false,
      TransactionBuilder::DEFAULT_TARGET_POSTAGE,
      false,
      false,
      false,
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
    let reveal_address = vec![recipient()];

    assert!(Inscribe::create_inscription_transactions(
      satpoint,
      vec![inscription],
      inscriptions,
      Network::Bitcoin,
      utxos.into_iter().collect(),
      [commit_address, change(1)],
      reveal_address,
      None,
      None,
      None,
      None,
      FeeRate::try_from(1.0).unwrap(),
      FeeRate::try_from(1.0).unwrap(),
      None,
      false,
      TransactionBuilder::DEFAULT_TARGET_POSTAGE,
      false,
      false,
      false,
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
    let reveal_address = vec![recipient()];
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
        None,
        None,
        None,
        FeeRate::try_from(fee_rate).unwrap(),
        FeeRate::try_from(fee_rate).unwrap(),
        None,
        false,
        TransactionBuilder::DEFAULT_TARGET_POSTAGE,
        false,
        false,
        false,
      )
      .unwrap();

    let sig_vbytes = 17.0;
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_sign_loss)]
    let fee = FeeRate::try_from(fee_rate)
      .unwrap()
      .fee(Weight::from_vb((commit_tx.weight().to_wu() as f64 / 4.0 + sig_vbytes) as u64).unwrap())
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
      .fee(reveal_tx[0].weight())
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
    let reveal_address = vec![recipient()];
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
        None,
        None,
        None,
        FeeRate::try_from(commit_fee_rate).unwrap(),
        FeeRate::try_from(fee_rate).unwrap(),
        None,
        false,
        TransactionBuilder::DEFAULT_TARGET_POSTAGE,
        false,
        false,
        false,
      )
      .unwrap();

    let sig_vbytes = 17;
    let fee = FeeRate::try_from(commit_fee_rate)
      .unwrap()
      .fee(Weight::from_vb((commit_tx.vsize() + sig_vbytes) as u64).unwrap())
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
      .fee(reveal_tx[0].weight())
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
    let reveal_address = vec![recipient()];

    let error = Inscribe::create_inscription_transactions(
      satpoint,
      vec![inscription],
      BTreeMap::new(),
      Network::Bitcoin,
      utxos.into_iter().collect(),
      [commit_address, change(1)],
      reveal_address,
      None,
      None,
      None,
      None,
      FeeRate::try_from(1.0).unwrap(),
      FeeRate::try_from(1.0).unwrap(),
      None,
      false,
      TransactionBuilder::DEFAULT_TARGET_POSTAGE,
      false,
      false,
      false,
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
    let reveal_address = vec![recipient()];

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
        None,
        None,
        None,
        FeeRate::try_from(1.0).unwrap(),
        FeeRate::try_from(1.0).unwrap(),
        None,
        true,
        TransactionBuilder::DEFAULT_TARGET_POSTAGE,
        false,
        false,
        false,
      )
      .unwrap();

    assert!(reveal_tx[0].size() >= MAX_STANDARD_TX_WEIGHT as usize);
  }
}
