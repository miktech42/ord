use {super::*, crate::wallet::Wallet};

#[derive(Debug, Parser)]
pub(crate) struct Send {
  address: Address,
  outgoing: Outgoing,
  #[clap(
    long,
    help = "Consider spending outpoint <UTXO>, even if it is unconfirmed or contains inscriptions"
  )]
  utxo: Vec<OutPoint>,
  #[clap(
    long,
    help = "Only spend outpoints given with --utxo when sending inscriptions or satpoints"
  )]
  pub(crate) coin_control: bool,
  #[clap(long, help = "Use fee rate of <FEE_RATE> sats/vB")]
  fee_rate: FeeRate,
  #[clap(long, help = "Send any alignment output to <ALIGNMENT>.")]
  pub(crate) alignment: Option<Address>,
  #[clap(long, help = "Send any change output to <CHANGE>.")]
  pub(crate) change: Option<Address>,
  #[clap(
    long,
    help = "Target amount of postage to include in the sent output. Default `10000 sats`"
  )]
  pub(crate) target_postage: Option<Amount>,
  #[clap(
    long,
    help = "Maximum amount of postage to include in the sent output. Default `20000 sats`"
  )]
  pub(crate) max_postage: Option<Amount>,
  #[clap(
    long,
    help = "Use at most <MAX_INPUTS> inputs to build the transaction sending a satpoint or an inscription."
  )]
  pub(crate) max_inputs: Option<usize>,
}

#[derive(Serialize, Deserialize)]
pub struct Output {
  pub transaction: Txid,
}

#[derive(Serialize, Deserialize)]
pub struct SendAllOutput {
  pub txid: Txid,
  pub complete: bool,
}

impl Send {
  pub(crate) fn run(self, options: Options) -> Result {
    if !self.address.is_valid_for_network(options.chain().network()) {
      bail!(
        "Address `{}` is not valid for {}",
        self.address,
        options.chain()
      );
    }

    let index = Index::open(&options)?;
    index.update()?;

    let client = options.bitcoin_rpc_client_for_wallet_command(false)?;

    let mut unspent_outputs = if self.coin_control {
      BTreeMap::new()
    } else {
      index.get_unspent_outputs(Wallet::load(&options)?)?
    };

    for outpoint in &self.utxo {
      unspent_outputs.insert(
        *outpoint,
        Amount::from_sat(
          client.get_raw_transaction(&outpoint.txid, None)?.output[outpoint.vout as usize].value,
        ),
      );
    }

    let inscriptions = index.get_inscriptions(None)?;

    let satpoint = match self.outgoing {
      Outgoing::SatPoint(satpoint) => {
        for inscription_satpoint in inscriptions.keys() {
          if satpoint == *inscription_satpoint {
            bail!("inscriptions must be sent by inscription ID");
          }
        }
        satpoint
      }
      Outgoing::InscriptionId(id) => index
        .get_inscription_satpoint_by_id(id)?
        .ok_or_else(|| anyhow!("Inscription {id} not found"))?,
      Outgoing::Amount(amount) => {
        self.send_amount(amount, &client, inscriptions, unspent_outputs)?;
        return Ok(());
      }
      Outgoing::All => {
        self.send_all_or_max(&client, inscriptions, unspent_outputs)?;
        return Ok(());
      }
      Outgoing::Max => {
        self.send_all_or_max(&client, inscriptions, unspent_outputs)?;
        return Ok(());
      }
    };

    let change = [
      get_change_address(&client)?,
      match self.change {
        Some(change) => change,
        None => get_change_address(&client)?,
      },
    ];

    let unsigned_transaction = TransactionBuilder::build_transaction_with_postage(
      satpoint,
      inscriptions,
      unspent_outputs,
      self.address,
      self.alignment,
      change,
      self.fee_rate,
      self.max_inputs,
      match self.target_postage {
        Some(target_postage) => target_postage,
        _ => TransactionBuilder::DEFAULT_TARGET_POSTAGE,
      },
      match self.max_postage {
        Some(max_postage) => max_postage,
        _ => TransactionBuilder::DEFAULT_MAX_POSTAGE,
      },
    )?;

    let signed_tx = client
      .sign_raw_transaction_with_wallet(&unsigned_transaction, None, None)?
      .hex;

    let txid = client.send_raw_transaction(&signed_tx)?;

    println!("{txid}");

    Ok(())
  }

  fn send_amount(
    self,
    amount: Amount,
    client: &Client,
    inscriptions: BTreeMap<SatPoint, InscriptionId>,
    unspent_outputs: BTreeMap<bitcoin::OutPoint, bitcoin::Amount>,
  ) -> Result {
    Self::lock_inscriptions(client, inscriptions, unspent_outputs)?;
    let txid = client.call(
      "sendtoaddress",
      &[
        self.address.to_string().into(),        //  1. address
        amount.to_btc().into(),                 //  2. amount
        serde_json::Value::Null,                //  3. comment
        serde_json::Value::Null,                //  4. comment_to
        serde_json::Value::Null,                //  5. subtractfeefromamount
        serde_json::Value::Null,                //  6. replaceable
        serde_json::Value::Null,                //  7. conf_target
        serde_json::Value::Null,                //  8. estimate_mode
        serde_json::Value::Null,                //  9. avoid_reuse
        self.fee_rate.fee(1.0).to_sat().into(), // 10. fee_rate
      ],
    )?;
    print_json(Output { transaction: txid })?;
    Ok(())
  }

  fn send_all_or_max(
    self,
    client: &Client,
    inscriptions: BTreeMap<SatPoint, InscriptionId>,
    unspent_outputs: BTreeMap<bitcoin::OutPoint, bitcoin::Amount>,
  ) -> Result {
    Self::lock_inscriptions(client, inscriptions, unspent_outputs)?;
    let result: SendAllOutput = client.call(
      "sendall",
      &[
        vec![serde_json::to_value((self.address).to_string())?].into(), //  1. recipients
        serde_json::Value::Null, //                                         2. conf_target
        serde_json::Value::Null, //                                         3. estimate_mode
        self.fee_rate.fee(1.0).to_sat().into(), //                          4. fee_rate
        serde_json::from_str(if self.outgoing == Outgoing::Max {
          "{\"send_max\": true}" //                                         5. options
        } else {
          "{\"send_max\": false}"
        })?,
      ],
    )?;
    print_json(result)?;
    Ok(())
  }

  fn lock_inscriptions(
    client: &Client,
    inscriptions: BTreeMap<SatPoint, InscriptionId>,
    unspent_outputs: BTreeMap<bitcoin::OutPoint, bitcoin::Amount>,
  ) -> Result {
    let all_inscription_outputs = inscriptions
      .keys()
      .map(|satpoint| satpoint.outpoint)
      .collect::<HashSet<OutPoint>>();

    let wallet_inscription_outputs = unspent_outputs
      .keys()
      .filter(|utxo| all_inscription_outputs.contains(utxo))
      .cloned()
      .collect::<Vec<OutPoint>>();

    if !client.lock_unspent(&wallet_inscription_outputs)? {
      bail!("failed to lock ordinal UTXOs");
    }

    Ok(())
  }
}
