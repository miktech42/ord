use {super::*, crate::wallet::Wallet};

#[derive(Serialize, Deserialize)]
pub struct OutputWithSat {
  pub sat: Sat,
  pub number: i64,
  pub inscription: InscriptionId,
  pub location: SatPoint,
  pub explorer: String,
  pub amount: u64,
}

#[derive(Serialize, Deserialize)]
pub struct OutputWithoutSat {
  pub number: i64,
  pub inscription: InscriptionId,
  pub location: SatPoint,
  pub explorer: String,
  pub amount: u64,
}

pub(crate) fn run(options: Options) -> Result {
  let index = Index::open(&options)?;
  index.update()?;

  let index_has_sats = index.has_sat_index()?;

  let unspent_outputs = index.get_unspent_outputs(Wallet::load(&options)?)?;
  let inscriptions = index.get_inscriptions(unspent_outputs.clone())?;

  let explorer = match options.chain() {
    Chain::Mainnet => "https://ordinals.com/inscription/",
    Chain::Regtest => "http://localhost/inscription/",
    Chain::Signet => "https://signet.ordinals.com/inscription/",
    Chain::Testnet => "https://testnet.ordinals.com/inscription/",
  };

  let mut output_with_sat = Vec::new();
  let mut output_without_sat = Vec::new();

  for (location, inscription) in inscriptions {
    if unspent_outputs.contains_key(&location.outpoint) {
      let entry = index
        .get_inscription_entry(inscription)?
        .ok_or_else(|| anyhow!("Inscription {inscription} not found"))?;
      if index_has_sats {
        output_with_sat.push(OutputWithSat {
          sat: entry.sat.unwrap(),
          number: entry.number,
          location,
          inscription,
          explorer: format!("{explorer}{inscription}"),
          amount: unspent_outputs.get(&location.outpoint).unwrap().to_sat(),
        });
      } else {
        output_without_sat.push(OutputWithoutSat {
          number: entry.number,
          location,
          inscription,
          explorer: format!("{explorer}{inscription}"),
          amount: unspent_outputs.get(&location.outpoint).unwrap().to_sat(),
        });
      }
    }
  }

  if index_has_sats {
    print_json(&output_with_sat)?;
  } else {
    print_json(&output_without_sat)?;
  }

  Ok(())
}
