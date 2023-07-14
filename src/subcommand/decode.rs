use super::*;
use std::io::Write;

#[derive(Debug, Parser)]
pub(crate) struct Decode {
  #[clap(help = "Decode inscription data in <TXID>.")]
  txid: Txid,
  #[clap(
    default_value = "0",
    help = "Decode inscription data in input <VIN> of <TXID>."
  )]
  vin: usize,
}

impl Decode {
  pub(crate) fn run(self, options: Options) -> Result {
    let index = Index::open(&options)?;

    let inputs = &Index::get_transaction(&index, self.txid)?.unwrap().input;
    let vin = self.vin;
    if vin >= inputs.len() {
      bail!("<VIN> too high - there are only {} input(s)", inputs.len());
    }
    let input = &inputs[vin];
    match Inscription::from_witness(&input.witness) {
      Err(_) => println!("no inscription in input {vin} of {}", self.txid),
      Ok(inscriptions) =>
        for (i, inscription) in inscriptions.iter().enumerate() {
          let file = if i == 0 { String::from("file.dat") } else { format!("file{i}.dat")};
          fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&file)?
            .write_all(inscription.body().unwrap())?;

          println!("content-type: {}", inscription.content_type().unwrap());
          println!("body written to {file}");
        }
    }
    Ok(())
  }
}
