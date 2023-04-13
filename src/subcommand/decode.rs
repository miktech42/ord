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
    let vin = self.vin as usize;
    if vin >= inputs.len() {
      bail!("<VIN> too high - there are only {} input(s)", inputs.len());
    }
    let input = &inputs[vin];
    match Inscription::from_witness(&input.witness) {
      Some(inscription) => {
        fs::OpenOptions::new()
          .create(true)
          .write(true)
          .truncate(true)
          .open("file.dat")?
          .write_all(&inscription.body().unwrap())?;

        println!("content-type: {}", inscription.content_type().unwrap());
        println!("body written to file.dat");
      }
      None => bail!("No inscription on that input"),
    }
    Ok(())
  }
}
