use super::*;

#[derive(Debug, Parser)]
pub(crate) struct Find {
  #[clap(long, help = "Only look in specified outpoint(s).")]
  outpoint: Vec<OutPoint>,
  #[clap(help = "Find output and offset of <SAT>.")]
  sat: Sat,
  #[clap(help = "Find output and offset of all sats in the range <SAT>-<END>.")]
  end: Option<Sat>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Output {
  pub satpoint: SatPoint,
}

impl Find {
  pub(crate) fn run(self, options: Options) -> Result {
    let index = Index::open(&options)?;

    index.update()?;

    match self.end {
      Some(end) => {
        if self.sat < end {
          match index.find_range(self.sat.0, end.0, &self.outpoint)? {
            Some(result) => {
              print_json(result)?;
              Ok(())
            }
            None => Err(anyhow!("range has not been mined as of index height")),
          }
        } else {
          Err(anyhow!("range is empty"))
        }
      }
      None => match index.find(self.sat.0, &self.outpoint)? {
        Some(satpoint) => {
          print_json(Output { satpoint })?;
          Ok(())
        }
        None => Err(anyhow!(if self.outpoint.len() == 0 {
          "sat has not been mined as of index height"
        } else {
          "sat was not found in satpoint(s)"
        })),
      },
    }
  }
}
