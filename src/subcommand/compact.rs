use super::*;

pub(crate) fn run(options: Options) -> Result {
  let mut index = Index::open(&options)?;
  index.update()?;

  println!("compacting db file");
  match index.compact_db()? {
    true => println!("compacted db"),
    false => println!("db didn't need compacting"),
  }

  Ok(())
}
