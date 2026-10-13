use anyhow::{Result,ensure};
use noah_public_proof::{InvoicePolicy,validate_invoice};
use std::io::{self,Read};

fn main()->Result<()> {
    let mut input=String::new();io::stdin().take(192*1024+1).read_to_string(&mut input)?;
    ensure!(input.len()<=192*1024,"public policy input exceeds bound");
    let policy:InvoicePolicy=serde_json::from_str(&input)?;
    let verified=validate_invoice(&policy)?;
    println!("{}",serde_json::to_string(&verified)?);
    Ok(())
}
