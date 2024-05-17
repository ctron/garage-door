use garage_door::config::Configuration;

fn main() -> anyhow::Result<()> {
    let schema = schemars::schema_for!(Configuration);
    let path = "schema/config.json";
    {
        let file = std::fs::File::create(path)?;
        serde_json::to_writer_pretty(file, &schema)?;
    }
    println!("Wrote schema to: {path}");

    Ok(())
}
