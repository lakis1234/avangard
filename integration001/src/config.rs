use std::path::PathBuf;

pub const MAX_BENCH_COUNT: usize = 128;
pub const DEFAULT_BENCH_COUNT: usize = MAX_BENCH_COUNT;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControllerConfig {
    pub bench_count: usize,
    pub evidence_path: Option<PathBuf>,
}

impl Default for ControllerConfig {
    fn default() -> Self {
        Self {
            bench_count: DEFAULT_BENCH_COUNT,
            evidence_path: None,
        }
    }
}

pub fn parse_controller_args(args: &[String]) -> Result<ControllerConfig, String> {
    let mut config = ControllerConfig::default();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--bench-count" => {
                let raw = args
                    .get(index + 1)
                    .ok_or("--bench-count requires an integer")?;
                let value = raw
                    .parse::<usize>()
                    .map_err(|_| format!("invalid --bench-count value: {raw}"))?;
                if !(1..=MAX_BENCH_COUNT).contains(&value) {
                    return Err(format!(
                        "--bench-count must be between 1 and {MAX_BENCH_COUNT}"
                    ));
                }
                config.bench_count = value;
                index += 2;
            }
            "--evidence" => {
                let raw = args.get(index + 1).ok_or("--evidence requires a path")?;
                if raw.is_empty() {
                    return Err("--evidence path cannot be empty".into());
                }
                config.evidence_path = Some(PathBuf::from(raw));
                index += 2;
            }
            "--campaign" | "--full-campaign" => {
                return Err(format!(
                    "{} is NOT IMPLEMENTED; refusing to report unexecuted Phase B gates",
                    args[index]
                ));
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn defaults_are_bounded() {
        let config = parse_controller_args(&[]).unwrap();
        assert_eq!(config.bench_count, DEFAULT_BENCH_COUNT);
        assert!(config.evidence_path.is_none());
    }

    #[test]
    fn supported_arguments_parse_in_either_order() {
        let config = parse_controller_args(&strings(&[
            "--evidence",
            "result.json",
            "--bench-count",
            "128",
        ]))
        .unwrap();
        assert_eq!(config.bench_count, 128);
        assert_eq!(config.evidence_path, Some(PathBuf::from("result.json")));
    }

    #[test]
    fn invalid_or_unimplemented_modes_fail_closed() {
        for args in [
            strings(&["--bench-count", "0"]),
            strings(&["--bench-count", "129"]),
            strings(&["--bench-count", "no"]),
            strings(&["--evidence"]),
            strings(&["--campaign"]),
            strings(&["--unknown"]),
        ] {
            assert!(parse_controller_args(&args).is_err(), "accepted {args:?}");
        }
    }
}
