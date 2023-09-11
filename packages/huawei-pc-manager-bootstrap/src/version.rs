use std::str::FromStr;

#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct SetupVersion(usize, usize, usize, usize);

impl FromStr for SetupVersion {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let num_list = match s
            .split('.')
            .map(|s| s.parse::<usize>())
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(num_list) => num_list,
            Err(err) => return Err(format!("{}", err)),
        };

        match num_list.as_slice() {
            [a, b, c, d, ..] => Ok(SetupVersion(*a, *b, *c, *d)),
            _ => Err(format!("No enough version field")),
        }
    }
}
