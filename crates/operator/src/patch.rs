use std::{fmt::Write, str::FromStr};

use serde_json::{Map, Value};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PatchError {
    #[error("invalid path `{path}`: {reason}")]
    Syntax { path: String, reason: &'static str },
    #[error("`{path}`: `{at}` is not an array")]
    NotAnArray { path: String, at: String },
    #[error("`{path}`: `{at}` has no element {index}")]
    OutOfBounds {
        path: String,
        at: String,
        index: usize,
    },
    #[error("`{path}`: `{at}` is not a table")]
    NotAnObject { path: String, at: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Step {
    Key(String),
    Each,
    Index(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchPath {
    text: String,
    steps: Vec<Step>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Patch {
    sets: Vec<(PatchPath, Value)>,
}

impl Patch {
    pub fn new(sets: impl IntoIterator<Item = (String, Value)>) -> Result<Self, PatchError> {
        let sets = sets
            .into_iter()
            .map(|(path, value)| Ok((path.parse::<PatchPath>()?, value)))
            .collect::<Result<Vec<_>, PatchError>>()?;
        Ok(Self { sets })
    }

    pub fn apply(&self, target: &mut Value) -> Result<(), PatchError> {
        self.sets
            .iter()
            .try_for_each(|(path, value)| path.set(target, value))
    }
}

impl FromStr for PatchPath {
    type Err = PatchError;

    fn from_str(text: &str) -> Result<Self, PatchError> {
        let steps = parse_steps(text).map_err(|reason| PatchError::Syntax {
            path: text.to_owned(),
            reason,
        })?;
        Ok(Self {
            text: text.to_owned(),
            steps,
        })
    }
}

fn parse_steps(text: &str) -> Result<Vec<Step>, &'static str> {
    let mut steps = Vec::new();
    let mut rest = text;
    loop {
        rest = parse_key(rest, &mut steps)?;
        while let Some(inner) = rest.strip_prefix('[') {
            let end = inner.find(']').ok_or("unterminated `[`")?;
            steps.push(match &inner[..end] {
                "*" => Step::Each,
                index => Step::Index(index.parse().map_err(|_| "index must be `*` or a number")?),
            });
            rest = &inner[end + 1..];
        }
        if rest.is_empty() {
            return Ok(steps);
        }
        rest = rest
            .strip_prefix('.')
            .ok_or("expected `.` or `[` after a segment")?;
    }
}

fn parse_key<'a>(rest: &'a str, steps: &mut Vec<Step>) -> Result<&'a str, &'static str> {
    if let Some(quoted) = rest.strip_prefix('"') {
        let end = quoted.find('"').ok_or("unterminated quote")?;
        steps.push(Step::Key(quoted[..end].to_owned()));
        return Ok(&quoted[end + 1..]);
    }
    let end = rest.find(is_special).unwrap_or(rest.len());
    if end == 0 {
        return Err("empty segment");
    }
    steps.push(Step::Key(rest[..end].to_owned()));
    Ok(&rest[end..])
}

fn is_special(c: char) -> bool {
    matches!(c, '.' | '[' | ']' | '"')
}

fn render(steps: &[Step]) -> String {
    let mut out = String::new();
    for step in steps {
        match step {
            Step::Key(key) => {
                if !out.is_empty() {
                    out.push('.');
                }
                if key.is_empty() || key.contains(is_special) {
                    let _ = write!(out, "\"{key}\"");
                } else {
                    out.push_str(key);
                }
            }
            Step::Each => out.push_str("[*]"),
            Step::Index(index) => {
                let _ = write!(out, "[{index}]");
            }
        }
    }
    out
}

impl PatchPath {
    fn set(&self, target: &mut Value, value: &Value) -> Result<(), PatchError> {
        self.set_at(target, 0, value)
    }

    fn set_at(&self, node: &mut Value, depth: usize, value: &Value) -> Result<(), PatchError> {
        let Some(step) = self.steps.get(depth) else {
            *node = value.clone();
            return Ok(());
        };
        match step {
            Step::Key(key) => {
                if node.is_null() {
                    *node = Value::Object(Map::new());
                }
                let Value::Object(fields) = node else {
                    return Err(PatchError::NotAnObject {
                        path: self.text.clone(),
                        at: render(&self.steps[..depth]),
                    });
                };
                let creates_array =
                    matches!(self.steps.get(depth + 1), Some(Step::Each | Step::Index(_)));
                if creates_array && fields.get(key).is_none_or(Value::is_null) {
                    return Err(self.not_an_array(depth + 1));
                }
                self.set_at(
                    fields.entry(key.as_str()).or_insert(Value::Null),
                    depth + 1,
                    value,
                )
            }
            Step::Each => {
                let Value::Array(items) = node else {
                    return Err(self.not_an_array(depth));
                };
                items
                    .iter_mut()
                    .try_for_each(|item| self.set_at(item, depth + 1, value))
            }
            Step::Index(index) => {
                let Value::Array(items) = node else {
                    return Err(self.not_an_array(depth));
                };
                let Some(item) = items.get_mut(*index) else {
                    return Err(PatchError::OutOfBounds {
                        path: self.text.clone(),
                        at: render(&self.steps[..depth]),
                        index: *index,
                    });
                };
                self.set_at(item, depth + 1, value)
            }
        }
    }

    fn not_an_array(&self, depth: usize) -> PatchError {
        PatchError::NotAnArray {
            path: self.text.clone(),
            at: render(&self.steps[..depth]),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn patch(sets: Value) -> Patch {
        let Value::Object(sets) = sets else {
            panic!("patch sets are an object")
        };
        Patch::new(sets).unwrap()
    }

    #[test]
    fn nested_set_creates_missing_tables() {
        let mut target = json!({ "spec": { "entryPoints": ["websecure"] } });
        patch(json!({
            "spec.tls.certResolver": "letsencrypt",
            "metadata.annotations.\"example.com/team\"": "web"
        }))
        .apply(&mut target)
        .unwrap();
        assert_eq!(
            target,
            json!({
                "metadata": { "annotations": { "example.com/team": "web" } },
                "spec": {
                    "entryPoints": ["websecure"],
                    "tls": { "certResolver": "letsencrypt" }
                }
            })
        );
    }

    #[test]
    fn wildcard_sets_every_element() {
        let mut target = json!({
            "spec": {
                "routes": [
                    { "match": "Host(`a`)" },
                    { "match": "Host(`b`)", "middlewares": [{ "name": "old" }] }
                ]
            }
        });
        patch(json!({ "spec.routes[*].middlewares": [{ "name": "auth" }] }))
            .apply(&mut target)
            .unwrap();
        assert_eq!(
            target["spec"]["routes"],
            json!([
                { "match": "Host(`a`)", "middlewares": [{ "name": "auth" }] },
                { "match": "Host(`b`)", "middlewares": [{ "name": "auth" }] }
            ])
        );
    }

    #[test]
    fn index_sets_one_element() {
        let mut target = json!({ "spec": { "routes": [{ "kind": "Rule" }, { "kind": "Rule" }] } });
        patch(json!({ "spec.routes[1].priority": 10 }))
            .apply(&mut target)
            .unwrap();
        assert_eq!(
            target["spec"]["routes"],
            json!([{ "kind": "Rule" }, { "kind": "Rule", "priority": 10 }])
        );
    }

    #[test]
    fn array_steps_on_missing_or_short_paths_fail() {
        let mut target = json!({ "spec": { "routes": [{}], "tls": "on" } });
        assert_eq!(
            patch(json!({ "spec.services[*].port": 80 })).apply(&mut target),
            Err(PatchError::NotAnArray {
                path: "spec.services[*].port".to_owned(),
                at: "spec.services".to_owned(),
            })
        );
        assert_eq!(
            patch(json!({ "spec.tls[*].x": 1 })).apply(&mut target),
            Err(PatchError::NotAnArray {
                path: "spec.tls[*].x".to_owned(),
                at: "spec.tls".to_owned(),
            })
        );
        assert_eq!(
            patch(json!({ "spec.routes[3].x": 1 })).apply(&mut target),
            Err(PatchError::OutOfBounds {
                path: "spec.routes[3].x".to_owned(),
                at: "spec.routes".to_owned(),
                index: 3,
            })
        );
        assert_eq!(target, json!({ "spec": { "routes": [{}], "tls": "on" } }));
    }

    #[test]
    fn malformed_paths_are_rejected() {
        for path in [
            "spec..routes",
            "spec.routes[x]",
            "spec.routes[1",
            "",
            "spec.\"open",
        ] {
            assert!(
                matches!(path.parse::<PatchPath>(), Err(PatchError::Syntax { .. })),
                "{path} should not parse"
            );
        }
    }
}
