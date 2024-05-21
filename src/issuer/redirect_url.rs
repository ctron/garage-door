use oxide_auth::primitives::registrar::{ExactUrl, IgnoreLocalPortUrl, RegisteredUrl};
use schemars::gen::SchemaGenerator;
use schemars::schema::{Schema, SchemaObject, SubschemaValidation};
use schemars::JsonSchema;
use serde::de::{Error, MapAccess};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::Formatter;
use std::str::FromStr;
use url::Url;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedirectUrlOrString(pub RedirectUrl);

impl Serialize for RedirectUrlOrString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // TODO: we could do better and try to use a string if that's sufficient
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RedirectUrlOrString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = RedirectUrlOrString;

            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("string of RedirectUrl struct")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                let ignore_localhost_port = match Url::parse(v) {
                    Ok(url) if url.host_str() == Some("localhost") => true,
                    _ => false,
                };

                Ok(RedirectUrlOrString(RedirectUrl::Exact {
                    url: v.to_string(),
                    ignore_localhost_port,
                }))
            }

            fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                Ok(RedirectUrlOrString(Deserialize::deserialize(
                    de::value::MapAccessDeserializer::new(map),
                )?))
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

impl JsonSchema for RedirectUrlOrString {
    fn schema_name() -> String {
        "RedirectUrlOrString".to_string()
    }

    fn json_schema(gen: &mut SchemaGenerator) -> Schema {
        SchemaObject {
            subschemas: Some(Box::new(SubschemaValidation {
                one_of: Some(vec![
                    {
                        let mut schema: SchemaObject = <String>::json_schema(gen).into();
                        schema.format = Some("uri".into());
                        schema.into()
                    },
                    <RedirectUrl>::json_schema(gen),
                ]),
                ..Default::default()
            })),
            ..Default::default()
        }
        .into()
    }
}

#[derive(
    Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub enum RedirectUrl {
    Semantic(Url),
    #[serde(rename_all = "camelCase")]
    Exact {
        url: String,
        /// ignore the port on localhost URLs
        #[serde(default)]
        ignore_localhost_port: bool,
    },
}

impl TryFrom<RedirectUrl> for RegisteredUrl {
    type Error = url::ParseError;

    fn try_from(value: RedirectUrl) -> Result<Self, Self::Error> {
        Ok(match value {
            RedirectUrl::Semantic(url) => Self::Semantic(url),
            RedirectUrl::Exact {
                url,
                ignore_localhost_port: false,
            } => Self::Exact(ExactUrl::from_str(&url)?),
            RedirectUrl::Exact {
                url,
                ignore_localhost_port: true,
            } => Self::IgnorePortOnLocalhost(IgnoreLocalPortUrl::from_str(&url)?),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::json;

    #[test]
    fn deser() -> anyhow::Result<()> {
        assert_eq!(
            serde_json::from_value::<Vec<RedirectUrlOrString>>(json!([
                "https://example.com/foo",
                "https://localhost/foo",
                "https://localhost:1234/foo",
                {
                    "semantic": "https://example.com/bar",
                },
                {
                    "exact": {
                        "url": "https://example.com/foo/bar"
                    },
                }, {
                    "exact": {
                        "url": "https://example.com/foo/bar/baz",
                        "ignoreLocalhostPort": true,
                    },
                }
            ]))?
            .into_iter()
            .map(|e| e.0)
            .collect::<Vec<_>>(),
            vec![
                RedirectUrl::Exact {
                    url: "https://example.com/foo".into(),
                    ignore_localhost_port: false
                },
                RedirectUrl::Exact {
                    url: "https://localhost/foo".into(),
                    ignore_localhost_port: true
                },
                RedirectUrl::Exact {
                    url: "https://localhost:1234/foo".into(),
                    ignore_localhost_port: true
                },
                RedirectUrl::Semantic("https://example.com/bar".parse()?),
                RedirectUrl::Exact {
                    url: "https://example.com/foo/bar".into(),
                    ignore_localhost_port: false
                },
                RedirectUrl::Exact {
                    url: "https://example.com/foo/bar/baz".into(),
                    ignore_localhost_port: true
                },
            ]
        );

        Ok(())
    }
}
