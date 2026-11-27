use base64::{engine::general_purpose, Engine};
use rug::{Complete, Integer};

use crate::DEFAULT_SEARCH_BUDGET;
use std::{
    fmt::Display,
    ops::{Add, AddAssign},
    str::FromStr,
};

#[derive(Debug, Clone, PartialEq, Eq)]
/// Orientation of the known digits (where the ? run sits)
pub enum Orientation {
    /// MSB known (trailing wildcards): ???? appears at the end
    MsbKnown,
    /// LSB known (leading wildcards): ???? appears at the start
    LsbKnown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Represents a partial prime with known and unknown digits
pub enum PartialPrime {
    /// Full prime value is known
    Full(Integer),
    /// Partial prime with wildcards (? or ...)
    Partial {
        /// The radix/base: 2 (0b), 8 (0o), 10 (default), 16 (0x)
        radix: u32,
        /// Count of ? digits in that radix (None for ellipsis, inferred from N)
        k: Option<usize>,
        /// Where the wildcard run sits (start = LsbKnown, end = MsbKnown)
        orient: Orientation,
        /// The known digit run parsed in that radix
        known: Integer,
    },
}

impl PartialPrime {
    /// Returns the known value if this is a full prime
    pub fn full(&self) -> Option<&Integer> {
        match self {
            PartialPrime::Full(n) => Some(n),
            _ => None,
        }
    }

    /// Returns true if this is a partial prime
    pub fn is_partial(&self) -> bool {
        !matches!(self, PartialPrime::Full(_))
    }
}

#[derive(Debug, Clone)]
/// Struct used to parse integers from different bases and formats
pub struct IntegerArg(pub Integer);

impl std::str::FromStr for IntegerArg {
    type Err = String;

    fn from_str(n: &str) -> Result<Self, Self::Err> {
        if let Some(n) = n.strip_prefix("0x").or_else(|| n.strip_prefix("0X")) {
            // Check for wildcards in hex numbers
            if n.contains('?') {
                return Err("Use PartialPrimeArg for wildcard numbers".to_string());
            }
            Ok(Self(
                Integer::from_str_radix(n, 16).or(Err("Invalid hex number".to_string()))?,
            ))
        } else if let Some(n) = n.strip_prefix("0b").or_else(|| n.strip_prefix("0B")) {
            Ok(Self(
                Integer::from_str_radix(n, 2).or(Err("Invalid binary number".to_string()))?,
            ))
        } else if let Some(n) = n.strip_prefix("0o").or_else(|| n.strip_prefix("0O")) {
            Ok(Self(
                Integer::from_str_radix(n, 8).or(Err("Invalid octal number".to_string()))?,
            ))
        } else if let Some(n) = n.strip_prefix("b64").or_else(|| n.strip_prefix("B64")) {
            let bytes = general_purpose::STANDARD
                .decode(n.as_bytes())
                .or(Err("Invalid base64 number".to_string()))?;
            Ok(Self(Integer::from_digits(&bytes, rug::integer::Order::Msf)))
        } else {
            Ok(Self(
                Integer::from_str(n).or(Err("Invalid number".to_string()))?,
            ))
        }
    }
}

#[derive(Debug, Clone)]
/// Struct used to parse partial primes with wildcards
pub struct PartialPrimeArg(pub PartialPrime);

impl std::str::FromStr for PartialPrimeArg {
    type Err = String;

    fn from_str(n: &str) -> Result<Self, Self::Err> {
        // Check for wildcards and ellipsis
        let has_wildcards = n.contains('?');
        let has_ellipsis = n.contains("...");

        if has_wildcards && has_ellipsis {
            return Err("Cannot mix ? wildcards and ellipsis (...)".to_string());
        }

        if !has_wildcards && !has_ellipsis {
            // No wildcards - try parsing as regular integer
            if let Ok(IntegerArg(num)) = IntegerArg::from_str(n) {
                return Ok(Self(PartialPrime::Full(num)));
            }
            return Err("Invalid number".to_string());
        }

        if has_ellipsis {
            // Has ellipsis - parse ellipsis-based partial
            if let Some(s) = n.strip_prefix("0x").or_else(|| n.strip_prefix("0X")) {
                Self::parse_with_ellipsis(s, 16)
            } else if let Some(s) = n.strip_prefix("0b").or_else(|| n.strip_prefix("0B")) {
                Self::parse_with_ellipsis(s, 2)
            } else if let Some(s) = n.strip_prefix("0o").or_else(|| n.strip_prefix("0O")) {
                Self::parse_with_ellipsis(s, 8)
            } else {
                // Default to decimal (radix 10)
                Self::parse_with_ellipsis(n, 10)
            }
        } else {
            // Has wildcards - determine radix based on prefix
            // Bases: 0b→2, 0o→8, 0x→16; otherwise 10
            if let Some(s) = n.strip_prefix("0x").or_else(|| n.strip_prefix("0X")) {
                Self::parse_with_wildcards(s, 16)
            } else if let Some(s) = n.strip_prefix("0b").or_else(|| n.strip_prefix("0B")) {
                Self::parse_with_wildcards(s, 2)
            } else if let Some(s) = n.strip_prefix("0o").or_else(|| n.strip_prefix("0O")) {
                Self::parse_with_wildcards(s, 8)
            } else {
                // Default to decimal (radix 10)
                Self::parse_with_wildcards(n, 10)
            }
        }
    }
}

impl PartialPrimeArg {
    fn parse_with_ellipsis(s: &str, radix: u32) -> Result<Self, String> {
        // Check if ellipsis is at start or end
        let starts_with_ellipsis = s.starts_with("...");
        let ends_with_ellipsis = s.ends_with("...");

        if starts_with_ellipsis && ends_with_ellipsis {
            return Err("Ellipsis must be either at start or end, not both".to_string());
        }

        if !starts_with_ellipsis && !ends_with_ellipsis {
            return Err("Ellipsis not found".to_string());
        }

        // Count ellipsis occurrences - should be exactly one run
        let ellipsis_count = s.matches("...").count();
        if ellipsis_count > 1 {
            return Err("Only one ellipsis run is allowed".to_string());
        }

        if starts_with_ellipsis {
            // LSB known (ellipsis at start means MSB is unknown)
            let known_part = &s[3..]; // "..." is 3 bytes
            if known_part.is_empty() {
                return Err("Must have some known digits after ellipsis".to_string());
            }
            let known = Integer::from_str_radix(known_part, radix as i32).or(Err(format!(
                "Invalid number in known part (radix {})",
                radix
            )))?;
            Ok(Self(PartialPrime::Partial {
                radix,
                k: None,
                orient: Orientation::LsbKnown,
                known,
            }))
        } else {
            // MSB known (ellipsis at end means LSB is unknown)
            let known_part = &s[..s.len() - 3]; // "..." is 3 bytes
            if known_part.is_empty() {
                return Err("Must have some known digits before ellipsis".to_string());
            }
            let known = Integer::from_str_radix(known_part, radix as i32).or(Err(format!(
                "Invalid number in known part (radix {})",
                radix
            )))?;
            Ok(Self(PartialPrime::Partial {
                radix,
                k: None,
                orient: Orientation::MsbKnown,
                known,
            }))
        }
    }

    fn parse_with_wildcards(s: &str, radix: u32) -> Result<Self, String> {
        // Count leading wildcards (LSB unknown)
        let leading_wildcards = s.chars().take_while(|&c| c == '?').count();
        // Count trailing wildcards (MSB unknown)
        let trailing_wildcards = s.chars().rev().take_while(|&c| c == '?').count();

        if leading_wildcards > 0 && trailing_wildcards > 0 {
            return Err("Wildcards must be either leading or trailing, not both".to_string());
        }

        if leading_wildcards > 0 {
            // LSB known: leading wildcards mean high digits are unknown
            let known_part = &s[leading_wildcards..];
            if known_part.is_empty() {
                return Err("Must have some known digits".to_string());
            }
            if known_part.contains('?') {
                return Err("Wildcards must be contiguous (leading or trailing only)".to_string());
            }
            let known = Integer::from_str_radix(known_part, radix as i32).or(Err(format!(
                "Invalid number in known part (radix {})",
                radix
            )))?;
            Ok(Self(PartialPrime::Partial {
                radix,
                k: Some(leading_wildcards),
                orient: Orientation::LsbKnown,
                known,
            }))
        } else if trailing_wildcards > 0 {
            // MSB known: trailing wildcards mean low digits are unknown
            let known_part = &s[..s.len() - trailing_wildcards];
            if known_part.is_empty() {
                return Err("Must have some known digits".to_string());
            }
            if known_part.contains('?') {
                return Err("Wildcards must be contiguous (leading or trailing only)".to_string());
            }
            let known = Integer::from_str_radix(known_part, radix as i32).or(Err(format!(
                "Invalid number in known part (radix {})",
                radix
            )))?;
            Ok(Self(PartialPrime::Partial {
                radix,
                k: Some(trailing_wildcards),
                orient: Orientation::MsbKnown,
                known,
            }))
        } else {
            // Both are 0 but string contains wildcards - must be non-contiguous
            Err("Wildcards must be contiguous (leading or trailing only)".to_string())
        }
    }
}

/// A single key entry for multi-key attacks
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyEntry {
    /// Cipher message for this key.
    pub c: Option<Integer>,
    /// Modulus.
    pub n: Option<Integer>,
    /// Public exponent.
    pub e: Integer,
}

enum RawValue {
    Integer(Integer),
    PartialPrime(PartialPrime),
}

/// Known parameters
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parameters {
    /// Cipher message.
    pub c: Option<Integer>,
    /// Known most-significant bits of the plaintext.
    pub m_known: Option<Integer>,
    /// Number of unknown least-significant bits in `m_known`.
    pub m_unknown_bits: Option<usize>,
    /// Second ciphertext for the related-message attack.
    pub related_c: Option<Integer>,
    /// Slope of the first affine relation m1 = a1*x + b1.
    pub related_a1: Option<Integer>,
    /// Intercept of the first affine relation.
    pub related_b1: Option<Integer>,
    /// Slope of the second affine relation m2 = a2*x + b2.
    pub related_a2: Option<Integer>,
    /// Intercept of the second affine relation.
    pub related_b2: Option<Integer>,
    /// Modulus.
    pub n: Option<Integer>,
    /// Public exponent.
    pub e: Integer,
    /// Shared pure-enumeration candidate budget; zero disables enumeration.
    pub search_budget: u64,
    /// Prime number p.
    pub p: Option<Integer>,
    /// Prime number q.
    pub q: Option<Integer>,
    /// Private exponent.
    pub d: Option<Integer>,
    /// Known least-significant bits of the private exponent.
    pub partial_d: Option<Integer>,
    /// Number of known least-significant bits in `partial_d`.
    pub partial_d_bits: Option<usize>,
    /// Known most-significant bits of the private exponent.
    pub d_known_msb: Option<Integer>,
    /// Number of unknown least-significant bits in `d_known_msb`.
    pub d_unknown_bits: Option<usize>,
    /// Phi or Euler's totient function of n. (p-1)(q-1)
    pub phi: Option<Integer>,
    /// dP or dmp1 CRT exponent. (d mod p-1)
    pub dp: Option<Integer>,
    /// dQ or dmq1 CRT exponent. (d mod q-1)
    pub dq: Option<Integer>,
    /// qInv or iqmp CRT coefficient. (q^-1 mod p)
    pub qinv: Option<Integer>,
    /// pInv or ipmq CRT coefficient. (p^-1 mod q)
    pub pinv: Option<Integer>,
    /// The sum of the two primes p and q.
    pub sum_pq: Option<Integer>,
    /// The difference of the two primes p and q.
    pub diff_pq: Option<Integer>,
    /// Partial prime p (with wildcards).
    pub partial_p: Option<PartialPrime>,
    /// Partial prime q (with wildcards).
    pub partial_q: Option<PartialPrime>,
    /// Additional keys for multi-key attacks.
    pub keys: Vec<KeyEntry>,
}

impl Default for Parameters {
    fn default() -> Self {
        Self {
            n: None,
            e: 65537.into(),
            search_budget: DEFAULT_SEARCH_BUDGET,
            c: None,
            m_known: None,
            m_unknown_bits: None,
            related_c: None,
            related_a1: None,
            related_b1: None,
            related_a2: None,
            related_b2: None,
            p: None,
            q: None,
            d: None,
            partial_d: None,
            partial_d_bits: None,
            d_known_msb: None,
            d_unknown_bits: None,
            phi: None,
            dp: None,
            dq: None,
            qinv: None,
            pinv: None,
            sum_pq: None,
            diff_pq: None,
            partial_p: None,
            partial_q: None,
            keys: Vec::new(),
        }
    }
}

impl Display for Parameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = String::new();

        if let Some(n) = &self.n {
            s += &format!("n = {n}\n");
        }
        s += &format!("e = {}\n", self.e);
        s += &format!("search_budget = {}\n", self.search_budget);
        if let Some(c) = &self.c {
            s += &format!("c = {c}\n");
        }
        if let Some(m_known) = &self.m_known {
            s += &format!("m_known = {m_known}\n");
        }
        if let Some(m_unknown_bits) = self.m_unknown_bits {
            s += &format!("m_unknown_bits = {m_unknown_bits}\n");
        }
        for (name, value) in [
            ("related_c", &self.related_c),
            ("related_a1", &self.related_a1),
            ("related_b1", &self.related_b1),
            ("related_a2", &self.related_a2),
            ("related_b2", &self.related_b2),
        ] {
            if let Some(value) = value {
                s += &format!("{name} = {value}\n");
            }
        }
        if let Some(p) = &self.p {
            s += &format!("p = {p}\n");
        }
        if let Some(q) = &self.q {
            s += &format!("q = {q}\n");
        }
        if let Some(d) = &self.d {
            s += &format!("d = {d}\n");
        }
        if let Some(partial_d) = &self.partial_d {
            s += &format!("partial_d = {partial_d}\n");
        }
        if let Some(partial_d_bits) = self.partial_d_bits {
            s += &format!("partial_d_bits = {partial_d_bits}\n");
        }
        if let Some(d_known_msb) = &self.d_known_msb {
            s += &format!("d_known_msb = {d_known_msb}\n");
        }
        if let Some(d_unknown_bits) = self.d_unknown_bits {
            s += &format!("d_unknown_bits = {d_unknown_bits}\n");
        }
        if let Some(phi) = &self.phi {
            s += &format!("phi = {phi}\n");
        }
        if let Some(dp) = &self.dp {
            s += &format!("dp = {dp}\n");
        }
        if let Some(dq) = &self.dq {
            s += &format!("dq = {dq}\n");
        }
        if let Some(qinv) = &self.qinv {
            s += &format!("qinv = {qinv}\n");
        }
        if let Some(pinv) = &self.pinv {
            s += &format!("pinv = {pinv}\n");
        }
        if let Some(sum_pq) = &self.sum_pq {
            s += &format!("sum_pq = {sum_pq}\n");
        }
        if let Some(diff_pq) = &self.diff_pq {
            s += &format!("diff_pq = {diff_pq}\n");
        }
        if let Some(partial_p) = &self.partial_p {
            s += &format!("partial_p = {:?}\n", partial_p);
        }
        if let Some(partial_q) = &self.partial_q {
            s += &format!("partial_q = {:?}\n", partial_q);
        }
        if !self.keys.is_empty() {
            s += &format!("keys = {} entries\n", self.keys.len());
            for (i, key) in self.keys.iter().enumerate() {
                s += &format!("  key[{}]: ", i);
                if let Some(n) = &key.n {
                    s += &format!("n={}, ", n);
                }
                s += &format!("e={}", key.e);
                if let Some(c) = &key.c {
                    s += &format!(", c={}", c);
                }
                s += "\n";
            }
        }

        // Remove trailing newline
        if s.ends_with('\n') {
            s.pop();
        }

        write!(f, "{s}")
    }
}

impl Parameters {
    /// Validate paired advanced-MSB fields and their modulus bounds.
    pub fn validate_advanced_inputs(&self) -> Result<(), String> {
        let related_fields = [
            self.related_c.is_some(),
            self.related_a1.is_some(),
            self.related_b1.is_some(),
            self.related_a2.is_some(),
            self.related_b2.is_some(),
        ];
        if related_fields.iter().any(|present| *present)
            && related_fields.iter().any(|present| !present)
        {
            return Err(
                "related_c, related_a1, related_b1, related_a2 and related_b2 must be provided together"
                    .to_string(),
            );
        }
        match (&self.m_known, self.m_unknown_bits) {
            (None, None) => {}
            (Some(_), None) | (None, Some(_)) => {
                return Err("m_known and m_unknown_bits must be provided together".to_string());
            }
            (Some(_), Some(unknown_bits)) => {
                if self
                    .n
                    .as_ref()
                    .is_some_and(|n| unknown_bits > n.significant_bits() as usize)
                {
                    return Err(
                        "m_unknown_bits must not exceed the significant bits of n".to_string()
                    );
                }
            }
        }
        match (&self.d_known_msb, self.d_unknown_bits) {
            (None, None) => Ok(()),
            (Some(_), None) | (None, Some(_)) => {
                Err("d_known_msb and d_unknown_bits must be provided together".to_string())
            }
            (Some(_), Some(unknown_bits)) => {
                if self
                    .n
                    .as_ref()
                    .is_some_and(|n| unknown_bits > n.significant_bits() as usize)
                {
                    Err("d_unknown_bits must not exceed the significant bits of n".to_string())
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Create parameters from raw file
    ///
    /// # Example
    ///
    /// ```text
    /// // Example of a raw file
    /// n = 1
    /// # This is a comment
    /// e: 0x1
    /// C 0x00
    /// phi: 0x1
    ///
    /// // Multi-key support
    /// n1 = 123
    /// e1 = 65537
    /// c1 = 456
    /// n2 = 789
    /// e2 = 3
    /// c2 = 101112
    /// ```
    pub fn from_raw(raw: &str) -> Self {
        let (params, errors) = Self::parse_raw(raw);
        for error in errors {
            eprintln!("Warning: {error}");
        }
        params
    }

    /// Create parameters from raw text, returning field-level parse errors.
    pub fn try_from_raw(raw: &str) -> Result<Self, String> {
        let (params, errors) = Self::parse_raw(raw);
        if errors.is_empty() {
            Ok(params)
        } else {
            Err(errors.join("\n"))
        }
    }

    fn set_prime(full: &mut Option<Integer>, partial: &mut Option<PartialPrime>, value: RawValue) {
        let RawValue::PartialPrime(value) = value else {
            return;
        };
        match value {
            PartialPrime::Full(value) => {
                *full = Some(value);
                *partial = None;
            }
            value => {
                *full = None;
                *partial = Some(value);
            }
        }
    }

    fn derive_known_values(&mut self) {
        if let (Some(p), Some(q)) = (&self.p, &self.q) {
            if self.n.is_none() {
                self.n = Some((p * q).complete());
            }
            if self.phi.is_none() {
                self.phi = Some((p - Integer::from(1)) * (q - Integer::from(1)));
            }
        }
    }

    fn parse_raw(raw: &str) -> (Self, Vec<String>) {
        let mut params = Self::default();
        let mut errors = Vec::new();
        let mut key_entries: std::collections::HashMap<usize, KeyEntry> =
            std::collections::HashMap::new();
        let mut has_main_key = false;

        for (line_index, line) in raw.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }

            let (key, value) = if let Some(idx) = line.find(':') {
                let (key, value) = line.split_at(idx);
                (key.trim(), value[1..].trim())
            } else if let Some(idx) = line.find('=') {
                let (key, value) = line.split_at(idx);
                (key.trim(), value[1..].trim())
            } else {
                continue;
            };

            // Clean up key and check for index suffix (e.g., n1, e2, c10)
            let key_cleaned = key.replace(['_', '-'], "");
            // Affine-relation names end in digits that are part of the field, not key indices.
            let key_lower = key_cleaned.to_lowercase();
            let is_related_field = matches!(
                key_lower.as_str(),
                "relatedc" | "relateda1" | "relatedb1" | "relateda2" | "relatedb2"
            );
            // Parse full numeric suffix at the end of ordinary key names (e.g., n1, e2, c10).
            let mut chars = key_cleaned.chars().rev().peekable();
            let mut digit_str = String::new();
            if !is_related_field {
                while let Some(&c) = chars.peek() {
                    if c.is_ascii_digit() {
                        digit_str.push(c);
                        chars.next();
                    } else {
                        break;
                    }
                }
            }

            let (base_key, index) = if !digit_str.is_empty() {
                // digit_str is reversed, so reverse it back
                let index_str: String = digit_str.chars().rev().collect();
                let base: String = chars.rev().collect();
                if let Ok(idx) = index_str.parse::<usize>() {
                    (base, Some(idx))
                } else {
                    (key_cleaned, None)
                }
            } else {
                (key_cleaned, None)
            };

            let base_key = base_key.to_lowercase();
            let recognized = if index.is_some() {
                matches!(base_key.as_str(), "n" | "e" | "c")
            } else {
                matches!(
                    base_key.as_str(),
                    "n" | "e"
                        | "searchbudget"
                        | "c"
                        | "mknown"
                        | "munknownbits"
                        | "relatedc"
                        | "relateda1"
                        | "relatedb1"
                        | "relateda2"
                        | "relatedb2"
                        | "p"
                        | "q"
                        | "d"
                        | "partiald"
                        | "partialdbits"
                        | "dknownmsb"
                        | "dunknownbits"
                        | "phi"
                        | "dp"
                        | "dmp1"
                        | "dq"
                        | "dmq1"
                        | "qinv"
                        | "iqmp"
                        | "pinv"
                        | "ipmq"
                        | "sumpq"
                        | "diffpq"
                        | "partialp"
                        | "partialq"
                )
            };
            if !recognized {
                errors.push(format!("line {}: unknown field `{key}`", line_index + 1));
                continue;
            }

            let value = if index.is_none()
                && matches!(base_key.as_str(), "p" | "q" | "partialp" | "partialq")
            {
                match PartialPrimeArg::from_str(value) {
                    Ok(value) => RawValue::PartialPrime(value.0),
                    Err(error) => {
                        errors.push(format!(
                            "line {}: invalid value for `{key}`: `{value}` ({error})",
                            line_index + 1
                        ));
                        continue;
                    }
                }
            } else {
                match IntegerArg::from_str(value) {
                    Ok(value) => RawValue::Integer(value.0),
                    Err(error) => {
                        errors.push(format!(
                            "line {}: invalid value for `{key}`: `{value}` ({error})",
                            line_index + 1
                        ));
                        continue;
                    }
                }
            };

            if let Some(idx) = index {
                // This is an indexed key (n1, e1, c1, etc.)
                let entry = key_entries.entry(idx).or_insert_with(|| KeyEntry {
                    n: None,
                    e: 65537.into(),
                    c: None,
                });

                let RawValue::Integer(value) = value else {
                    continue;
                };
                match base_key.as_str() {
                    "n" => entry.n = Some(value),
                    "e" => entry.e = value,
                    "c" => entry.c = Some(value),
                    _ => {}
                }
            } else {
                // This is a regular parameter (n, e, c, etc.)
                match (base_key.as_str(), value) {
                    ("n", RawValue::Integer(value)) => {
                        params.n = Some(value);
                        has_main_key = true;
                    }
                    ("e", RawValue::Integer(value)) => {
                        params.e = value;
                        has_main_key = true;
                    }
                    ("searchbudget", RawValue::Integer(value)) => {
                        if let Some(budget) = value.to_u64() {
                            params.search_budget = budget;
                        } else {
                            errors.push(format!(
                                "line {}: invalid value for `{key}`: `{value}` (must fit in u64)",
                                line_index + 1
                            ));
                        }
                    }
                    ("c", RawValue::Integer(value)) => {
                        params.c = Some(value);
                        has_main_key = true;
                    }
                    ("mknown", RawValue::Integer(value)) => params.m_known = Some(value),
                    ("munknownbits", RawValue::Integer(value)) => {
                        if let Some(bits) = value.to_usize() {
                            params.m_unknown_bits = Some(bits);
                        } else {
                            errors.push(format!(
                                "line {}: invalid value for `{key}`: `{value}` (must fit in usize)",
                                line_index + 1
                            ));
                        }
                    }
                    ("relatedc", RawValue::Integer(value)) => params.related_c = Some(value),
                    ("relateda1", RawValue::Integer(value)) => params.related_a1 = Some(value),
                    ("relatedb1", RawValue::Integer(value)) => params.related_b1 = Some(value),
                    ("relateda2", RawValue::Integer(value)) => params.related_a2 = Some(value),
                    ("relatedb2", RawValue::Integer(value)) => params.related_b2 = Some(value),
                    ("p", value) => Self::set_prime(&mut params.p, &mut params.partial_p, value),
                    ("partialp", value) => {
                        Self::set_prime(&mut params.p, &mut params.partial_p, value)
                    }
                    ("q", value) => Self::set_prime(&mut params.q, &mut params.partial_q, value),
                    ("partialq", value) => {
                        Self::set_prime(&mut params.q, &mut params.partial_q, value)
                    }
                    ("d", RawValue::Integer(value)) => params.d = Some(value),
                    ("partiald", RawValue::Integer(value)) => params.partial_d = Some(value),
                    ("partialdbits", RawValue::Integer(value)) => {
                        params.partial_d_bits = value.to_usize();
                    }
                    ("dknownmsb", RawValue::Integer(value)) => {
                        params.d_known_msb = Some(value);
                    }
                    ("dunknownbits", RawValue::Integer(value)) => {
                        if let Some(bits) = value.to_usize() {
                            params.d_unknown_bits = Some(bits);
                        } else {
                            errors.push(format!(
                                "line {}: invalid value for `{key}`: `{value}` (must fit in usize)",
                                line_index + 1
                            ));
                        }
                    }
                    ("phi", RawValue::Integer(value)) => params.phi = Some(value),
                    ("dp" | "dmp1", RawValue::Integer(value)) => params.dp = Some(value),
                    ("dq" | "dmq1", RawValue::Integer(value)) => params.dq = Some(value),
                    ("qinv" | "iqmp", RawValue::Integer(value)) => params.qinv = Some(value),
                    ("pinv" | "ipmq", RawValue::Integer(value)) => params.pinv = Some(value),
                    ("sumpq", RawValue::Integer(value)) => params.sum_pq = Some(value),
                    ("diffpq", RawValue::Integer(value)) => params.diff_pq = Some(value),
                    _ => {}
                }
            }
        }

        // Convert the HashMap to a sorted Vec
        if !key_entries.is_empty() {
            let mut indices: Vec<_> = key_entries.keys().copied().collect();
            indices.sort();
            params.keys = indices
                .into_iter()
                .filter_map(|i| key_entries.remove(&i))
                .collect();
        }

        // Indexed-only input uses the lowest-indexed key as the main key.
        if !has_main_key {
            let mut entries = std::mem::take(&mut params.keys).into_iter();
            if let Some(first) = entries.next() {
                params.n = first.n;
                params.e = first.e;
                params.c = first.c;
                params.keys = entries.collect();
            }
        }

        params.derive_known_values();
        if let Err(error) = params.validate_advanced_inputs() {
            errors.push(error);
        }

        (params, errors)
    }

    /// Create parameters from public key
    pub fn from_public_key(key: &[u8]) -> Option<Self> {
        Self::from_rsa_public_key(key)
            .or_else(|| Self::from_x509_cert(key))
            .or_else(|| Self::from_openssh_public_key(key))
            .or_else(|| Self::from_x509_csr(key))
            .or_else(|| Self::from_pkcs7(key))
    }

    /// Create parameters from rsa public key
    pub fn from_rsa_public_key(key: &[u8]) -> Option<Self> {
        let public_key = openssl::pkey::PKey::public_key_from_pem(key)
            .or_else(|_| openssl::pkey::PKey::public_key_from_der(key))
            .or_else(|_| {
                // RSA der pkcs1 are not decoded by the `PKey::public_key_from_der` function
                openssl::rsa::Rsa::public_key_from_der_pkcs1(key)
                    .map(|rsa| openssl::pkey::PKey::from_rsa(rsa).unwrap())
            })
            .ok()?;
        let rsa = public_key.rsa().ok()?;

        Some(Self {
            n: Some(Integer::from_digits(
                &rsa.n().to_vec(),
                rug::integer::Order::Msf,
            )),
            e: Integer::from_digits(&rsa.e().to_vec(), rug::integer::Order::Msf),
            ..Default::default()
        })
    }

    /// Create parameters from x509 certificate
    pub fn from_x509_cert(key: &[u8]) -> Option<Self> {
        let cert = openssl::x509::X509::from_pem(key)
            .or_else(|_| openssl::x509::X509::from_der(key))
            .ok()?;
        let rsa = cert.public_key().ok()?.rsa().ok()?;

        Some(Self {
            n: Some(Integer::from_digits(
                &rsa.n().to_vec(),
                rug::integer::Order::Msf,
            )),
            e: Integer::from_digits(&rsa.e().to_vec(), rug::integer::Order::Msf),
            ..Default::default()
        })
    }

    /// Create parameters from openssh public key
    pub fn from_openssh_public_key(key: &[u8]) -> Option<Self> {
        let public_key = ssh_key::public::PublicKey::from_bytes(key)
            .ok()
            .or_else(|| {
                if let Ok(key) = String::from_utf8(key.to_vec()) {
                    ssh_key::public::PublicKey::from_openssh(&key).ok()
                } else {
                    None
                }
            })?;
        let rsa = public_key.key_data().rsa()?;

        Some(Self {
            n: Some(Integer::from_digits(
                rsa.n.as_bytes(),
                rug::integer::Order::Msf,
            )),
            e: Integer::from_digits(rsa.e.as_bytes(), rug::integer::Order::Msf),
            ..Default::default()
        })
    }

    /// Create parameters from x509 certificate signing request (CSR)
    pub fn from_x509_csr(key: &[u8]) -> Option<Self> {
        let req = openssl::x509::X509Req::from_pem(key)
            .or_else(|_| openssl::x509::X509Req::from_der(key))
            .ok()?;
        let rsa = req.public_key().ok()?.rsa().ok()?;

        Some(Self {
            n: Some(Integer::from_digits(
                &rsa.n().to_vec(),
                rug::integer::Order::Msf,
            )),
            e: Integer::from_digits(&rsa.e().to_vec(), rug::integer::Order::Msf),
            ..Default::default()
        })
    }

    /// Create parameters from pkcs7 (.p7b, .p7c) certificate chain
    pub fn from_pkcs7(key: &[u8]) -> Option<Self> {
        let pkcs7 = openssl::pkcs7::Pkcs7::from_pem(key)
            .or_else(|_| openssl::pkcs7::Pkcs7::from_der(key))
            .ok()?;

        // Get signed data from PKCS7
        let signed = pkcs7.signed()?;

        // Get certificates from signed data
        let certs = signed.certificates()?;

        // Try to extract RSA public key from the first certificate
        let cert = certs.get(0)?;
        let rsa = cert.public_key().ok()?.rsa().ok()?;

        Some(Self {
            n: Some(Integer::from_digits(
                &rsa.n().to_vec(),
                rug::integer::Order::Msf,
            )),
            e: Integer::from_digits(&rsa.e().to_vec(), rug::integer::Order::Msf),
            ..Default::default()
        })
    }

    /// Create parameters from private key
    pub fn from_private_key(key: &[u8], passphrase: Option<&str>) -> Option<Self> {
        Self::from_rsa_private_key(key, passphrase)
            .or_else(|| Self::from_openssh_private_key(key, passphrase))
            .or_else(|| Self::from_pkcs12(key, passphrase))
    }

    /// Create parameters from rsa private key
    pub fn from_rsa_private_key(key: &[u8], passphrase: Option<&str>) -> Option<Self> {
        let private_key = openssl::pkey::PKey::private_key_from_der(key)
            .or_else(|_| {
                if let Some(passphrase) = passphrase {
                    openssl::pkey::PKey::private_key_from_pkcs8_passphrase(
                        key,
                        passphrase.as_bytes(),
                    )
                    .or_else(|_| {
                        openssl::pkey::PKey::private_key_from_pem_passphrase(
                            key,
                            passphrase.as_bytes(),
                        )
                    })
                } else {
                    openssl::pkey::PKey::private_key_from_pkcs8(key)
                        .or_else(|_| openssl::pkey::PKey::private_key_from_pem(key))
                }
            })
            .map_err(|e| {
                e.errors().first().map(|e| {
                    if e.reason() == Some("bad decrypt") {
                        panic!("Failed to decrypt private key")
                    }
                })
            })
            .ok()?;
        let rsa = private_key.rsa().ok()?;

        Some(Self {
            n: Some(Integer::from_digits(
                &rsa.n().to_vec(),
                rug::integer::Order::Msf,
            )),
            e: Integer::from_digits(&rsa.e().to_vec(), rug::integer::Order::Msf),
            p: rsa
                .p()
                .map(|n| Integer::from_digits(&n.to_vec(), rug::integer::Order::Msf)),
            q: rsa
                .q()
                .map(|n| Integer::from_digits(&n.to_vec(), rug::integer::Order::Msf)),
            ..Default::default()
        })
    }

    /// Create parameters from openssh private key
    pub fn from_openssh_private_key(key: &[u8], passphrase: Option<&str>) -> Option<Self> {
        let mut private_key = ssh_key::private::PrivateKey::from_openssh(key)
            .or_else(|_| ssh_key::private::PrivateKey::from_bytes(key))
            .ok()?;
        let rsa = if private_key.key_data().is_encrypted() {
            if let Some(passphrase) = passphrase {
                private_key = private_key
                    .decrypt(passphrase)
                    .expect("Failed to decrypt private key");
                private_key.key_data().rsa()?
            } else {
                eprintln!("Warning: Private key is encrypted, but no passphrase was provided, only n and e will be extracted");
                let public_rsa = private_key.public_key().key_data().rsa()?;
                return Some(Self {
                    n: Some(Integer::from_digits(
                        public_rsa.n.as_bytes(),
                        rug::integer::Order::Msf,
                    )),
                    e: Integer::from_digits(public_rsa.e.as_bytes(), rug::integer::Order::Msf),
                    ..Default::default()
                });
            }
        } else {
            private_key.key_data().rsa()?
        };

        Some(Self {
            n: Some(Integer::from_digits(
                rsa.public.n.as_bytes(),
                rug::integer::Order::Msf,
            )),
            e: Integer::from_digits(rsa.public.e.as_bytes(), rug::integer::Order::Msf),
            p: Some(Integer::from_digits(
                rsa.private.p.as_bytes(),
                rug::integer::Order::Msf,
            )),
            q: Some(Integer::from_digits(
                rsa.private.q.as_bytes(),
                rug::integer::Order::Msf,
            )),
            ..Default::default()
        })
    }

    /// Create parameters from pkcs12 (.p12, .pfx) format
    pub fn from_pkcs12(key: &[u8], passphrase: Option<&str>) -> Option<Self> {
        let pkcs12 = openssl::pkcs12::Pkcs12::from_der(key).ok()?;
        let parsed = pkcs12
            .parse2(passphrase.unwrap_or(""))
            .map_err(|e| {
                e.errors().first().map(|e| {
                    if e.reason() == Some("bad decrypt") || e.reason() == Some("mac verify failure")
                    {
                        panic!("Failed to decrypt PKCS#12: incorrect password")
                    }
                })
            })
            .ok()?;

        // Try to extract RSA key from private key
        if let Some(pkey) = parsed.pkey {
            if let Ok(rsa) = pkey.rsa() {
                return Some(Self {
                    n: Some(Integer::from_digits(
                        &rsa.n().to_vec(),
                        rug::integer::Order::Msf,
                    )),
                    e: Integer::from_digits(&rsa.e().to_vec(), rug::integer::Order::Msf),
                    p: rsa
                        .p()
                        .map(|n| Integer::from_digits(&n.to_vec(), rug::integer::Order::Msf)),
                    q: rsa
                        .q()
                        .map(|n| Integer::from_digits(&n.to_vec(), rug::integer::Order::Msf)),
                    ..Default::default()
                });
            }
        }

        // If private key is not available, try to extract public key from certificate
        if let Some(cert) = parsed.cert {
            if let Ok(pkey) = cert.public_key() {
                if let Ok(rsa) = pkey.rsa() {
                    return Some(Self {
                        n: Some(Integer::from_digits(
                            &rsa.n().to_vec(),
                            rug::integer::Order::Msf,
                        )),
                        e: Integer::from_digits(&rsa.e().to_vec(), rug::integer::Order::Msf),
                        ..Default::default()
                    });
                }
            }
        }

        None
    }
}

impl Add for Parameters {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut out = self;
        out += rhs;
        out
    }
}

impl<'a> Add<&'a Parameters> for Parameters {
    type Output = Self;

    fn add(mut self, rhs: &'a Parameters) -> Self::Output {
        self += rhs.clone();
        self
    }
}

impl AddAssign for Parameters {
    fn add_assign(&mut self, rhs: Self) {
        if self.n.is_none() {
            self.n = rhs.n;
        }
        if self.e == 65537 {
            self.e = rhs.e;
        }
        if self.search_budget == DEFAULT_SEARCH_BUDGET {
            self.search_budget = rhs.search_budget;
        }
        if self.c.is_none() {
            self.c = rhs.c;
        }
        if self.m_known.is_none() {
            self.m_known = rhs.m_known;
        }
        if self.m_unknown_bits.is_none() {
            self.m_unknown_bits = rhs.m_unknown_bits;
        }
        if self.related_c.is_none() {
            self.related_c = rhs.related_c;
        }
        if self.related_a1.is_none() {
            self.related_a1 = rhs.related_a1;
        }
        if self.related_b1.is_none() {
            self.related_b1 = rhs.related_b1;
        }
        if self.related_a2.is_none() {
            self.related_a2 = rhs.related_a2;
        }
        if self.related_b2.is_none() {
            self.related_b2 = rhs.related_b2;
        }
        if self.p.is_none() {
            self.p = rhs.p;
        }
        if self.q.is_none() {
            self.q = rhs.q;
        }
        if self.d.is_none() {
            self.d = rhs.d;
        }
        if self.partial_d.is_none() {
            self.partial_d = rhs.partial_d;
        }
        if self.partial_d_bits.is_none() {
            self.partial_d_bits = rhs.partial_d_bits;
        }
        if self.d_known_msb.is_none() {
            self.d_known_msb = rhs.d_known_msb;
        }
        if self.d_unknown_bits.is_none() {
            self.d_unknown_bits = rhs.d_unknown_bits;
        }
        if self.phi.is_none() {
            self.phi = rhs.phi;
        }
        if self.dp.is_none() {
            self.dp = rhs.dp;
        }
        if self.dq.is_none() {
            self.dq = rhs.dq;
        }
        if self.qinv.is_none() {
            self.qinv = rhs.qinv;
        }
        if self.pinv.is_none() {
            self.pinv = rhs.pinv;
        }
        if self.sum_pq.is_none() {
            self.sum_pq = rhs.sum_pq;
        }
        if self.diff_pq.is_none() {
            self.diff_pq = rhs.diff_pq;
        }
        if self.partial_p.is_none() {
            self.partial_p = rhs.partial_p;
        }
        if self.partial_q.is_none() {
            self.partial_q = rhs.partial_q;
        }
        // Extend keys vector with new keys
        self.keys.extend(rhs.keys);
        self.derive_known_values();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_parses_search_budget_and_display_round_trips() {
        let params = Parameters::try_from_raw("n = 3233\nsearch_budget = 0\n").unwrap();
        assert_eq!(params.search_budget, 0);
        assert!(params.to_string().contains("search_budget = 0"));
    }

    #[test]
    fn raw_parses_message_msb_fields() {
        let params =
            Parameters::try_from_raw("n = 3233\nm_known = 21\nm_unknown_bits = 1\n").unwrap();
        assert_eq!(params.m_known, Some(21.into()));
        assert_eq!(params.m_unknown_bits, Some(1));
        assert!(params.to_string().contains("m_unknown_bits = 1"));
    }

    #[test]
    fn raw_parses_franklin_reiter_fields() {
        let params = Parameters::try_from_raw(
            "n = 3233\nrelated_c = 1411\nrelated_a1 = 2\nrelated_b1 = 3\nrelated_a2 = 3\nrelated_b2 = 5\n",
        )
        .unwrap();
        assert_eq!(params.related_c, Some(1411.into()));
        assert_eq!(params.related_a1, Some(2.into()));
        assert_eq!(params.related_b1, Some(3.into()));
        assert_eq!(params.related_a2, Some(3.into()));
        assert_eq!(params.related_b2, Some(5.into()));
    }

    #[test]
    fn raw_parses_uppercase_franklin_reiter_fields() {
        let params = Parameters::try_from_raw(
            "n = 3233\nRELATED_C = 1411\nRELATED_A1 = 2\nRELATED_B1 = 3\nRELATED_A2 = 3\nRELATED_B2 = 5\n",
        )
        .unwrap();
        assert_eq!(params.related_c, Some(1411.into()));
        assert_eq!(params.related_a1, Some(2.into()));
        assert_eq!(params.related_b1, Some(3.into()));
        assert_eq!(params.related_a2, Some(3.into()));
        assert_eq!(params.related_b2, Some(5.into()));
        assert!(params.keys.is_empty());
    }

    #[test]
    fn franklin_reiter_fields_must_be_provided_together() {
        for field in [
            "related_c",
            "related_a1",
            "related_b1",
            "related_a2",
            "related_b2",
        ] {
            let mut raw = "n = 3233\n".to_string();
            for other in [
                "related_c",
                "related_a1",
                "related_b1",
                "related_a2",
                "related_b2",
            ] {
                if other != field {
                    raw.push_str(&format!("{other} = 1\n"));
                }
            }
            let error = Parameters::try_from_raw(&raw).unwrap_err();
            assert!(error.contains("must be provided together"), "{error}");
        }
    }

    #[test]
    fn related_c_is_independent_of_indexed_c2() {
        let params = Parameters::try_from_raw(
            "n = 3233\nc = 1680\nc2 = 999\nrelated_c = 1411\nrelated_a1 = 2\nrelated_b1 = 3\nrelated_a2 = 3\nrelated_b2 = 5\n",
        )
        .unwrap();
        assert_eq!(params.c, Some(1680.into()));
        assert_eq!(params.related_c, Some(1411.into()));
        assert_eq!(params.keys[0].c, Some(999.into()));
    }

    #[test]
    fn message_msb_fields_must_be_paired() {
        let error = Parameters::try_from_raw("n = 3233\nm_known = 21\n").unwrap_err();
        assert!(error.contains("m_known"));
        assert!(error.contains("m_unknown_bits"));
    }

    #[test]
    fn message_msb_unknown_bits_must_not_exceed_modulus() {
        let error =
            Parameters::try_from_raw("n = 3233\nm_known = 21\nm_unknown_bits = 13\n").unwrap_err();
        assert!(error.contains("m_unknown_bits"));
    }

    #[test]
    fn message_msb_unknown_bits_rejects_non_usize() {
        let error = Parameters::try_from_raw(
            "n = 3233\nm_known = 21\nm_unknown_bits = 18446744073709551616\n",
        )
        .unwrap_err();
        assert!(error.contains("m_unknown_bits"));
        assert!(error.contains("usize"));
    }

    #[test]
    fn message_msb_fields_merge_without_overwriting() {
        let mut params = Parameters::default();
        params += Parameters::try_from_raw("n = 3233\nm_known = 21\nm_unknown_bits = 1\n").unwrap();
        params += Parameters::default();

        assert_eq!(params.m_known, Some(21.into()));
        assert_eq!(params.m_unknown_bits, Some(1));
    }

    #[test]
    fn raw_parses_d_msb_fields_and_display_round_trips() {
        let params =
            Parameters::try_from_raw("n = 3233\nd_known_msb = 171\nd_unknown_bits = 4\n").unwrap();
        let displayed = params.to_string();

        assert_eq!(params.d_known_msb, Some(171.into()));
        assert_eq!(params.d_unknown_bits, Some(4));
        assert!(displayed.contains("d_known_msb = 171"));
        assert!(displayed.contains("d_unknown_bits = 4"));
    }

    #[test]
    fn d_msb_fields_must_be_paired() {
        for raw in [
            "n = 3233\nd_known_msb = 171\n",
            "n = 3233\nd_unknown_bits = 4\n",
        ] {
            let error = Parameters::try_from_raw(raw).unwrap_err();
            assert!(error.contains("d_known_msb"));
            assert!(error.contains("d_unknown_bits"));
        }
    }

    #[test]
    fn d_msb_unknown_bits_must_not_exceed_modulus() {
        let error = Parameters::try_from_raw("n = 3233\nd_known_msb = 171\nd_unknown_bits = 13\n")
            .unwrap_err();
        assert!(error.contains("d_unknown_bits"));
    }

    #[test]
    fn d_msb_unknown_bits_rejects_non_usize() {
        let error = Parameters::try_from_raw(
            "n = 3233\nd_known_msb = 171\nd_unknown_bits = 18446744073709551616\n",
        )
        .unwrap_err();
        assert!(error.contains("d_unknown_bits"));
        assert!(error.contains("usize"));
    }

    #[test]
    fn d_msb_fields_merge_without_overwriting() {
        let mut params = Parameters::default();
        params +=
            Parameters::try_from_raw("n = 3233\nd_known_msb = 171\nd_unknown_bits = 4\n").unwrap();
        params += Parameters::try_from_raw("d_known_msb = 170\nd_unknown_bits = 5\n").unwrap();
        params += Parameters::default();

        assert_eq!(params.d_known_msb, Some(171.into()));
        assert_eq!(params.d_unknown_bits, Some(4));
    }

    #[test]
    fn raw_rejects_search_budget_above_u64() {
        let error = Parameters::try_from_raw("n = 3233\nsearch_budget = 18446744073709551616\n")
            .unwrap_err();
        assert!(error.contains("search_budget"));
    }

    #[test]
    fn merging_default_params_preserves_custom_search_budget() {
        let mut params = Parameters::try_from_raw("n = 3233\nsearch_budget = 0\n").unwrap();
        params += Parameters::default();
        assert_eq!(params.search_budget, 0);
    }

    #[test]
    fn raw_derives_modulus_from_known_primes() {
        let params = Parameters::from_raw("p = 61\nq = 53\nc = 2790\n");
        assert_eq!(params.p, Some(Integer::from(61)));
        assert_eq!(params.q, Some(Integer::from(53)));
        assert_eq!(params.n, Some(Integer::from(61 * 53)));
    }

    #[test]
    fn raw_derives_phi_from_known_primes() {
        let params = Parameters::from_raw("p = 61\nq = 53\n");
        assert_eq!(params.phi, Some(Integer::from(60 * 52)));
    }

    #[test]
    fn merging_known_primes_derives_modulus_and_phi() {
        let mut params = Parameters::default();
        params += Parameters {
            p: Some(Integer::from(61)),
            q: Some(Integer::from(53)),
            ..Default::default()
        };

        assert_eq!(params.n, Some(Integer::from(3233)));
        assert_eq!(params.phi, Some(Integer::from(3120)));
    }

    #[test]
    fn strict_raw_parser_reports_invalid_field() {
        let error = Parameters::try_from_raw("# comment\nn = invalid\n").unwrap_err();
        assert!(error.contains("n"));
        assert!(error.contains("invalid"));
    }

    #[test]
    fn strict_raw_parser_rejects_unknown_field() {
        let error = Parameters::try_from_raw("n = 3233\nmodulu = 3233\n").unwrap_err();
        assert!(error.contains("modulu"));
        assert!(error.contains("unknown field"));
    }

    #[test]
    fn raw_parses_partial_primes() {
        let params = Parameters::try_from_raw("n = 3233\np = 0x3d??\nq = 0x...35\n").unwrap();

        assert!(matches!(
            params.partial_p,
            Some(PartialPrime::Partial {
                radix: 16,
                k: Some(2),
                orient: Orientation::MsbKnown,
                ..
            })
        ));
        assert!(matches!(
            params.partial_q,
            Some(PartialPrime::Partial {
                radix: 16,
                k: None,
                orient: Orientation::LsbKnown,
                ..
            })
        ));
    }

    #[test]
    fn raw_parses_explicit_partial_prime_fields() {
        let params =
            Parameters::try_from_raw("n = 3233\npartial_p = 0x3d??\npartial_q = 0x...35\n")
                .unwrap();

        assert!(params.partial_p.is_some());
        assert!(params.partial_q.is_some());
        assert!(params.p.is_none());
        assert!(params.q.is_none());
    }

    #[test]
    fn raw_parses_partial_d_fields() {
        let params =
            Parameters::try_from_raw("n = 3233\ne = 17\npartial_d = 5\npartial_d_bits = 4\n")
                .unwrap();
        let displayed = params.to_string();

        assert!(displayed.contains("partial_d = 5"));
        assert!(displayed.contains("partial_d_bits = 4"));
    }

    #[test]
    fn strict_raw_parser_accepts_whitespace_and_comments() {
        let params = Parameters::try_from_raw(
            "  # comment\n p : 0x3d \n // another comment\nq=0o65\nc = 284\n",
        )
        .unwrap();
        assert_eq!(params.p, Some(Integer::from(61)));
        assert_eq!(params.q, Some(Integer::from(53)));
        assert_eq!(params.n, Some(Integer::from(61 * 53)));
    }

    #[test]
    fn parse_full_prime() {
        let arg = PartialPrimeArg::from_str("0xDEADBEEF").unwrap();
        match arg.0 {
            PartialPrime::Full(n) => {
                assert_eq!(n, Integer::from(0xDEADBEEFu64));
            }
            _ => panic!("Expected Full"),
        }
    }

    #[test]
    fn parse_msb_known_question_marks() {
        let arg = PartialPrimeArg::from_str("0xDEADBEEF????").unwrap();
        match arg.0 {
            PartialPrime::Partial {
                radix,
                k,
                orient,
                known,
            } => {
                assert_eq!(radix, 16);
                assert_eq!(k, Some(4)); // 4 hex digits
                assert!(matches!(orient, Orientation::MsbKnown));
                assert_eq!(known, Integer::from(0xDEADBEEFu64));
            }
            _ => panic!("Expected Partial with MsbKnown"),
        }
    }

    #[test]
    fn parse_lsb_known_question_marks() {
        let arg = PartialPrimeArg::from_str("0x????C0FFEE").unwrap();
        match arg.0 {
            PartialPrime::Partial {
                radix,
                k,
                orient,
                known,
            } => {
                assert_eq!(radix, 16);
                assert_eq!(k, Some(4)); // 4 hex digits
                assert!(matches!(orient, Orientation::LsbKnown));
                assert_eq!(known, Integer::from(0xC0FFEEu64));
            }
            _ => panic!("Expected Partial with LsbKnown"),
        }
    }

    #[test]
    fn parse_decimal_msb_known() {
        let arg = PartialPrimeArg::from_str("12345????").unwrap();
        match arg.0 {
            PartialPrime::Partial {
                radix,
                k,
                orient,
                known,
            } => {
                assert_eq!(radix, 10);
                assert_eq!(k, Some(4)); // 4 decimal digits
                assert!(matches!(orient, Orientation::MsbKnown));
                assert_eq!(known, Integer::from(12345));
            }
            _ => panic!("Expected Partial with MsbKnown"),
        }
    }

    #[test]
    fn parse_decimal_lsb_known() {
        let arg = PartialPrimeArg::from_str("????6789").unwrap();
        match arg.0 {
            PartialPrime::Partial {
                radix,
                k,
                orient,
                known,
            } => {
                assert_eq!(radix, 10);
                assert_eq!(k, Some(4)); // 4 decimal digits
                assert!(matches!(orient, Orientation::LsbKnown));
                assert_eq!(known, Integer::from(6789));
            }
            _ => panic!("Expected Partial with LsbKnown"),
        }
    }

    #[test]
    fn parse_both_wildcards_error() {
        let result = PartialPrimeArg::from_str("0x????DEAD????");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("both"));
    }

    #[test]
    fn parse_non_contiguous_wildcards_error() {
        let result = PartialPrimeArg::from_str("0xDE??AD??EF");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("contiguous"));
    }

    #[test]
    fn parse_ellipsis_lsb_known() {
        // Test ASCII ellipsis
        let arg = PartialPrimeArg::from_str("0x...C0FFEE").unwrap();
        match arg.0 {
            PartialPrime::Partial {
                radix,
                k,
                orient,
                known,
            } => {
                assert_eq!(radix, 16);
                assert_eq!(k, None);
                assert!(matches!(orient, Orientation::LsbKnown));
                assert_eq!(known, Integer::from(0xC0FFEEu64));
            }
            _ => panic!("Expected Partial with LsbKnown and k=None"),
        }
    }

    #[test]
    fn parse_ellipsis_msb_known() {
        // Test ASCII ellipsis
        let arg = PartialPrimeArg::from_str("0xDEADBEEF...").unwrap();
        match arg.0 {
            PartialPrime::Partial {
                radix,
                k,
                orient,
                known,
            } => {
                assert_eq!(radix, 16);
                assert_eq!(k, None);
                assert!(matches!(orient, Orientation::MsbKnown));
                assert_eq!(known, Integer::from(0xDEADBEEFu64));
            }
            _ => panic!("Expected Partial with MsbKnown and k=None"),
        }
    }

    #[test]
    fn parse_ellipsis_both_error() {
        let result = PartialPrimeArg::from_str("0x...DEAD...");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("both"));
    }

    #[test]
    fn parse_mixed_wildcards_ellipsis_error() {
        let result = PartialPrimeArg::from_str("0x...C0FF??");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("mix"));
    }
}
