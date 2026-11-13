//! Targeting rules: an ordered list of `if condition, send the visitor to
//! url`, decided the same way at the origin and the edge.
//!
//! # Grammar
//!
//! A rule list is JSON. Each rule has a condition under `if` and a
//! destination under `url`; the first rule whose condition holds wins, and
//! when none does the link's own destinations apply.
//!
//! ```json
//! [
//!   {"if": {"all": [{"country": ["US", "CA"]}, {"os": ["ios"]}]},
//!    "url": "https://apps.apple.com/app/id1"},
//!   {"if": {"any": [{"language": ["de"]}, {"region": ["CH-ZH"]}]},
//!    "url": "https://example.com/de"},
//!   {"if": {"not": {"time": {"days": ["sat", "sun"], "hours": ["09:00", "17:00"],
//!                            "utc_offset_minutes": -300}}},
//!    "url": "https://example.com/closed"},
//!   {"if": {"query": {"name": "utm_source", "values": ["newsletter"]}},
//!    "url": "https://example.com/welcome"}
//! ]
//! ```
//!
//! Conditions combine with `all`, `any` and `not`. The leaves are:
//!
//! | Leaf | Holds when |
//! |---|---|
//! | `country` | the visitor's country (ISO 3166-1 alpha-2, from the trusted header) is listed |
//! | `region` | the visitor's subdivision, written `CC-SUB` as in ISO 3166-2 (`US-CA`), is listed |
//! | `device` | the device class ([`crate::classify::device_class`]) is listed |
//! | `os` | the operating system family ([`crate::classify::os_family`]) is listed |
//! | `browser` | the browser family ([`crate::classify::browser_family`]) is listed |
//! | `language` | the most preferred Accept-Language tag is a listed tag or a more specific form of one (`en` matches `en-GB`) |
//! | `referrer` | the Referer host is a listed host or a subdomain of one |
//! | `time` | the time is in `[after, before)`, on one of `days` and within `hours` (`["22:00", "06:00"]` wraps midnight), days and hours read at `utc_offset_minutes` |
//! | `query` | the query parameter `name` is present, or with `values`, has one of them (compared after percent-decoding) |
//!
//! An unknown visitor attribute (no country header, no Referer) never
//! matches a list, so `{"not": {"country": ["US"]}}` holds for it.
//!
//! # Compilation and the bound
//!
//! [`compile`] validates a rule list and turns it into a flat decision list:
//! one [`Step`] per leaf, each naming the step to go to when the leaf holds
//! and when it does not. `all`, `any` and `not` disappear into those jumps
//! (`not` swaps them), so evaluation short-circuits exactly like the tree,
//! keeps no stack and never revisits a step. Every jump goes forward, so a
//! visit tests at most as many leaves as the list has, and a list may have
//! at most [`MAX_CONDITIONS`] (64) across all its rules. Each leaf test is
//! itself bounded: value lists are sorted for binary search or capped, the
//! User-Agent and Accept-Language reads stop at 512 bytes and query strings
//! at [`MAX_QUERY_PARAMS`] parameters within [`MAX_QUERY_BYTES`].
//!
//! The request facts a leaf needs (a User-Agent classification, the
//! referrer host, the parsed query) are computed once per visit and only if
//! some leaf in the list reads them.
//!
//! Like everything in this crate there is no I/O, clock or allocator-hungry
//! work here: the caller passes the time in, and the module builds for
//! `wasm32-unknown-unknown`.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::classify::{
    Browser, Device, Os, browser_family, device_class, is_language_tag, os_family,
    preferred_language, referrer_host,
};
use crate::destination::{Policy, normalize};
use crate::host::is_valid_hostname;

/// Most leaf conditions in one rule list, over all its rules. This is the
/// evaluation bound: no visit tests more leaves than this.
pub const MAX_CONDITIONS: usize = 64;

/// Most rules on one link.
pub const MAX_RULES: usize = 32;

/// Deepest nesting of `all`, `any` and `not`.
pub const MAX_DEPTH: usize = 8;

/// Most values in one leaf's list (the number of countries there are,
/// near enough).
pub const MAX_VALUES: usize = 300;

/// Longest query parameter name or value in a rule, in bytes.
pub const MAX_QUERY_VALUE_LEN: usize = 256;

/// Query parameters read from a request, and the bytes of query string they
/// must lie within. Parameters past either limit are not seen by rules.
pub const MAX_QUERY_PARAMS: usize = 64;
pub const MAX_QUERY_BYTES: usize = 2048;

/// Widest `utc_offset_minutes` (UTC-14:00 to UTC+14:00).
pub const MAX_UTC_OFFSET_MINUTES: i32 = 14 * 60;

// ---------------------------------------------------------------- grammar

/// One rule as written in the API and stored: a condition and where it
/// sends the visitor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    #[serde(rename = "if")]
    pub condition: Condition,
    pub url: String,
}

/// A condition tree. Serialised externally tagged: `{"country": ["US"]}`,
/// `{"all": [...]}`, `{"not": {...}}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Condition {
    All(Vec<Condition>),
    Any(Vec<Condition>),
    Not(Box<Condition>),
    Country(Vec<String>),
    Region(Vec<String>),
    Device(Vec<String>),
    Os(Vec<String>),
    Browser(Vec<String>),
    Language(Vec<String>),
    Referrer(Vec<String>),
    Time(TimeWindow),
    Query(QueryMatch),
}

/// A time condition. Every part given must hold; at least one is required.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeWindow {
    /// Holds from this instant on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<DateTime<Utc>>,
    /// Holds until just before this instant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<DateTime<Utc>>,
    /// Days of the week (`mon` to `sun`) in local time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub days: Option<Vec<String>>,
    /// `["HH:MM", "HH:MM"]` in local time, start included and end not;
    /// `24:00` may end a window. An end before the start wraps midnight.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hours: Option<[String; 2]>,
    /// Local time for `days` and `hours`, as minutes east of UTC.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub utc_offset_minutes: i32,
}

fn is_zero(v: &i32) -> bool {
    *v == 0
}

/// A query parameter condition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryMatch {
    pub name: String,
    /// Without values, the parameter only has to be present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

/// Why a rule list was refused, with the JSON path of the part at fault
/// (`rules[1].if.all[0].country[2]`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleError {
    pub path: String,
    pub reason: String,
}

impl fmt::Display for RuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.reason)
    }
}

impl std::error::Error for RuleError {}

fn fail<T>(path: &str, reason: impl Into<String>) -> Result<T, RuleError> {
    Err(RuleError {
        path: path.to_owned(),
        reason: reason.into(),
    })
}

// ---------------------------------------------------------------- request

/// The request facts rules can read. Header values are raw bytes as
/// received; the caller only passes the time and the trusted geo headers.
#[derive(Clone, Copy, Debug, Default)]
pub struct Request<'a> {
    pub now_ms: i64,
    /// Two-letter country from a trusted header, if any.
    pub country: Option<[u8; 2]>,
    /// The subdivision part of the visitor's ISO 3166-2 region (`CA` for
    /// `US-CA`) from a trusted header, if any.
    pub region: Option<&'a [u8]>,
    pub user_agent: Option<&'a [u8]>,
    pub accept_language: Option<&'a [u8]>,
    pub referer: Option<&'a [u8]>,
    /// The query string without the `?`.
    pub query: Option<&'a [u8]>,
}

// ---------------------------------------------------------------- compiled

/// Where a step goes next.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Jump {
    /// Test the step at this index, always greater than the current one.
    Step(u8),
    /// The rule at this index matched.
    Rule(u8),
    /// No rule matched.
    Default,
}

/// One leaf test and where to go after it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    test: Test,
    pub on_true: Jump,
    pub on_false: Jump,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Test {
    /// Sorted, for binary search.
    Country(Box<[[u8; 2]]>),
    /// Sorted `(country, subdivision)` pairs, subdivision uppercase.
    Region(Box<[([u8; 2], Box<str>)]>),
    /// Bit sets indexed by the enums' `ALL` order.
    Device(u8),
    Os(u8),
    Browser(u8),
    /// Lowercase tags.
    Language(Box<[Box<str>]>),
    /// Lowercase hosts.
    Referrer(Box<[Box<str>]>),
    Time(Window),
    Query {
        name: Box<[u8]>,
        values: Option<Box<[Box<[u8]>]>>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Window {
    after_ms: Option<i64>,
    before_ms: Option<i64>,
    /// Bit 0 is Monday.
    days: Option<u8>,
    /// Minutes of the day, start included, end excluded.
    minutes: Option<(u16, u16)>,
    offset_ms: i64,
}

const NEEDS_DEVICE: u8 = 1;
const NEEDS_OS: u8 = 2;
const NEEDS_BROWSER: u8 = 4;
const NEEDS_LANGUAGE: u8 = 8;
const NEEDS_REFERRER: u8 = 16;
const NEEDS_QUERY: u8 = 32;

impl Test {
    fn needs(&self) -> u8 {
        match self {
            Test::Device(_) => NEEDS_DEVICE,
            Test::Os(_) => NEEDS_OS,
            Test::Browser(_) => NEEDS_BROWSER,
            Test::Language(_) => NEEDS_LANGUAGE,
            Test::Referrer(_) => NEEDS_REFERRER,
            Test::Query { .. } => NEEDS_QUERY,
            Test::Country(_) | Test::Region(_) | Test::Time(_) => 0,
        }
    }
}

/// A validated rule list in the form evaluation runs: the flat decision
/// list and each rule's normalised destination.
///
/// It serialises as `{"steps": [...], "urls": [...]}`, the form published
/// to the edge, and deserialising checks everything evaluation relies on
/// (see [`Rules::check`]), so a record that would not compile to this
/// cannot be loaded.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Program", into = "Program")]
pub struct Rules {
    steps: Vec<Step>,
    urls: Vec<String>,
    needs: u8,
}

impl Rules {
    /// The decision list, in evaluation order.
    pub fn steps(&self) -> &[Step] {
        &self.steps
    }

    /// Each rule's destination, normalised like a link destination.
    pub fn urls(&self) -> &[String] {
        &self.urls
    }

    pub fn is_empty(&self) -> bool {
        self.urls.is_empty()
    }

    /// The first rule whose condition holds for `req`, by index.
    pub fn evaluate(&self, req: &Request<'_>) -> Option<usize> {
        self.evaluate_counted(req).0
    }

    /// The matching rule's destination, if any rule matches.
    pub fn destination(&self, req: &Request<'_>) -> Option<&str> {
        self.evaluate(req).map(|i| self.urls[i].as_str())
    }

    /// [`Rules::evaluate`], also returning how many leaves were tested.
    pub fn evaluate_counted(&self, req: &Request<'_>) -> (Option<usize>, usize) {
        if self.steps.is_empty() {
            return (None, 0);
        }
        let facts = Facts::gather(req, self.needs);
        let mut at = 0;
        let mut tested = 0;
        loop {
            let step = &self.steps[at];
            tested += 1;
            let next = if facts.test(&step.test) {
                step.on_true
            } else {
                step.on_false
            };
            match next {
                Jump::Step(i) => at = usize::from(i),
                Jump::Rule(r) => return (Some(usize::from(r)), tested),
                Jump::Default => return (None, tested),
            }
        }
    }
}

/// The serialised form of [`Rules`].
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Program {
    steps: Vec<Step>,
    urls: Vec<String>,
}

impl From<Rules> for Program {
    fn from(r: Rules) -> Program {
        Program {
            steps: r.steps,
            urls: r.urls,
        }
    }
}

impl TryFrom<Program> for Rules {
    type Error = &'static str;
    fn try_from(p: Program) -> Result<Rules, &'static str> {
        Rules::check(p.steps, p.urls)
    }
}

impl Rules {
    /// A decision list from outside the compiler, refused unless it keeps
    /// the promises [`compile`] makes: at most [`MAX_CONDITIONS`] steps and
    /// [`MAX_RULES`] rules, every jump forward and in range, value lists
    /// within [`MAX_VALUES`] and country lists sorted for binary search.
    fn check(steps: Vec<Step>, urls: Vec<String>) -> Result<Rules, &'static str> {
        if steps.len() > MAX_CONDITIONS || urls.len() > MAX_RULES {
            return Err("too many steps or rules");
        }
        for (i, step) in steps.iter().enumerate() {
            for jump in [step.on_true, step.on_false] {
                let ok = match jump {
                    Jump::Step(j) => usize::from(j) > i && usize::from(j) < steps.len(),
                    Jump::Rule(r) => usize::from(r) < urls.len(),
                    Jump::Default => true,
                };
                if !ok {
                    return Err("a jump goes backward or out of range");
                }
            }
            let values = match &step.test {
                Test::Country(list) => {
                    if !list.is_sorted() {
                        return Err("a country list is not sorted");
                    }
                    list.len()
                }
                Test::Region(list) => list.len(),
                Test::Language(list) | Test::Referrer(list) => list.len(),
                Test::Query { values, .. } => values.as_ref().map_or(0, |v| v.len()),
                Test::Device(_) | Test::Os(_) | Test::Browser(_) | Test::Time(_) => 0,
            };
            if values > MAX_VALUES {
                return Err("a value list is too long");
            }
        }
        let needs = steps.iter().fold(0, |n, s| n | s.test.needs());
        Ok(Rules { steps, urls, needs })
    }
}

// ---------------------------------------------------------------- compiler

/// A validated condition tree, before it is flattened.
enum Node {
    All(Vec<Node>),
    Any(Vec<Node>),
    Not(Box<Node>),
    Leaf(Test),
}

impl Node {
    fn leaves(&self) -> usize {
        match self {
            Node::All(c) | Node::Any(c) => c.iter().map(Node::leaves).sum(),
            Node::Not(c) => c.leaves(),
            Node::Leaf(_) => 1,
        }
    }
}

/// Validates `rules` and compiles them. Destinations are normalised under
/// `policy`, as link destinations are.
pub fn compile(rules: &[Rule], policy: Policy) -> Result<Rules, RuleError> {
    build(rules, |url| {
        normalize(url, policy).map_err(|e| e.to_string())
    })
}

/// Compiles `rules` with each destination taken as given: what [`compile`]
/// does with `normalize` replaced by `url`.
fn build(rules: &[Rule], url: impl Fn(&str) -> Result<String, String>) -> Result<Rules, RuleError> {
    if rules.len() > MAX_RULES {
        return fail("rules", format!("at most {MAX_RULES} rules"));
    }
    let mut trees = Vec::with_capacity(rules.len());
    let mut urls = Vec::with_capacity(rules.len());
    let mut total = 0;
    for (i, rule) in rules.iter().enumerate() {
        let path = format!("rules[{i}]");
        let url = url(&rule.url).map_err(|reason| RuleError {
            path: format!("{path}.url"),
            reason,
        })?;
        let tree = check(&rule.condition, &format!("{path}.if"), 0)?;
        total += tree.leaves();
        if total > MAX_CONDITIONS {
            return fail(
                &path,
                format!("rules may hold at most {MAX_CONDITIONS} conditions in all"),
            );
        }
        trees.push(tree);
        urls.push(url);
    }

    let mut steps = Vec::with_capacity(total);
    let mut start = 0;
    for (i, tree) in trees.into_iter().enumerate() {
        let end = start + tree.leaves();
        let on_false = if end < total {
            Jump::Step(index(end))
        } else {
            Jump::Default
        };
        emit(tree, Jump::Rule(index(i)), on_false, &mut steps);
        start = end;
    }
    debug_assert_eq!(steps.len(), total);
    let needs = steps.iter().fold(0, |n, s| n | s.test.needs());
    Ok(Rules { steps, urls, needs })
}

// ---------------------------------------------------------------- rule set

/// A link's rules as written and as compiled, so the redirect path never
/// compiles.
///
/// Its own serde form is the written list: that is what the database and
/// the API hold, and deserialising it compiles, once, when the origin loads
/// a link. [`crate::model::Link`] publishes the compiled form instead,
/// through [`program`], and the edge loads that: it needs only the decision
/// list, and so never links the compiler. A set loaded from its compiled
/// form has no written rules. Two sets are equal when their compiled forms
/// are, which the written rules determine.
#[derive(Clone, Debug, Default)]
pub struct RuleSet {
    written: Vec<Rule>,
    compiled: Rules,
}

impl RuleSet {
    /// Compiles stored `rules`, whose destinations the API normalised
    /// before storing them. They are not normalised again: that would link
    /// the URL parser and its IDNA tables into the edge Worker, and a
    /// destination policy made stricter since must not make a stored link
    /// unreadable. Fails only if a condition is malformed or a limit is
    /// exceeded, which the API would have refused.
    pub fn new(written: Vec<Rule>) -> Result<RuleSet, RuleError> {
        let compiled = build(&written, |url| Ok(url.to_owned()))?;
        Ok(RuleSet { written, compiled })
    }

    /// The rules as written, in order; empty for a set loaded from its
    /// compiled form.
    pub fn rules(&self) -> &[Rule] {
        &self.written
    }

    pub fn compiled(&self) -> &Rules {
        &self.compiled
    }

    pub fn is_empty(&self) -> bool {
        self.compiled.is_empty()
    }
}

impl PartialEq for RuleSet {
    fn eq(&self, other: &RuleSet) -> bool {
        self.compiled == other.compiled
    }
}

impl Eq for RuleSet {}

impl Serialize for RuleSet {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.written.serialize(s)
    }
}

impl<'de> Deserialize<'de> for RuleSet {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<RuleSet, D::Error> {
        let written = Vec::<Rule>::deserialize(d)?;
        RuleSet::new(written).map_err(serde::de::Error::custom)
    }
}

/// A [`RuleSet`] as its compiled [`Rules`], for `#[serde(with)]`: the form
/// link records carry to the edge.
pub mod program {
    use super::{RuleSet, Rules};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(set: &RuleSet, s: S) -> Result<S::Ok, S::Error> {
        set.compiled.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<RuleSet, D::Error> {
        Ok(RuleSet {
            written: Vec::new(),
            compiled: Rules::deserialize(d)?,
        })
    }
}

fn index(i: usize) -> u8 {
    u8::try_from(i).expect("bounded by MAX_CONDITIONS and MAX_RULES")
}

/// Appends `node`'s leaves in order. Its first leaf is the step at the
/// current end of `steps`; the whole subtree ends in `on_true` or
/// `on_false`.
fn emit(node: Node, on_true: Jump, on_false: Jump, steps: &mut Vec<Step>) {
    match node {
        Node::Leaf(test) => steps.push(Step {
            test,
            on_true,
            on_false,
        }),
        Node::Not(child) => emit(*child, on_false, on_true, steps),
        Node::All(children) | Node::Any(children) if children.len() == 1 => {
            let child = children.into_iter().next().expect("one child");
            emit(child, on_true, on_false, steps)
        }
        Node::All(children) => {
            let last = children.len() - 1;
            for (k, child) in children.into_iter().enumerate() {
                let next = steps.len() + child.leaves();
                let t = if k == last {
                    on_true
                } else {
                    Jump::Step(index(next))
                };
                emit(child, t, on_false, steps);
            }
        }
        Node::Any(children) => {
            let last = children.len() - 1;
            for (k, child) in children.into_iter().enumerate() {
                let next = steps.len() + child.leaves();
                let f = if k == last {
                    on_false
                } else {
                    Jump::Step(index(next))
                };
                emit(child, on_true, f, steps);
            }
        }
    }
}

fn check(c: &Condition, path: &str, depth: usize) -> Result<Node, RuleError> {
    let branch = |children: &[Condition], kind: &str| -> Result<Vec<Node>, RuleError> {
        let path = format!("{path}.{kind}");
        if depth >= MAX_DEPTH {
            return fail(&path, format!("conditions nest at most {MAX_DEPTH} deep"));
        }
        if children.is_empty() {
            return fail(&path, "must hold at least one condition");
        }
        if children.len() > MAX_CONDITIONS {
            return fail(&path, format!("at most {MAX_CONDITIONS} conditions"));
        }
        children
            .iter()
            .enumerate()
            .map(|(i, c)| check(c, &format!("{path}[{i}]"), depth + 1))
            .collect()
    };
    let test = match c {
        Condition::All(children) => return Ok(Node::All(branch(children, "all")?)),
        Condition::Any(children) => return Ok(Node::Any(branch(children, "any")?)),
        Condition::Not(child) => {
            let path = format!("{path}.not");
            if depth >= MAX_DEPTH {
                return fail(&path, format!("conditions nest at most {MAX_DEPTH} deep"));
            }
            return Ok(Node::Not(Box::new(check(child, &path, depth + 1)?)));
        }
        Condition::Country(v) => {
            let mut out = values(v, &format!("{path}.country"), parse_country)?;
            out.sort_unstable();
            out.dedup();
            Test::Country(out.into())
        }
        Condition::Region(v) => {
            let mut out = values(v, &format!("{path}.region"), parse_region)?;
            out.sort_unstable();
            out.dedup();
            Test::Region(out.into())
        }
        Condition::Device(v) => Test::Device(bits(v, &format!("{path}.device"), |s| {
            Device::ALL.iter().position(|d| d.as_str() == s)
        })?),
        Condition::Os(v) => Test::Os(bits(v, &format!("{path}.os"), |s| {
            Os::ALL.iter().position(|o| o.as_str() == s)
        })?),
        Condition::Browser(v) => Test::Browser(bits(v, &format!("{path}.browser"), |s| {
            Browser::ALL.iter().position(|b| b.as_str() == s)
        })?),
        Condition::Language(v) => {
            let mut out = values(v, &format!("{path}.language"), |s| {
                is_language_tag(s)
                    .then(|| s.to_ascii_lowercase().into_boxed_str())
                    .ok_or("is not a language tag such as \"en\" or \"pt-BR\"")
            })?;
            out.sort_unstable();
            out.dedup();
            Test::Language(out.into())
        }
        Condition::Referrer(v) => {
            let mut out = values(v, &format!("{path}.referrer"), |s| {
                let host = s.strip_suffix('.').unwrap_or(s).to_ascii_lowercase();
                is_valid_hostname(&host)
                    .then(|| host.into_boxed_str())
                    .ok_or("is not a hostname such as \"news.example.com\"")
            })?;
            out.sort_unstable();
            out.dedup();
            Test::Referrer(out.into())
        }
        Condition::Time(w) => Test::Time(window(w, &format!("{path}.time"))?),
        Condition::Query(q) => query(q, &format!("{path}.query"))?,
    };
    Ok(Node::Leaf(test))
}

/// Checks a leaf's value list, parsing each value.
fn values<T>(
    list: &[String],
    path: &str,
    parse: impl Fn(&str) -> Result<T, &'static str>,
) -> Result<Vec<T>, RuleError> {
    if list.is_empty() {
        return fail(path, "must list at least one value");
    }
    if list.len() > MAX_VALUES {
        return fail(path, format!("at most {MAX_VALUES} values"));
    }
    list.iter()
        .enumerate()
        .map(|(i, v)| parse(v).or_else(|why| fail(&format!("{path}[{i}]"), format!("{v:?} {why}"))))
        .collect()
}

fn bits(
    list: &[String],
    path: &str,
    position: impl Fn(&str) -> Option<usize>,
) -> Result<u8, RuleError> {
    let found = values(list, path, |s| position(s).ok_or("is not a known value"))?;
    Ok(found.into_iter().fold(0, |b, i| b | (1 << i)))
}

fn parse_country(s: &str) -> Result<[u8; 2], &'static str> {
    match s.as_bytes() {
        [a, b] if a.is_ascii_alphabetic() && b.is_ascii_alphabetic() => {
            Ok([a.to_ascii_uppercase(), b.to_ascii_uppercase()])
        }
        _ => Err("is not a two-letter country code"),
    }
}

fn parse_region(s: &str) -> Result<([u8; 2], Box<str>), &'static str> {
    const WHY: &str = "is not a region code such as \"US-CA\"";
    let (country, sub) = s.split_once('-').ok_or(WHY)?;
    let country = parse_country(country).map_err(|_| WHY)?;
    if !is_subdivision(sub.as_bytes()) {
        return Err(WHY);
    }
    Ok((country, sub.to_ascii_uppercase().into_boxed_str()))
}

/// An ISO 3166-2 subdivision code after the country: 1 to 3 letters or
/// digits.
fn is_subdivision(b: &[u8]) -> bool {
    (1..=3).contains(&b.len()) && b.iter().all(u8::is_ascii_alphanumeric)
}

const DAYS: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

fn window(w: &TimeWindow, path: &str) -> Result<Window, RuleError> {
    if w.after.is_none() && w.before.is_none() && w.days.is_none() && w.hours.is_none() {
        return fail(path, "needs at least one of after, before, days and hours");
    }
    let after_ms = w.after.map(|t| t.timestamp_millis());
    let before_ms = w.before.map(|t| t.timestamp_millis());
    if let (Some(a), Some(b)) = (after_ms, before_ms)
        && a >= b
    {
        return fail(&format!("{path}.before"), "must be later than after");
    }
    let days = match &w.days {
        None => None,
        Some(list) => {
            let path = format!("{path}.days");
            let found = values(list, &path, |s| {
                DAYS.iter()
                    .position(|d| *d == s)
                    .ok_or("is not a day (mon, tue, wed, thu, fri, sat or sun)")
            })?;
            Some(found.into_iter().fold(0u8, |b, i| b | (1 << i)))
        }
    };
    let minutes = match &w.hours {
        None => None,
        Some([from, to]) => {
            let start = parse_clock(from)
                .filter(|&m| m < 24 * 60)
                .ok_or_else(|| RuleError {
                    path: format!("{path}.hours[0]"),
                    reason: format!("{from:?} is not a time from \"00:00\" to \"23:59\""),
                })?;
            let end = parse_clock(to).ok_or_else(|| RuleError {
                path: format!("{path}.hours[1]"),
                reason: format!("{to:?} is not a time from \"00:00\" to \"24:00\""),
            })?;
            if start == end % (24 * 60) {
                return fail(&format!("{path}.hours"), "must not start and end together");
            }
            Some((start, end))
        }
    };
    if w.utc_offset_minutes.abs() > MAX_UTC_OFFSET_MINUTES {
        return fail(
            &format!("{path}.utc_offset_minutes"),
            "must be from -840 to 840",
        );
    }
    Ok(Window {
        after_ms,
        before_ms,
        days,
        minutes,
        offset_ms: i64::from(w.utc_offset_minutes) * 60_000,
    })
}

/// `HH:MM` as minutes of the day, `00:00` to `24:00`.
fn parse_clock(s: &str) -> Option<u16> {
    let b = s.as_bytes();
    if b.len() != 5
        || b[2] != b':'
        || !b
            .iter()
            .enumerate()
            .all(|(i, c)| i == 2 || c.is_ascii_digit())
    {
        return None;
    }
    let h = u16::from(b[0] - b'0') * 10 + u16::from(b[1] - b'0');
    let m = u16::from(b[3] - b'0') * 10 + u16::from(b[4] - b'0');
    let total = h * 60 + m;
    (m < 60 && total <= 24 * 60).then_some(total)
}

fn query(q: &QueryMatch, path: &str) -> Result<Test, RuleError> {
    if q.name.is_empty() || q.name.len() > MAX_QUERY_VALUE_LEN {
        return fail(
            &format!("{path}.name"),
            format!("must be 1 to {MAX_QUERY_VALUE_LEN} bytes"),
        );
    }
    let values = match &q.values {
        None => None,
        Some(list) => {
            let mut out = values(list, &format!("{path}.values"), |s| {
                if s.len() > MAX_QUERY_VALUE_LEN {
                    Err("is longer than 256 bytes")
                } else {
                    Ok(Box::<[u8]>::from(s.as_bytes()))
                }
            })?;
            out.sort_unstable();
            out.dedup();
            Some(out.into_boxed_slice())
        }
    };
    Ok(Test::Query {
        name: q.name.as_bytes().into(),
        values,
    })
}

// ---------------------------------------------------------------- evaluation

/// The request facts, each computed only if some step reads it.
struct Facts<'a> {
    now_ms: i64,
    country: Option<[u8; 2]>,
    region: Option<&'a [u8]>,
    device: Device,
    os: Os,
    browser: Browser,
    language: Option<&'a str>,
    referrer: Option<String>,
    /// Parsed only when a step reads it; `None` costs nothing to build.
    query: Option<QueryParams<'a>>,
}

struct QueryParams<'a> {
    pairs: [(&'a [u8], &'a [u8]); MAX_QUERY_PARAMS],
    len: usize,
}

impl<'a> QueryParams<'a> {
    fn parse(q: &'a [u8]) -> QueryParams<'a> {
        let mut pairs = [(&[][..], &[][..]); MAX_QUERY_PARAMS];
        let len = parse_query(q, &mut pairs);
        QueryParams { pairs, len }
    }

    fn pairs(&self) -> &[(&'a [u8], &'a [u8])] {
        &self.pairs[..self.len]
    }
}

impl<'a> Facts<'a> {
    fn gather(req: &Request<'a>, needs: u8) -> Facts<'a> {
        let wants = |bit: u8| needs & bit != 0;
        Facts {
            now_ms: req.now_ms,
            country: req.country,
            region: req.region.filter(|r| is_subdivision(r)),
            device: if wants(NEEDS_DEVICE) {
                device_class(req.user_agent)
            } else {
                Device::Other
            },
            os: if wants(NEEDS_OS) {
                os_family(req.user_agent)
            } else {
                Os::Other
            },
            browser: if wants(NEEDS_BROWSER) {
                browser_family(req.user_agent)
            } else {
                Browser::Other
            },
            language: if wants(NEEDS_LANGUAGE) {
                preferred_language(req.accept_language)
            } else {
                None
            },
            referrer: if wants(NEEDS_REFERRER) {
                referrer_host(req.referer)
            } else {
                None
            },
            query: if wants(NEEDS_QUERY) {
                req.query.map(QueryParams::parse)
            } else {
                None
            },
        }
    }

    fn test(&self, test: &Test) -> bool {
        match test {
            Test::Country(list) => self.country.is_some_and(|c| list.binary_search(&c).is_ok()),
            Test::Region(list) => match (self.country, self.region) {
                (Some(c), Some(sub)) => list
                    .iter()
                    .any(|(lc, ls)| *lc == c && ls.as_bytes().eq_ignore_ascii_case(sub)),
                _ => false,
            },
            Test::Device(bits) => {
                has_bit(*bits, Device::ALL.iter().position(|d| *d == self.device))
            }
            Test::Os(bits) => has_bit(*bits, Os::ALL.iter().position(|o| *o == self.os)),
            Test::Browser(bits) => {
                has_bit(*bits, Browser::ALL.iter().position(|b| *b == self.browser))
            }
            Test::Language(list) => self
                .language
                .is_some_and(|tag| list.iter().any(|want| language_matches(tag, want))),
            Test::Referrer(list) => self
                .referrer
                .as_deref()
                .is_some_and(|host| list.iter().any(|want| host_matches(host, want))),
            Test::Time(w) => w.holds(self.now_ms),
            Test::Query { name, values } => self
                .query
                .as_ref()
                .map_or(&[][..], QueryParams::pairs)
                .iter()
                .filter(|(n, _)| decoded_eq(n, name))
                .any(|(_, v)| {
                    values
                        .as_ref()
                        .is_none_or(|vals| vals.iter().any(|want| decoded_eq(v, want)))
                }),
        }
    }
}

fn has_bit(bits: u8, i: Option<usize>) -> bool {
    i.is_some_and(|i| bits & (1 << i) != 0)
}

/// Whether the visitor's `tag` is `want` (lowercase) or a more specific
/// form of it.
fn language_matches(tag: &str, want: &str) -> bool {
    let (t, w) = (tag.as_bytes(), want.as_bytes());
    t.len() >= w.len()
        && t[..w.len()].eq_ignore_ascii_case(w)
        && (t.len() == w.len() || t[w.len()] == b'-')
}

/// Whether `host` is `want` or a subdomain of it, both lowercase.
fn host_matches(host: &str, want: &str) -> bool {
    host == want
        || (host.len() > want.len()
            && host.ends_with(want)
            && host.as_bytes()[host.len() - want.len() - 1] == b'.')
}

impl Window {
    fn holds(&self, now_ms: i64) -> bool {
        if self.after_ms.is_some_and(|a| now_ms < a) || self.before_ms.is_some_and(|b| now_ms >= b)
        {
            return false;
        }
        const DAY_MS: i64 = 86_400_000;
        let local = now_ms.saturating_add(self.offset_ms);
        let day = local.div_euclid(DAY_MS);
        // 1970-01-01 was a Thursday, index 3 from Monday.
        let weekday = (day + 3).rem_euclid(7);
        if self.days.is_some_and(|d| d & (1 << weekday) == 0) {
            return false;
        }
        let minute = u16::try_from(local.rem_euclid(DAY_MS) / 60_000).expect("under 1440");
        match self.minutes {
            None => true,
            Some((start, end)) if start < end => (start..end).contains(&minute),
            Some((start, end)) => minute >= start || minute < end,
        }
    }
}

/// Splits a query string into raw `(name, value)` pairs, at most
/// [`MAX_QUERY_PARAMS`] and only those ending within [`MAX_QUERY_BYTES`],
/// so a parameter is never seen cut short. Returns how many were stored.
fn parse_query<'a>(q: &'a [u8], out: &mut [(&'a [u8], &'a [u8]); MAX_QUERY_PARAMS]) -> usize {
    let mut n = 0;
    let mut offset = 0;
    for part in q.split(|&b| b == b'&') {
        let end = offset + part.len();
        offset = end + 1;
        if end > MAX_QUERY_BYTES || n == MAX_QUERY_PARAMS {
            break;
        }
        if part.is_empty() {
            continue;
        }
        out[n] = match part.iter().position(|&b| b == b'=') {
            Some(i) => (&part[..i], &part[i + 1..]),
            None => (part, &[][..]),
        };
        n += 1;
    }
    n
}

/// Whether `raw`, decoded as `application/x-www-form-urlencoded` (`+` is a
/// space, `%XX` a byte, any other `%` itself), equals `want`. Stops at the
/// first difference.
fn decoded_eq(raw: &[u8], want: &[u8]) -> bool {
    let mut i = 0;
    let mut w = want.iter();
    while i < raw.len() {
        let (byte, used) = match raw[i] {
            b'+' => (b' ', 1),
            b'%' if i + 2 < raw.len() => match (hex(raw[i + 1]), hex(raw[i + 2])) {
                (Some(h), Some(l)) => (h << 4 | l, 3),
                _ => (b'%', 1),
            },
            b => (b, 1),
        };
        if w.next() != Some(&byte) {
            return false;
        }
        i += used;
    }
    w.next().is_none()
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: Policy = Policy {
        allow_ip_literals: false,
        allow_private: false,
    };

    fn parse(json: &str) -> Vec<Rule> {
        serde_json::from_str(json).unwrap_or_else(|e| panic!("{json}: {e}"))
    }

    fn rules(json: &str) -> Rules {
        compile(&parse(json), POLICY).unwrap_or_else(|e| panic!("{json}: {e}"))
    }

    fn err(json: &str) -> RuleError {
        match compile(&parse(json), POLICY) {
            Ok(_) => panic!("{json} compiled"),
            Err(e) => e,
        }
    }

    /// A one-rule list sending matches to https://a.example.com/.
    fn one(condition: &str) -> Rules {
        rules(&format!(
            r#"[{{"if": {condition}, "url": "https://a.example.com/"}}]"#
        ))
    }

    fn hit(r: &Rules, req: &Request<'_>) -> bool {
        r.evaluate(req) == Some(0)
    }

    // 2026-11-16 (a Monday) 12:30:00 UTC.
    const MONDAY_NOON: i64 = 1_794_832_200_000;

    #[test]
    fn monday_noon_is_what_it_says() {
        let t = DateTime::from_timestamp_millis(MONDAY_NOON).unwrap();
        assert_eq!(t.to_rfc3339(), "2026-11-16T12:30:00+00:00");
    }

    #[test]
    fn first_match_wins_and_none_falls_through() {
        let r = rules(
            r#"[{"if": {"country": ["us"]}, "url": "https://US.example.com"},
                {"if": {"country": ["US", "DE"]}, "url": "https://de.example.com/"}]"#,
        );
        assert_eq!(
            r.urls(),
            ["https://us.example.com/", "https://de.example.com/"]
        );
        let mut req = Request {
            country: Some(*b"US"),
            ..Request::default()
        };
        assert_eq!(r.destination(&req), Some("https://us.example.com/"));
        req.country = Some(*b"DE");
        assert_eq!(r.evaluate_counted(&req), (Some(1), 2));
        req.country = Some(*b"FR");
        assert_eq!(r.evaluate_counted(&req), (None, 2));
        req.country = None;
        assert_eq!(r.evaluate(&req), None);
        let empty = compile(&[], POLICY).unwrap();
        assert!(empty.is_empty());
        assert_eq!(empty.evaluate_counted(&req), (None, 0));
    }

    #[test]
    fn all_any_not_short_circuit_into_forward_jumps() {
        // (US and mobile) or not (ios or de) — 4 leaves.
        let r = one(
            r#"{"any": [{"all": [{"country": ["US"]}, {"device": ["mobile"]}]},
                        {"not": {"any": [{"os": ["ios"]}, {"language": ["de"]}]}}]}"#,
        );
        let s = r.steps();
        assert_eq!(s.len(), 4);
        assert_eq!(
            (s[0].on_true, s[0].on_false),
            (Jump::Step(1), Jump::Step(2))
        );
        assert_eq!(
            (s[1].on_true, s[1].on_false),
            (Jump::Rule(0), Jump::Step(2))
        );
        assert_eq!(
            (s[2].on_true, s[2].on_false),
            (Jump::Default, Jump::Step(3))
        );
        assert_eq!(
            (s[3].on_true, s[3].on_false),
            (Jump::Default, Jump::Rule(0))
        );
        let iphone = b"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148";
        let mut req = Request {
            country: Some(*b"US"),
            user_agent: Some(iphone),
            ..Request::default()
        };
        assert_eq!(r.evaluate_counted(&req), (Some(0), 2));
        req.country = Some(*b"FR");
        assert_eq!(r.evaluate_counted(&req), (None, 2), "ios: the not fails");
        req.user_agent = Some(b"Mozilla/5.0 (Windows NT 10.0)");
        assert_eq!(r.evaluate_counted(&req), (Some(0), 3));
        req.accept_language = Some(b"de-AT");
        assert_eq!(r.evaluate_counted(&req), (None, 3));
    }

    #[test]
    fn every_jump_goes_forward() {
        let r = rules(
            r#"[{"if": {"all": [{"not": {"country": ["US"]}}, {"any": [{"os": ["ios"]},
                       {"not": {"all": [{"browser": ["chrome"]}, {"device": ["bot"]}]}}]}]},
                 "url": "https://a.example.com/"},
                {"if": {"not": {"not": {"region": ["US-CA"]}}}, "url": "https://b.example.com/"},
                {"if": {"any": [{"referrer": ["example.org"]}]}, "url": "https://c.example.com/"}]"#,
        );
        assert_eq!(r.steps().len(), 6);
        for (i, s) in r.steps().iter().enumerate() {
            for j in [s.on_true, s.on_false] {
                if let Jump::Step(n) = j {
                    assert!(usize::from(n) > i, "step {i} jumps back to {n}");
                }
            }
        }
    }

    #[test]
    fn sixty_four_conditions_is_the_bound() {
        let leaf = r#"{"country": ["US"]}"#;
        let all = |n: usize| format!(r#"{{"all": [{}]}}"#, vec![leaf; n].join(","));
        let r = one(&all(64));
        let req = Request {
            country: Some(*b"US"),
            ..Request::default()
        };
        assert_eq!(r.evaluate_counted(&req), (Some(0), 64));
        let e = err(&format!(
            r#"[{{"if": {}, "url": "https://a.example.com/"}}]"#,
            all(65)
        ));
        assert_eq!(e.path, "rules[0].if.all");
        // Across rules: 32 rules of 2 leaves fit, one more leaf does not.
        let rule = format!(r#"{{"if": {}, "url": "https://a.example.com/"}}"#, all(2));
        let r = rules(&format!("[{}]", vec![rule.as_str(); 32].join(",")));
        let fr = Request {
            country: Some(*b"FR"),
            ..Request::default()
        };
        assert_eq!(r.evaluate_counted(&fr), (None, 32));
        let mut list = vec![rule.as_str(); 31];
        let three = format!(r#"{{"if": {}, "url": "https://a.example.com/"}}"#, all(3));
        list.push(&three);
        assert_eq!(err(&format!("[{}]", list.join(","))).path, "rules[31]");
        let thirty_three =
            vec![format!(r#"{{"if": {leaf}, "url": "https://a.example.com/"}}"#); 33];
        assert_eq!(err(&format!("[{}]", thirty_three.join(","))).path, "rules");
    }

    #[test]
    fn nesting_is_limited() {
        let mut c = r#"{"country": ["US"]}"#.to_owned();
        for _ in 0..MAX_DEPTH {
            c = format!(r#"{{"not": {c}}}"#);
        }
        let r = one(&c);
        assert!(hit(&r, &Request::default()) == (MAX_DEPTH % 2 == 1));
        let e = err(&format!(
            r#"[{{"if": {{"all": [{c}]}}, "url": "https://a.example.com/"}}]"#
        ));
        assert!(e.reason.contains("nest"), "{e}");
        assert!(e.path.ends_with(".not"), "{e}");
    }

    #[test]
    fn countries_and_regions() {
        let r = one(r#"{"country": ["de", "US", "US"]}"#);
        assert_eq!(
            r.steps()[0].test,
            Test::Country(vec![*b"DE", *b"US"].into())
        );
        let r = one(r#"{"region": ["us-ca", "CH-ZH", "GB-ENG"]}"#);
        let req = |c: &[u8; 2], sub: &'static [u8]| Request {
            country: Some(*c),
            region: Some(sub),
            ..Request::default()
        };
        assert!(hit(&r, &req(b"US", b"CA")));
        assert!(hit(&r, &req(b"US", b"ca")));
        assert!(hit(&r, &req(b"GB", b"ENG")));
        assert!(!hit(&r, &req(b"US", b"NY")));
        assert!(!hit(&r, &req(b"CA", b"CA")));
        assert!(!hit(&r, &req(b"US", b"CA-X")), "malformed region header");
        assert!(!hit(
            &r,
            &Request {
                region: Some(b"CA"),
                ..Request::default()
            }
        ));
    }

    #[test]
    fn user_agent_leaves() {
        let android = b"Mozilla/5.0 (Linux; Android 14; Pixel 8) Chrome/120.0 Mobile Safari/537.36";
        let mac = b"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Version/17.0 Safari/605.1.15";
        let r = one(
            r#"{"all": [{"device": ["mobile", "tablet"]}, {"os": ["android"]}, {"browser": ["chrome"]}]}"#,
        );
        let ua = |u: &'static [u8]| Request {
            user_agent: Some(u),
            ..Request::default()
        };
        assert!(hit(&r, &ua(android)));
        assert!(!hit(&r, &ua(mac)));
        assert!(!hit(&r, &Request::default()));
        let r = one(r#"{"browser": ["safari"]}"#);
        assert!(hit(&r, &ua(mac)));
        let r = one(r#"{"os": ["other"]}"#);
        assert!(hit(&r, &Request::default()), "no User-Agent is os other");
    }

    #[test]
    fn languages_match_by_prefix_on_a_subtag_boundary() {
        let r = one(r#"{"language": ["EN", "pt-br"]}"#);
        let lang = |h: &'static [u8]| Request {
            accept_language: Some(h),
            ..Request::default()
        };
        assert!(hit(&r, &lang(b"en")));
        assert!(hit(&r, &lang(b"en-GB,de;q=0.5")));
        assert!(hit(&r, &lang(b"PT-BR")));
        assert!(!hit(&r, &lang(b"pt")));
        assert!(!hit(&r, &lang(b"eng")));
        assert!(
            !hit(&r, &lang(b"de,en;q=0.9")),
            "only the preferred language"
        );
        assert!(!hit(&r, &Request::default()));
    }

    #[test]
    fn referrers_match_hosts_and_subdomains() {
        let r = one(r#"{"referrer": ["Example.com.", "news.example.org"]}"#);
        let referer = |h: &'static [u8]| Request {
            referer: Some(h),
            ..Request::default()
        };
        assert!(hit(&r, &referer(b"https://example.com/x")));
        assert!(hit(&r, &referer(b"https://www.EXAMPLE.com/")));
        assert!(hit(&r, &referer(b"http://news.example.org:8080/")));
        assert!(!hit(&r, &referer(b"https://badexample.com/")));
        assert!(!hit(&r, &referer(b"https://example.org/")));
        assert!(!hit(&r, &referer(b"android-app://com.example")));
        assert!(!hit(&r, &Request::default()));
        let direct = one(r#"{"not": {"referrer": ["example.com"]}}"#);
        assert!(hit(&direct, &Request::default()));
    }

    #[test]
    fn time_windows() {
        let at = |now_ms| Request {
            now_ms,
            ..Request::default()
        };
        let hour = 3_600_000;
        let r =
            one(r#"{"time": {"after": "2026-11-16T12:30:00Z", "before": "2026-11-16T13:00:00Z"}}"#);
        assert!(!hit(&r, &at(MONDAY_NOON - 1)));
        assert!(hit(&r, &at(MONDAY_NOON)));
        assert!(!hit(&r, &at(MONDAY_NOON + hour / 2)));

        let r = one(r#"{"time": {"days": ["mon", "fri"], "hours": ["09:00", "17:00"]}}"#);
        assert!(hit(&r, &at(MONDAY_NOON)));
        assert!(!hit(&r, &at(MONDAY_NOON + 24 * hour)), "tuesday");
        assert!(hit(&r, &at(MONDAY_NOON + 4 * 24 * hour)), "friday");
        assert!(!hit(&r, &at(MONDAY_NOON + 5 * hour)), "17:30");
        assert!(hit(&r, &at(MONDAY_NOON + 4 * hour + 29 * 60_000)), "16:59");
        assert!(!hit(&r, &at(MONDAY_NOON + 4 * hour + 30 * 60_000)), "17:00");

        // 12:30 UTC is 07:30 at UTC-5 and still Monday; at UTC+12 it is
        // 00:30 on Tuesday.
        let r = one(r#"{"time": {"hours": ["07:00", "08:00"], "utc_offset_minutes": -300}}"#);
        assert!(hit(&r, &at(MONDAY_NOON)));
        let r = one(r#"{"time": {"days": ["tue"], "utc_offset_minutes": 720}}"#);
        assert!(hit(&r, &at(MONDAY_NOON)));

        // Overnight, and to the end of the day.
        let r = one(r#"{"time": {"hours": ["22:00", "06:00"]}}"#);
        assert!(!hit(&r, &at(MONDAY_NOON)));
        assert!(hit(&r, &at(MONDAY_NOON + 10 * hour)), "22:30");
        assert!(hit(&r, &at(MONDAY_NOON + 17 * hour)), "05:30");
        let r = one(r#"{"time": {"hours": ["12:00", "24:00"]}}"#);
        assert!(hit(&r, &at(MONDAY_NOON)));
        assert!(!hit(&r, &at(MONDAY_NOON - hour)));

        // Before 1970, weekdays still come out right (1969-12-31 was a
        // Wednesday).
        let r = one(r#"{"time": {"days": ["wed"]}}"#);
        assert!(hit(&r, &at(-1)));
        assert!(!hit(&r, &at(0)));
        let extreme = one(r#"{"time": {"days": ["mon"], "utc_offset_minutes": 840}}"#);
        extreme.evaluate(&at(i64::MAX));
        extreme.evaluate(&at(i64::MIN));
    }

    #[test]
    fn query_parameters() {
        let q = |s: &'static [u8]| Request {
            query: Some(s),
            ..Request::default()
        };
        let present = one(r#"{"query": {"name": "ref"}}"#);
        assert!(hit(&present, &q(b"a=1&ref")));
        assert!(hit(&present, &q(b"ref=")));
        assert!(hit(&present, &q(b"r%65f=x")));
        assert!(!hit(&present, &q(b"refs=1&xref=2")));
        assert!(!hit(&present, &Request::default()));

        let r =
            one(r#"{"query": {"name": "utm source", "values": ["news letter", "a&b", "100%"]}}"#);
        assert!(hit(&r, &q(b"utm+source=news+letter")));
        assert!(hit(&r, &q(b"x=1&utm%20source=news%20letter")));
        assert!(hit(&r, &q(b"utm+source=a%26b")));
        assert!(hit(&r, &q(b"utm+source=100%")), "a lone % is itself");
        assert!(hit(&r, &q(b"utm+source=100%25")));
        assert!(!hit(&r, &q(b"utm+source=100%2")));
        assert!(!hit(&r, &q(b"utm+source=news")));
        assert!(!hit(&r, &q(b"utm+source=news+letters")));
        assert!(!hit(&r, &q(b"utm+source=a&b")));
        assert!(hit(&r, &q(b"utm+source=x&utm+source=a%26b")), "any repeat");
        let empty = one(r#"{"query": {"name": "x", "values": [""]}}"#);
        assert!(hit(&empty, &q(b"x")));
        assert!(hit(&empty, &q(b"x=")));
        assert!(!hit(&empty, &q(b"x=1")));
    }

    #[test]
    fn query_reading_is_bounded() {
        let r = one(r#"{"query": {"name": "want"}}"#);
        let mut q = "a=1&".repeat(MAX_QUERY_PARAMS - 1);
        q.push_str("want");
        let req = |s: &str| {
            let b = s.as_bytes().to_vec();
            let r2 = r.clone();
            let req = Request {
                query: Some(&b),
                ..Request::default()
            };
            r2.evaluate(&req) == Some(0)
        };
        assert!(req(&q), "the 64th parameter is read");
        assert!(!req(&format!("a=1&{q}")), "the 65th is not");
        assert!(req(&format!("&&{q}&&")), "empty parts do not count");
        let pad = "x".repeat(MAX_QUERY_BYTES - "&want".len());
        assert!(req(&format!("{pad}&want")), "ends at the byte limit");
        assert!(!req(&format!("{pad}x&want")), "ends one byte past it");
        let v = one(r#"{"query": {"name": "want", "values": ["abc"]}}"#);
        let long = format!("{}&want=abcdef", "x".repeat(MAX_QUERY_BYTES - 10));
        let b = long.into_bytes();
        let cut = Request {
            query: Some(&b),
            ..Request::default()
        };
        assert_eq!(v.evaluate(&cut), None, "never matches a cut value");
    }

    #[test]
    fn facts_are_only_gathered_when_read() {
        let r = one(r#"{"country": ["US"]}"#);
        assert_eq!(r.needs, 0);
        let r = one(
            r#"{"all": [{"os": ["ios"]}, {"query": {"name": "a"}}, {"referrer": ["example.com"]}]}"#,
        );
        assert_eq!(r.needs, NEEDS_OS | NEEDS_QUERY | NEEDS_REFERRER);
        let f = Facts::gather(
            &Request {
                user_agent: Some(b"Mozilla/5.0 (iPhone)"),
                accept_language: Some(b"de"),
                query: Some(b"a=1"),
                ..Request::default()
            },
            NEEDS_OS,
        );
        assert_eq!(
            (f.os, f.device, f.language, f.query.is_none()),
            (Os::Ios, Device::Other, None, true)
        );
    }

    #[test]
    fn invalid_rules_name_the_part_at_fault() {
        let cases: &[(&str, &str)] = &[
            (r#"{"all": []}"#, "rules[0].if.all"),
            (r#"{"any": []}"#, "rules[0].if.any"),
            (r#"{"country": []}"#, "rules[0].if.country"),
            (r#"{"country": ["USA"]}"#, "rules[0].if.country[0]"),
            (r#"{"country": ["U1"]}"#, "rules[0].if.country[0]"),
            (r#"{"region": ["US"]}"#, "rules[0].if.region[0]"),
            (r#"{"region": ["US-"]}"#, "rules[0].if.region[0]"),
            (r#"{"region": ["USA-CA"]}"#, "rules[0].if.region[0]"),
            (r#"{"region": ["US-CALI"]}"#, "rules[0].if.region[0]"),
            (r#"{"device": ["phone"]}"#, "rules[0].if.device[0]"),
            (r#"{"os": ["iOS"]}"#, "rules[0].if.os[0]"),
            (r#"{"browser": ["ie"]}"#, "rules[0].if.browser[0]"),
            (r#"{"language": ["en_US"]}"#, "rules[0].if.language[0]"),
            (r#"{"referrer": ["localhost"]}"#, "rules[0].if.referrer[0]"),
            (
                r#"{"referrer": ["https://example.com/"]}"#,
                "rules[0].if.referrer[0]",
            ),
            (r#"{"time": {}}"#, "rules[0].if.time"),
            (
                r#"{"time": {"after": "2026-01-02T00:00:00Z", "before": "2026-01-01T00:00:00Z"}}"#,
                "rules[0].if.time.before",
            ),
            (r#"{"time": {"days": []}}"#, "rules[0].if.time.days"),
            (
                r#"{"time": {"days": ["monday"]}}"#,
                "rules[0].if.time.days[0]",
            ),
            (
                r#"{"time": {"hours": ["24:00", "01:00"]}}"#,
                "rules[0].if.time.hours[0]",
            ),
            (
                r#"{"time": {"hours": ["9:00", "17:00"]}}"#,
                "rules[0].if.time.hours[0]",
            ),
            (
                r#"{"time": {"hours": ["09:00", "17:60"]}}"#,
                "rules[0].if.time.hours[1]",
            ),
            (
                r#"{"time": {"hours": ["09:00", "24:01"]}}"#,
                "rules[0].if.time.hours[1]",
            ),
            (
                r#"{"time": {"hours": ["00:00", "24:00"]}}"#,
                "rules[0].if.time.hours",
            ),
            (
                r#"{"time": {"hours": ["09:00", "09:00"]}}"#,
                "rules[0].if.time.hours",
            ),
            (
                r#"{"time": {"days": ["mon"], "utc_offset_minutes": 841}}"#,
                "rules[0].if.time.utc_offset_minutes",
            ),
            (r#"{"query": {"name": ""}}"#, "rules[0].if.query.name"),
            (
                r#"{"query": {"name": "a", "values": []}}"#,
                "rules[0].if.query.values",
            ),
            (
                r#"{"not": {"all": [{"os": ["ios"]}, {"os": []}]}}"#,
                "rules[0].if.not.all[1].os",
            ),
        ];
        for (cond, path) in cases {
            let e = err(&format!(
                r#"[{{"if": {cond}, "url": "https://a.example.com/"}}]"#
            ));
            assert_eq!(e.path, *path, "{cond}: {e}");
            assert!(e.to_string().starts_with(path));
        }
        let long = format!(r#"{{"query": {{"name": "{}"}}}}"#, "n".repeat(257));
        assert_eq!(
            err(&format!(
                r#"[{{"if": {long}, "url": "https://a.example.com/"}}]"#
            ))
            .path,
            "rules[0].if.query.name"
        );
        let long = format!(
            r#"{{"query": {{"name": "n", "values": ["{}"]}}}}"#,
            "v".repeat(257)
        );
        assert_eq!(
            err(&format!(
                r#"[{{"if": {long}, "url": "https://a.example.com/"}}]"#
            ))
            .path,
            "rules[0].if.query.values[0]"
        );
        let many = format!(
            r#"{{"country": [{}]}}"#,
            vec![r#""US""#; MAX_VALUES + 1].join(",")
        );
        assert_eq!(
            err(&format!(
                r#"[{{"if": {many}, "url": "https://a.example.com/"}}]"#
            ))
            .path,
            "rules[0].if.country"
        );
        let e = err(r#"[{"if": {"country": ["US"]}, "url": "ftp://a.example.com/"}]"#);
        assert_eq!(e.to_string(), "rules[0].url: URL must use http or https");
    }

    #[test]
    fn the_grammar_refuses_unknown_shapes() {
        for json in [
            r#"[{"if": {"planet": ["mars"]}, "url": "https://a.example.com/"}]"#,
            r#"[{"if": {"country": ["US"]}, "url": "https://a.example.com/", "then": 1}]"#,
            r#"[{"if": {"country": ["US"], "os": ["ios"]}, "url": "https://a.example.com/"}]"#,
            r#"[{"if": {"time": {"hour": ["09:00", "10:00"]}}, "url": "https://a.example.com/"}]"#,
            r#"[{"if": {"time": {"hours": ["09:00"]}}, "url": "https://a.example.com/"}]"#,
            r#"[{"if": {"time": {"after": "yesterday"}}, "url": "https://a.example.com/"}]"#,
            r#"[{"if": {"query": {"name": "a", "value": "b"}}, "url": "https://a.example.com/"}]"#,
            r#"[{"if": {"not": [{"os": ["ios"]}]}, "url": "https://a.example.com/"}]"#,
            r#"[{"url": "https://a.example.com/"}]"#,
        ] {
            assert!(serde_json::from_str::<Vec<Rule>>(json).is_err(), "{json}");
        }
    }

    #[test]
    fn rules_round_trip_through_json() {
        let json = r#"[{"if":{"all":[{"country":["US"]},{"not":{"time":{"after":"2026-11-16T12:30:00Z","days":["sat","sun"],"hours":["22:00","06:00"],"utc_offset_minutes":-300}}},{"query":{"name":"a"}},{"query":{"name":"b","values":["1"]}}]},"url":"https://a.example.com/"}]"#;
        let parsed = parse(json);
        assert_eq!(serde_json::to_string(&parsed).unwrap(), json);
        assert!(!compile(&parsed, POLICY).unwrap().is_empty());
    }

    #[test]
    fn helpers() {
        assert_eq!(parse_clock("00:00"), Some(0));
        assert_eq!(parse_clock("24:00"), Some(1440));
        assert_eq!(parse_clock("23:59"), Some(1439));
        assert_eq!(parse_clock("24:30"), None);
        assert_eq!(parse_clock("1a:00"), None);
        assert_eq!(parse_clock("12-00"), None);
        assert!(decoded_eq(b"", b""));
        assert!(!decoded_eq(b"a", b""));
        assert!(!decoded_eq(b"", b"a"));
        assert!(decoded_eq(b"%41%62", b"Ab"));
        assert!(decoded_eq(b"%zz", b"%zz"));
        assert!(decoded_eq(b"%4", b"%4"));
        assert!(host_matches("a.b.example.com", "example.com"));
        assert!(!host_matches("aexample.com", "example.com"));
        assert!(!host_matches("com", "example.com"));
        assert!(language_matches("zh-Hant-TW", "zh-hant"));
        assert!(!language_matches("zh", "zh-hant"));
    }

    #[test]
    fn rule_sets_compile_on_read_and_keep_the_written_form() {
        let json = r#"[{"if":{"country":["US"]},"url":"https://example.com/us"}]"#;
        let set: RuleSet = serde_json::from_str(json).unwrap();
        assert_eq!(set.rules().len(), 1);
        assert_eq!(set.compiled().steps().len(), 1);
        assert_eq!(serde_json::to_string(&set).unwrap(), json);
        assert_eq!(set, RuleSet::new(set.rules().to_vec()).unwrap());
        assert_ne!(set, RuleSet::default());
        assert!(RuleSet::default().is_empty() && RuleSet::default().compiled().is_empty());
        // Stored destinations are taken as stored: a host a stricter policy
        // would now refuse still loads, and nothing is rewritten.
        let private = r#"[{"if":{"country":["US"]},"url":"HTTP://10.0.0.1/x"}]"#;
        let set: RuleSet = serde_json::from_str(private).unwrap();
        assert_eq!(set.compiled().urls(), ["HTTP://10.0.0.1/x"]);
        // Conditions are still checked.
        let bad = r#"[{"if":{"country":["USA"]},"url":"https://example.com/"}]"#;
        let err = serde_json::from_str::<RuleSet>(bad).unwrap_err();
        assert!(
            err.to_string().starts_with("rules[0].if.country[0]"),
            "{err}"
        );
        // A list past the limits is refused as a whole.
        let leaf = r#"{"if":{"country":["US"]},"url":"https://example.com/"}"#;
        let many = format!("[{}]", vec![leaf; MAX_RULES + 1].join(","));
        let err = serde_json::from_str::<RuleSet>(&many).unwrap_err();
        assert!(err.to_string().contains("at most 32 rules"), "{err}");
    }

    #[test]
    fn the_compiled_program_round_trips_and_evaluates_alike() {
        let written: Vec<Rule> = serde_json::from_str(
            r#"[{"if": {"all": [{"country": ["US", "CA"]}, {"not": {"os": ["ios"]}}]},
                 "url": "https://example.com/a"},
                {"if": {"any": [{"region": ["US-CA"]}, {"language": ["de"]},
                                {"referrer": ["news.example"]},
                                {"query": {"name": "src", "values": ["mail"]}},
                                {"time": {"days": ["mon"], "hours": ["22:00", "06:00"]}}]},
                 "url": "https://example.com/b"}]"#,
        )
        .unwrap();
        let set = RuleSet::new(written).unwrap();
        #[derive(Serialize, Deserialize)]
        struct Record {
            #[serde(with = "program")]
            rules: RuleSet,
        }
        let json = serde_json::to_string(&Record { rules: set.clone() }).unwrap();
        assert!(
            json.starts_with(r#"{"rules":{"steps":[{"test":{"country""#),
            "{json}"
        );
        let loaded: Record = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.rules, set);
        assert!(
            loaded.rules.rules().is_empty(),
            "the written form is not published"
        );
        assert_eq!(loaded.rules.compiled().needs, set.compiled().needs);
        let req = Request {
            now_ms: 1_794_832_200_000,
            accept_language: Some(b"de"),
            ..Request::default()
        };
        assert_eq!(loaded.rules.compiled().evaluate(&req), Some(1));
        assert_eq!(set.compiled().evaluate(&req), Some(1));
        // The written list (what records published before held) is refused.
        let old = r#"{"rules":[{"if":{"country":["US"]},"url":"https://example.com/"}]}"#;
        assert!(serde_json::from_str::<Record>(old).is_err());
    }

    #[test]
    fn a_program_that_breaks_a_promise_is_refused() {
        let leaf = |test: &str, t: &str, f: &str| {
            format!(r#"{{"test": {test}, "on_true": {t}, "on_false": {f}}}"#)
        };
        let program = |steps: &[String], urls: usize| {
            let urls: Vec<String> = (0..urls)
                .map(|i| format!("\"https://e.example/{i}\""))
                .collect();
            format!(
                r#"{{"steps": [{}], "urls": [{}]}}"#,
                steps.join(","),
                urls.join(",")
            )
        };
        let us = r#"{"country": [[85, 83]]}"#;
        let ok = program(
            &[
                leaf(us, r#"{"step": 1}"#, r#""default""#),
                leaf(r#"{"device": 1}"#, r#"{"rule": 0}"#, r#""default""#),
            ],
            1,
        );
        let rules: Rules = serde_json::from_str(&ok).unwrap();
        assert_eq!(rules.steps().len(), 2);
        assert_eq!(rules.needs, NEEDS_DEVICE);

        let bad = [
            // Backward, to itself, and past the end.
            program(&[leaf(us, r#"{"step": 0}"#, r#""default""#)], 1),
            program(&[leaf(us, r#"{"step": 1}"#, r#""default""#)], 1),
            // A rule that does not exist.
            program(&[leaf(us, r#"{"rule": 1}"#, r#""default""#)], 1),
            // Unsorted countries would break the binary search.
            program(
                &[leaf(
                    r#"{"country": [[85, 83], [68, 69]]}"#,
                    r#"{"rule": 0}"#,
                    r#""default""#,
                )],
                1,
            ),
            // Past the bounds.
            program(
                &vec![leaf(us, r#""default""#, r#""default""#); MAX_CONDITIONS + 1],
                1,
            ),
            program(&[], MAX_RULES + 1),
            format!(
                r#"{{"steps": [{}], "urls": ["https://e.example/"]}}"#,
                leaf(
                    &format!(
                        r#"{{"language": [{}]}}"#,
                        vec![r#""en""#; MAX_VALUES + 1].join(",")
                    ),
                    r#"{"rule": 0}"#,
                    r#""default""#
                )
            ),
            // Unknown fields and tests.
            r#"{"steps": [], "urls": [], "extra": 1}"#.to_owned(),
            program(
                &[leaf(r#"{"planet": 3}"#, r#"{"rule": 0}"#, r#""default""#)],
                1,
            ),
        ];
        for json in &bad {
            assert!(serde_json::from_str::<Rules>(json).is_err(), "{json}");
        }
        // Every list compile produces passes the same check.
        let compiled = compile(
            &serde_json::from_str::<Vec<Rule>>(
                r#"[{"if": {"query": {"name": "a", "values": ["1", "2"]}}, "url": "https://example.com/"},
                    {"if": {"time": {"after": "2020-01-01T00:00:00Z"}}, "url": "https://example.com/t"}]"#,
            )
            .unwrap(),
            Policy::default(),
        )
        .unwrap();
        let again: Rules =
            serde_json::from_str(&serde_json::to_string(&compiled).unwrap()).unwrap();
        assert_eq!(again, compiled);
    }
}
