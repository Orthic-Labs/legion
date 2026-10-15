#!/usr/bin/env bash
# Rebuild the audit-bench fixture bundles from scratch.
#
#   evals/audit-bench/build-fixtures.sh <work-dir> [out-dir]
#
# <work-dir> must be absent or empty, on a large volume. Every commit uses a
# fixed author and date, so commit ids and tags are stable. Each case is one
# commit on its own detached branch off the `base` tag, tagged with the case id;
# cases never see one another's changes.
set -euo pipefail

work=${1:?usage: build-fixtures.sh <work-dir> [out-dir]}
here=$(cd "$(dirname "$0")" && pwd)
out=${2:-$here/fixtures}
mkdir -p "$work" "$out"
work=$(cd "$work" && pwd)
out=$(cd "$out" && pwd)

export GIT_AUTHOR_NAME="Bench Author" GIT_AUTHOR_EMAIL="bench@example.invalid"
export GIT_COMMITTER_NAME="Bench Author" GIT_COMMITTER_EMAIL="bench@example.invalid"
export GIT_AUTHOR_DATE="2026-01-01T00:00:00Z" GIT_COMMITTER_DATE="2026-01-01T00:00:00Z"
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null

put() { mkdir -p "$(dirname "$1")"; cat >"$1"; }

# sub <file> <old> <new>: replace exactly one occurrence of <old>.
sub() {
  python3 -I - "$1" "$2" "$3" <<'PY'
import sys
path, old, new = sys.argv[1:4]
text = open(path, encoding="utf-8").read()
if text.count(old) != 1:
    sys.exit(f"sub: expected one match in {path}: {old!r} (found {text.count(old)})")
open(path, "w", encoding="utf-8").write(text.replace(old, new))
PY
}

new_repo() { # name
  repo="$work/$1"
  if [ -e "$repo" ]; then
    echo "refusing to reuse existing $repo; pass a fresh work dir" >&2
    exit 1
  fi
  mkdir -p "$repo"
  cd "$repo"
  git init -q -b main
  git config commit.gpgsign false
  git config tag.gpgsign false
}

base_done() {
  git add -A
  git commit -q -m "base"
  git tag base
}

begin_case() { # message
  git checkout -q --detach base
  case_msg=$1
}

end_case() { # id
  git add -A
  git commit -q -m "$case_msg"
  git tag "$1"
}

bundle() { # name
  git checkout -q main
  git bundle create "$out/$1.bundle" --all >/dev/null 2>&1
  git bundle verify "$out/$1.bundle" >/dev/null 2>&1
}

# ---------------------------------------------------------------- rust-ledger
new_repo rust-ledger

put Cargo.toml <<'EOF'
[package]
name = "ledger"
version = "0.1.0"
edition = "2021"

[dependencies]
EOF

put src/lib.rs <<'EOF'
//! Tiny integer-cents ledger.
pub mod account;
pub mod auth;
pub mod error;
pub mod money;
pub mod report;
pub mod store;
pub mod transfer;
EOF

put src/error.rs <<'EOF'
#[derive(Debug, PartialEq, Eq)]
pub enum LedgerError {
    Frozen,
    Insufficient,
    InvalidAmount,
    InvalidName,
    Parse(String),
}
EOF

put src/money.rs <<'EOF'
use crate::error::LedgerError;

/// Amounts are integer cents.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Cents(pub i64);

impl Cents {
    pub fn checked_add(self, other: Cents) -> Option<Cents> {
        self.0.checked_add(other.0).map(Cents)
    }

    pub fn checked_sub(self, other: Cents) -> Option<Cents> {
        self.0.checked_sub(other.0).map(Cents)
    }

    pub fn is_negative(self) -> bool {
        self.0 < 0
    }
}

/// Split `total` into `parts` shares that differ by at most one cent; the first
/// `total % parts` shares get the extra cent. `None` when `parts` is zero.
pub fn split(total: Cents, parts: u32) -> Option<Vec<Cents>> {
    if parts == 0 {
        return None;
    }
    let n = i64::from(parts);
    let base = total.0 / n;
    let rem = total.0 % n;
    Some((0..n).map(|i| Cents(base + i64::from(i < rem))).collect())
}

/// Parse a decimal amount such as `12.34` (exactly two fractional digits).
pub fn parse_cents(text: &str) -> Result<Cents, LedgerError> {
    let (whole, frac) = text.split_once('.').unwrap_or((text, "00"));
    if frac.len() != 2 {
        return Err(LedgerError::Parse(text.to_string()));
    }
    let w: u64 = whole
        .parse()
        .map_err(|_| LedgerError::Parse(text.to_string()))?;
    let f: u64 = frac
        .parse()
        .map_err(|_| LedgerError::Parse(text.to_string()))?;
    Ok(Cents((w * 100 + f) as i64))
}
EOF

put src/account.rs <<'EOF'
use crate::error::LedgerError;
use crate::money::Cents;

#[derive(Clone, Debug)]
pub struct Account {
    pub id: u64,
    pub balance: Cents,
    pub frozen: bool,
}

impl Account {
    pub fn new(id: u64) -> Self {
        Account {
            id,
            balance: Cents(0),
            frozen: false,
        }
    }

    /// Remove `amount` from the balance. Frozen accounts cannot be debited and
    /// the balance never goes negative.
    pub fn debit(&mut self, amount: Cents) -> Result<(), LedgerError> {
        if self.frozen {
            return Err(LedgerError::Frozen);
        }
        match self.balance.checked_sub(amount) {
            Some(next) if !next.is_negative() => {
                self.balance = next;
                Ok(())
            }
            _ => Err(LedgerError::Insufficient),
        }
    }

    /// Add `amount` to the balance. Credits are allowed on frozen accounts.
    pub fn credit(&mut self, amount: Cents) -> Result<(), LedgerError> {
        match self.balance.checked_add(amount) {
            Some(next) => {
                self.balance = next;
                Ok(())
            }
            None => Err(LedgerError::InvalidAmount),
        }
    }
}
EOF

put src/transfer.rs <<'EOF'
use crate::account::Account;
use crate::error::LedgerError;
use crate::money::Cents;

/// Move `amount` from one account to another. A failed credit puts the money
/// back, so a transfer either happens completely or not at all.
pub fn transfer(from: &mut Account, to: &mut Account, amount: Cents) -> Result<(), LedgerError> {
    if amount.0 <= 0 {
        return Err(LedgerError::InvalidAmount);
    }
    from.debit(amount)?;
    if let Err(err) = to.credit(amount) {
        from.balance = Cents(from.balance.0 + amount.0);
        return Err(err);
    }
    Ok(())
}
EOF

put src/report.rs <<'EOF'
use crate::account::Account;
use crate::money::{split, Cents};

pub fn total_balance(accounts: &[Account]) -> Cents {
    Cents(accounts.iter().map(|a| a.balance.0).sum())
}

/// One line per account, ordered by id, with its share of the grand total.
pub fn statement(accounts: &[Account]) -> String {
    let total = total_balance(accounts).0;
    let mut ordered: Vec<&Account> = accounts.iter().collect();
    ordered.sort_by_key(|a| a.id);
    let mut out = String::new();
    for account in ordered {
        let pct = if total == 0 {
            0
        } else {
            account.balance.0 * 100 / total
        };
        out.push_str(&format!(
            "{:>6} {:>12} {:>3}%\n",
            account.id, account.balance.0, pct
        ));
    }
    out
}

/// Even per-account share of the grand total, for example a fee pool. Returns
/// the first account's share and the number of accounts.
pub fn first_share(accounts: &[Account]) -> Option<(Cents, usize)> {
    let shares = split(total_balance(accounts), accounts.len() as u32)?;
    Some((shares[0], accounts.len()))
}
EOF

put src/auth.rs <<'EOF'
/// Compare two tokens without returning early on the first differing byte.
pub fn verify_token(expected: &str, given: &str) -> bool {
    let a = expected.as_bytes();
    let b = given.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
EOF

put src/store.rs <<'EOF'
use std::path::{Path, PathBuf};

use crate::error::LedgerError;
use crate::money::{parse_cents, Cents};

/// Path of the balance file for `name` under `base`. A name is a single path
/// segment, never a path.
pub fn account_path(base: &Path, name: &str) -> Result<PathBuf, LedgerError> {
    if name.is_empty() || name.contains('/') || name.contains('\\') || name.contains("..") {
        return Err(LedgerError::InvalidName);
    }
    Ok(base.join(format!("{name}.bal")))
}

pub fn read_balance(base: &Path, name: &str) -> Result<Cents, LedgerError> {
    let path = account_path(base, name)?;
    let text =
        std::fs::read_to_string(&path).map_err(|e| LedgerError::Parse(e.to_string()))?;
    parse_cents(text.trim())
}
EOF
base_done

begin_case "store: allow any account name"
sub src/store.rs $'    if name.is_empty() || name.contains(\'/\') || name.contains(\'\\\\\') || name.contains("..") {' '    if name.is_empty() {'
end_case rust-sec-traversal

begin_case "auth: simplify token comparison"
sub src/auth.rs $'    let a = expected.as_bytes();\n    let b = given.as_bytes();\n    if a.len() != b.len() {\n        return false;\n    }\n    let mut diff = 0u8;\n    for (x, y) in a.iter().zip(b.iter()) {\n        diff |= x ^ y;\n    }\n    diff == 0' $'    expected.len() == given.len()\n        && expected\n            .bytes()\n            .zip(given.bytes())\n            .all(|(x, y)| x == y)'
sub src/auth.rs '/// Compare two tokens without returning early on the first differing byte.' '/// Compare two tokens.'
end_case rust-sec-timing

begin_case "money: spread the remainder"
sub src/money.rs 'i64::from(i < rem)' 'i64::from(i <= rem)'
end_case rust-corr-split-remainder

begin_case "transfer: drop redundant restore"
sub src/transfer.rs $'    if let Err(err) = to.credit(amount) {\n        from.balance = Cents(from.balance.0 + amount.0);\n        return Err(err);\n    }\n    Ok(())' $'    to.credit(amount)'
sub src/transfer.rs $'A failed credit puts the money\n/// back, so a transfer either happens completely or not at all.' 'The debit comes first.'
end_case rust-corr-transfer-rollback

begin_case "report: compute shares per line"
sub src/report.rs $'    let total = total_balance(accounts).0;\n    let mut ordered' $'    let mut ordered'
sub src/report.rs $'    for account in ordered {\n        let pct' $'    for account in ordered {\n        let total = total_balance(accounts).0;\n        let pct'
end_case rust-perf-statement-total

begin_case "money: add even split helper"
cat >>src/money.rs <<'EOF'

/// Split `total` evenly across `parts` shares.
pub fn split_even(total: Cents, parts: u32) -> Option<Vec<Cents>> {
    if parts == 0 {
        return None;
    }
    let n = i64::from(parts);
    let base = total.0 / n;
    let rem = total.0 % n;
    Some((0..n).map(|i| Cents(base + i64::from(i < rem))).collect())
}
EOF
end_case rust-lean-dead-duplicate

begin_case "account: let the transfer layer decide about frozen accounts"
sub src/account.rs $'        if self.frozen {\n            return Err(LedgerError::Frozen);\n        }\n        match self.balance.checked_sub' $'        match self.balance.checked_sub'
sub src/account.rs $'Remove `amount` from the balance. Frozen accounts cannot be debited and\n    /// the balance never goes negative.' 'Remove `amount` from the balance; the balance never goes negative.'
end_case rust-cr-frozen-debit

begin_case "money: return an empty split for zero parts"
sub src/money.rs $'    if parts == 0 {\n        return None;\n    }\n    let n = i64::from(parts);\n    let base = total.0 / n;\n    let rem = total.0 % n;\n    Some((0..n).map(|i| Cents(base + i64::from(i < rem))).collect())\n}\n\n/// Parse' $'    if parts == 0 {\n        return Some(Vec::new());\n    }\n    let n = i64::from(parts);\n    let base = total.0 / n;\n    let rem = total.0 % n;\n    Some((0..n).map(|i| Cents(base + i64::from(i < rem))).collect())\n}\n\n/// Parse'
sub src/money.rs '`None` when `parts` is zero.' 'Zero parts yields no shares.'
end_case rust-cr-split-empty

begin_case "money: document and test split"
sub src/money.rs '/// Amounts are integer cents.' '/// Amounts are integer cents. The wrapper keeps cents from mixing with other integers.'
cat >>src/money.rs <<'EOF'

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_conserves_total() {
        let shares = split(Cents(1001), 3).unwrap();
        assert_eq!(shares.iter().map(|c| c.0).sum::<i64>(), 1001);
    }

    #[test]
    fn split_zero_parts_is_none() {
        assert!(split(Cents(5), 0).is_none());
    }
}
EOF
end_case rust-clean-doc-tests

begin_case "transfer: extract restore helper"
sub src/transfer.rs $'        from.balance = Cents(from.balance.0 + amount.0);\n        return Err(err);\n    }\n    Ok(())\n}' $'        restore(from, amount);\n        return Err(err);\n    }\n    Ok(())\n}\n\nfn restore(from: &mut Account, amount: Cents) {\n    from.balance = Cents(from.balance.0 + amount.0);\n}'
end_case rust-clean-extract-restore

begin_case "account: add is_empty"
sub src/account.rs $'    /// Remove `amount`' $'    pub fn is_empty(&self) -> bool {\n        self.balance.0 == 0\n    }\n\n    /// Remove `amount`'
cat >>src/account.rs <<'EOF'

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_account_is_empty() {
        assert!(Account::new(1).is_empty());
    }
}
EOF
end_case rust-clean-is-empty
bundle rust-ledger

# ----------------------------------------------------------------- ts-orders
new_repo ts-orders

put package.json <<'EOF'
{
  "name": "orders",
  "version": "0.1.0",
  "private": true,
  "type": "module"
}
EOF

put tsconfig.json <<'EOF'
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "strict": true,
    "outDir": "dist"
  },
  "include": ["src"]
}
EOF

put src/db.ts <<'EOF'
export interface Db {
  query<T>(sql: string, params?: unknown[]): Promise<T[]>;
}
EOF

put src/money.ts <<'EOF'
/** Prices are decimal strings like "12.34"; amounts are integer cents. */
export function parsePrice(text: string): number {
  const match = /^(\d+)\.(\d{2})$/.exec(text);
  if (!match) {
    throw new Error(`invalid price: ${text}`);
  }
  return Number(match[1]) * 100 + Number(match[2]);
}

export function formatCents(cents: number): string {
  return `${Math.floor(cents / 100)}.${String(cents % 100).padStart(2, "0")}`;
}
EOF

put src/catalog.ts <<'EOF'
import type { Db } from "./db.js";

export interface Product {
  id: number;
  name: string;
  price: string;
}

/** Fetch many products with one query. */
export async function getProducts(db: Db, ids: number[]): Promise<Product[]> {
  if (ids.length === 0) {
    return [];
  }
  const marks = ids.map(() => "?").join(", ");
  return db.query<Product>(
    `SELECT id, name, price FROM products WHERE id IN (${marks})`,
    ids,
  );
}

export async function getProduct(db: Db, id: number): Promise<Product | undefined> {
  const rows = await getProducts(db, [id]);
  return rows[0];
}
EOF

put src/orders.ts <<'EOF'
import { getProducts } from "./catalog.js";
import type { Db } from "./db.js";
import { parsePrice } from "./money.js";

export interface OrderLine {
  productId: number;
  quantity: number;
}

/** Orders of 10000 cents (100.00) or more ship free. */
export const FREE_SHIPPING_THRESHOLD = 10000;

export async function orderSubtotal(db: Db, lines: OrderLine[]): Promise<number> {
  const products = await getProducts(
    db,
    lines.map((line) => line.productId),
  );
  const byId = new Map(products.map((product) => [product.id, product]));
  let total = 0;
  for (const line of lines) {
    const product = byId.get(line.productId);
    if (!product) {
      throw new Error(`unknown product ${line.productId}`);
    }
    total += parsePrice(product.price) * line.quantity;
  }
  return total;
}

export async function findOrdersByEmail(db: Db, email: string): Promise<unknown[]> {
  return db.query("SELECT id, total FROM orders WHERE email = ?", [email]);
}
EOF

put src/shipping.ts <<'EOF'
import { FREE_SHIPPING_THRESHOLD } from "./orders.js";

export function shippingCents(subtotal: number): number {
  return subtotal >= FREE_SHIPPING_THRESHOLD ? 0 : 599;
}
EOF

put src/checkout.ts <<'EOF'
import type { Db } from "./db.js";
import { orderSubtotal, type OrderLine } from "./orders.js";
import { shippingCents } from "./shipping.js";

export async function orderTotal(db: Db, lines: OrderLine[]): Promise<number> {
  const subtotal = await orderSubtotal(db, lines);
  return subtotal + shippingCents(subtotal);
}
EOF

put src/render.ts <<'EOF'
import { formatCents } from "./money.js";

export function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export function renderReceiptLine(name: string, cents: number): string {
  return `<li>${escapeHtml(name)} - ${formatCents(cents)}</li>`;
}
EOF
base_done

begin_case "orders: build the email lookup inline"
sub src/orders.ts '  return db.query("SELECT id, total FROM orders WHERE email = ?", [email]);' $'  return db.query(`SELECT id, total FROM orders WHERE email = \'${email}\'`);'
end_case ts-sec-sql-injection

begin_case "render: show product names as written"
sub src/render.ts '${escapeHtml(name)} - ' '${name} - '
end_case ts-sec-xss

begin_case "shipping: free shipping above the threshold"
sub src/shipping.ts 'subtotal >= FREE_SHIPPING_THRESHOLD' 'subtotal > FREE_SHIPPING_THRESHOLD'
end_case ts-corr-shipping-boundary

begin_case "orders: look products up line by line"
sub src/orders.ts 'import { getProducts } from "./catalog.js";' 'import { getProduct } from "./catalog.js";'
sub src/orders.ts $'  const products = await getProducts(\n    db,\n    lines.map((line) => line.productId),\n  );\n  const byId = new Map(products.map((product) => [product.id, product]));\n  let total = 0;\n  for (const line of lines) {\n    const product = byId.get(line.productId);' $'  let total = 0;\n  for (const line of lines) {\n    const product = await getProduct(db, line.productId);'
end_case ts-perf-per-line-lookup

begin_case "money: tolerate odd price strings"
sub src/money.ts $'  if (!match) {\n    throw new Error(`invalid price: ${text}`);\n  }\n  return' $'  if (!match) {\n    return 0;\n  }\n  return'
end_case ts-cr-parse-price-lenient

begin_case "orders: name the per-line amount"
sub src/orders.ts $'    total += parsePrice(product.price) * line.quantity;\n  }\n  return total;\n}' $'    total += lineCents(product.price, line.quantity);\n  }\n  return total;\n}\n\nfunction lineCents(price: string, quantity: number): number {\n  return parsePrice(price) * quantity;\n}'
end_case ts-clean-extract-line-cents

begin_case "orders: add status lookup"
cat >>src/orders.ts <<'EOF'

export async function findOrdersByStatus(db: Db, status: string): Promise<unknown[]> {
  return db.query("SELECT id, total FROM orders WHERE status = ?", [status]);
}
EOF
end_case ts-clean-status-lookup

begin_case "shipping: rename to shippingFeeCents"
sub src/shipping.ts 'export function shippingCents' 'export function shippingFeeCents'
sub src/checkout.ts 'import { shippingCents }' 'import { shippingFeeCents }'
sub src/checkout.ts 'subtotal + shippingCents(subtotal)' 'subtotal + shippingFeeCents(subtotal)'
end_case ts-clean-rename-shipping
bundle ts-orders

# --------------------------------------------------------- audit-behavior
new_repo audit-behavior

put package.json <<'EOF'
{
  "name": "audit-behavior",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "dependencies": { "redis": "4.6.14" }
}
EOF

put src/session.ts <<'EOF'
import type { RedisClientType } from "redis";

export function cacheSession(redis: RedisClientType, id: string, payload: string) {
  return redis.set(`session:${id}`, payload, { EX: 3600 });
}
EOF
base_done

begin_case "session: omit expiry from ephemeral Redis key"
sub src/session.ts 'return redis.set(`session:${id}`, payload, { EX: 3600 });' 'return redis.set(`session:${id}`, payload);'
end_case audit-redis-session-no-ttl

begin_case "session: add explicit expiring session key"
put src/session-safe.ts <<'EOF'
import type { RedisClientType } from "redis";

export function cacheEphemeralSession(redis: RedisClientType, id: string, payload: string) {
  return redis.set(`session:${id}`, payload, { EX: 900 });
}
EOF
end_case audit-redis-session-valid-ttl

begin_case "cache: keep process-local Map state"
put src/cache.ts <<'EOF'
const values = new Map<string, string>();

export function cacheValue(key: string, value: string) {
  return values.set(key, value);
}
EOF
end_case audit-map-set-clean

begin_case "installer: stream mutable URL to shell"
put scripts/install.sh <<'EOF'
#!/bin/sh
set -eu
curl -fsSL "https://downloads.example.invalid/agent/install.sh" | sh
EOF
chmod +x scripts/install.sh
end_case audit-executable-download-unpinned

begin_case "docs: link to installer instructions"
put README.md <<'EOF'
# Setup

See [installation instructions](https://docs.example.invalid/agent/install).
EOF
end_case audit-docs-url-clean

begin_case "sessions: retain both Redis key locations"
put src/sessions.ts <<'EOF'
import type { RedisClientType } from "redis";

export function cacheLogin(redis: RedisClientType, id: string, value: string) {
  return redis.set(`login:${id}`, value);
}

export function cacheRecovery(redis: RedisClientType, id: string, value: string) {
  return redis.set(`recovery:${id}`, value);
}
EOF
end_case audit-redis-two-locations
bundle audit-behavior

# -------------------------------------------------------------- py-inventory
new_repo py-inventory

put inventory/__init__.py <<'EOF'
"""Small in-memory inventory helpers."""
EOF

put inventory/stock.py <<'EOF'
"""In-memory stock levels keyed by upper-case SKU."""

_STOCK = {}


def normalize_sku(sku):
    return sku.strip().upper()


def set_stock(sku, qty):
    _STOCK[normalize_sku(sku)] = qty


def get_stock(sku):
    """Stock for `sku`; raises KeyError for an unknown SKU."""
    return _STOCK[normalize_sku(sku)]


def reserve(sku, qty):
    """Take `qty` units; unknown SKUs and short stock are errors."""
    key = normalize_sku(sku)
    if qty <= 0:
        raise ValueError("quantity must be positive")
    if _STOCK[key] < qty:
        raise ValueError("insufficient stock")
    _STOCK[key] -= qty
EOF

put inventory/pricing.py <<'EOF'
"""Pricing helpers. Prices are integer cents."""


def line_total(item: dict) -> int:
    return item["price"] * item["qty"]


def total(items: list[dict]) -> int:
    return sum(line_total(item) for item in items)


def apply_discount(items: list[dict], percent: int) -> list[dict]:
    """Return new items with prices reduced by `percent`; the input is not modified."""
    factor = 100 - percent
    return [{**item, "price": item["price"] * factor // 100} for item in items]
EOF

put inventory/quote.py <<'EOF'
from .pricing import apply_discount, total


def quote(items: list[dict], percent: int) -> dict:
    """Price a basket and show what the discount saves."""
    discounted = apply_discount(items, percent)
    return {
        "items": discounted,
        "before": total(items),
        "after": total(discounted),
    }
EOF

put inventory/tags.py <<'EOF'
from .stock import normalize_sku


def with_default_tags(sku: str, tags: list[str] | None = None) -> list[str]:
    """Tags for `sku`, plus a `sku:` tag; never modifies `tags`."""
    merged = list(tags) if tags is not None else []
    merged.append("sku:" + normalize_sku(sku))
    return merged
EOF

put inventory/snapshot.py <<'EOF'
import json


def save_snapshot(path: str, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle)


def load_snapshot(path: str) -> dict:
    """Snapshots may come from another host, so they are plain JSON."""
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)
EOF

put inventory/export.py <<'EOF'
import csv
import subprocess


def export_csv(rows: list[dict], path: str) -> None:
    fields = sorted({key for row in rows for key in row})
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def compress_export(path: str) -> None:
    """Gzip the export in place; `path` is derived from a caller-supplied name."""
    subprocess.run(["gzip", "-f", "--", path], check=True)
EOF
base_done

begin_case "snapshot: use pickle for faster loads"
put inventory/snapshot.py <<'EOF'
import json
import pickle


def save_snapshot(path: str, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle)


def load_snapshot(path: str) -> dict:
    """Load a snapshot written by another host."""
    with open(path, "rb") as handle:
        return pickle.load(handle)
EOF
end_case py-sec-pickle-load

begin_case "export: build the gzip command as a string"
sub inventory/export.py '    subprocess.run(["gzip", "-f", "--", path], check=True)' '    subprocess.run(f"gzip -f {path}", shell=True, check=True)'
end_case py-sec-shell-injection

begin_case "tags: share one default list"
put inventory/tags.py <<'EOF'
from .stock import normalize_sku


def with_default_tags(sku: str, tags: list[str] = []) -> list[str]:
    """Tags for `sku`, plus a `sku:` tag."""
    tags.append("sku:" + normalize_sku(sku))
    return tags
EOF
end_case py-corr-mutable-default

begin_case "pricing: pluggable rounding"
put inventory/pricing.py <<'EOF'
"""Pricing helpers. Prices are integer cents."""
from abc import ABC, abstractmethod


class RoundingStrategy(ABC):
    @abstractmethod
    def scale(self, price: int, factor: int) -> int:
        """Scale `price` by `factor` percent."""


class FloorRounding(RoundingStrategy):
    def scale(self, price: int, factor: int) -> int:
        return price * factor // 100


class RoundingFactory:
    @staticmethod
    def create(name: str = "floor") -> RoundingStrategy:
        if name == "floor":
            return FloorRounding()
        raise ValueError(f"unknown rounding: {name}")


def line_total(item: dict) -> int:
    return item["price"] * item["qty"]


def total(items: list[dict]) -> int:
    return sum(line_total(item) for item in items)


def apply_discount(items: list[dict], percent: int) -> list[dict]:
    """Return new items with prices reduced by `percent`; the input is not modified."""
    factor = 100 - percent
    rounding = RoundingFactory.create()
    return [{**item, "price": rounding.scale(item["price"], factor)} for item in items]
EOF
end_case py-lean-rounding-strategy

begin_case "pricing: discount in place to avoid copies"
sub inventory/pricing.py $'    """Return new items with prices reduced by `percent`; the input is not modified."""\n    factor = 100 - percent\n    return [{**item, "price": item["price"] * factor // 100} for item in items]' $'    """Reduce prices by `percent` in place and return the same list."""\n    factor = 100 - percent\n    for item in items:\n        item["price"] = item["price"] * factor // 100\n    return items'
end_case py-cr-discount-in-place

begin_case "stock: add docstrings and hints"
put inventory/stock.py <<'EOF'
"""In-memory stock levels keyed by upper-case SKU."""

_STOCK: dict[str, int] = {}


def normalize_sku(sku: str) -> str:
    """Canonical key for a SKU: trimmed and upper-case."""
    return sku.strip().upper()


def set_stock(sku: str, qty: int) -> None:
    """Set the stock level for `sku`."""
    _STOCK[normalize_sku(sku)] = qty


def get_stock(sku: str) -> int:
    """Stock for `sku`; raises KeyError for an unknown SKU."""
    return _STOCK[normalize_sku(sku)]


def reserve(sku: str, qty: int) -> None:
    """Take `qty` units; unknown SKUs and short stock are errors."""
    key = normalize_sku(sku)
    if qty <= 0:
        raise ValueError("quantity must be positive")
    if _STOCK[key] < qty:
        raise ValueError("insufficient stock")
    _STOCK[key] -= qty
EOF
end_case py-clean-stock-hints

begin_case "pricing: add format_cents with tests"
cat >>inventory/pricing.py <<'EOF'


def format_cents(cents: int) -> str:
    """Render integer cents as a decimal string such as `12.34`."""
    return f"{cents // 100}.{cents % 100:02d}"
EOF
put tests/test_pricing.py <<'EOF'
import unittest

from inventory.pricing import apply_discount, format_cents, total


class PricingTests(unittest.TestCase):
    def test_format_cents(self):
        self.assertEqual(format_cents(1234), "12.34")
        self.assertEqual(format_cents(5), "0.05")

    def test_discount_does_not_modify_input(self):
        items = [{"price": 1000, "qty": 2}]
        discounted = apply_discount(items, 10)
        self.assertEqual(total(items), 2000)
        self.assertEqual(total(discounted), 1800)


if __name__ == "__main__":
    unittest.main()
EOF
end_case py-clean-format-cents
bundle py-inventory

echo "built bundles in $out"
