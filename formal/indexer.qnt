// Ultraviolet — a persistent Bitcoin index under a moving RPC view.
//
// `formal/reorg.qnt` models an ideal canonical-chain oracle. The implementation
// does not receive a snapshot: it asks `getblockhash` and `getblock` once per
// height and stores the result across processes. This model opens that boundary.
//
// It checks two independent failures:
//
//   mid-scan reorg
//     height 1 is read from fork A, the node reorganizes, and heights 2..3 are
//     read from fork B. Remembering only B's final tip hash certifies a mixed
//     index forever.
//
//   shorter reorg
//     an A index through height 3 sees a new B tip at height 2. Deleting only
//     height 3 leaves stale A records below the new tip and answers once before
//     the retained height-2 hash is compared.
//
// The Rust bridge is `btc/src/lib.rs`: every fetched block must extend the
// previous block/checkpoint, the indexed and post-scan tips must equal the
// captured tip, and shortening continues hash comparison below the new tip
// before any lookup can answer.

module scanner {
  const CHECK_SCAN_SNAPSHOT: bool
  const CHECK_SHORT_HASH: bool
  const ALLOW_MIDSCAN_REORG: bool
  const ALLOW_SHORT_REORG: bool

  pure val NONE = -1

  // "a" and "b" are two chains with different first occurrences at height 1.
  var fork: str
  var tip: int
  var cursor: int
  var lastFork: str
  var indexForks: Set[str]
  var indexedFirst: int
  // The backend returns a positive answer only when `ready`.
  var ready: bool

  def canonicalFirst: int = if (fork == "a") 1 else 2

  // A completed scan is one canonical snapshot, never a union of forks.
  val noMixedSnapshot: bool = not(ready) or indexForks.size() <= 1
  // Every positive first-occurrence answer agrees with the current chain.
  val answersCanonical: bool =
    not(ready) or indexedFirst == canonicalFirst

  action init = all {
    fork' = "a",
    tip' = 3,
    cursor' = 0,
    lastFork' = "",
    indexForks' = Set(),
    indexedFirst' = NONE,
    ready' = false,
  }

  action scanNext = all {
    cursor < tip,
    not(CHECK_SCAN_SNAPSHOT) or cursor == 0 or lastFork == fork,
    val nextHeight = cursor + 1
    all {
      indexedFirst' =
        if (indexedFirst == NONE and nextHeight == 1) canonicalFirst
        else indexedFirst,
      indexForks' = indexForks.union(Set(fork)),
      cursor' = nextHeight,
      lastFork' = fork,
      ready' = nextHeight == tip,
      fork' = fork,
      tip' = tip,
    }
  }

  // Same-height replacement while a multi-call scan is in flight.
  action reorgMidScan = all {
    ALLOW_MIDSCAN_REORG,
    fork == "a",
    cursor > 0,
    cursor < tip,
    fork' = "b",
    tip' = tip,
    cursor' = cursor,
    lastFork' = lastFork,
    indexForks' = indexForks,
    indexedFirst' = indexedFirst,
    ready' = false,
  }

  // A transactional scanner discards the staged range and starts again.
  action discardMovingSnapshot = all {
    CHECK_SCAN_SNAPSHOT,
    cursor > 0,
    lastFork != fork,
    cursor' = 0,
    lastFork' = "",
    indexForks' = Set(),
    indexedFirst' = NONE,
    ready' = false,
    fork' = fork,
    tip' = tip,
  }

  // The old index is complete at A/3; the replacement B chain is only height 2.
  action reorgToShorterFork = all {
    ALLOW_SHORT_REORG,
    fork == "a",
    cursor == 3,
    ready,
    fork' = "b",
    tip' = 2,
    cursor' = if (CHECK_SHORT_HASH) 0 else 2,
    lastFork' = if (CHECK_SHORT_HASH) "" else lastFork,
    indexForks' = if (CHECK_SHORT_HASH) Set() else indexForks,
    indexedFirst' = if (CHECK_SHORT_HASH) NONE else indexedFirst,
    ready' = not(CHECK_SHORT_HASH),
  }

  action stutter = all {
    fork' = fork, tip' = tip, cursor' = cursor, lastFork' = lastFork,
    indexForks' = indexForks, indexedFirst' = indexedFirst, ready' = ready,
  }

  action step = any {
    scanNext, reorgMidScan, discardMovingSnapshot, reorgToShorterFork, stutter,
  }
}

module midscanUnsafe {
  import scanner(
    CHECK_SCAN_SNAPSHOT = false,
    CHECK_SHORT_HASH = true,
    ALLOW_MIDSCAN_REORG = true,
    ALLOW_SHORT_REORG = false,
  ).*
}

module midscanSafe {
  import scanner(
    CHECK_SCAN_SNAPSHOT = true,
    CHECK_SHORT_HASH = true,
    ALLOW_MIDSCAN_REORG = true,
    ALLOW_SHORT_REORG = false,
  ).*
}

module shortUnsafe {
  import scanner(
    CHECK_SCAN_SNAPSHOT = true,
    CHECK_SHORT_HASH = false,
    ALLOW_MIDSCAN_REORG = false,
    ALLOW_SHORT_REORG = true,
  ).*
}

module shortSafe {
  import scanner(
    CHECK_SCAN_SNAPSHOT = true,
    CHECK_SHORT_HASH = true,
    ALLOW_MIDSCAN_REORG = false,
    ALLOW_SHORT_REORG = true,
  ).*
}
