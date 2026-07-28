// Ultraviolet — the wallet file as a consensus-critical transaction boundary.
//
// `formal/onetime.qnt` proves the replay discipline only under an assumption:
// the sign log survives restart and every process sees the latest value. This
// model opens that assumption. It separates:
//
//   visible   bytes returned by an ordinary read (possibly page cache only)
//   durable   bytes guaranteed to survive power loss
//   localA/B  snapshots held by two independent CLI processes
//   published signatures an observer can actually obtain
//
// Three implementation obligations follow:
//
//   1. one exclusive lock spans load -> decision -> durable save;
//   2. save means fsync before publish, not merely a successful write syscall;
//   3. replacement is atomic, so a torn write cannot destroy the last good log.
//
// The Rust bridge is `cli/src/durable.rs`: an OS file lock, a private
// same-directory temporary file, sync, rename, then directory sync.

module walletFile {
  const LOCKED: bool
  const SYNCED: bool
  const ATOMIC: bool

  pure val PAYLOADS = Set(10, 20)
  pure val IDLE = "idle"
  pure val LOADED = "loaded"
  pure val SIGNED = "signed"
  pure val PERSISTED = "persisted"

  // The last write visible to another process and the last write guaranteed to
  // survive power loss. A plain write updates only the former.
  var visible: Set[int]
  var durable: Set[int]
  // Each process makes its decision from its own load-time snapshot.
  var localA: Set[int]
  var localB: Set[int]
  var phaseA: str
  var phaseB: str
  // Empty, "a", or "b". When locking is disabled it remains empty.
  var lockOwner: str
  // Payloads whose WOTS signatures have escaped the process via publication.
  var published: Set[int]
  var fileValid: bool

  // Two different published payloads under one WOTS key are the safety failure.
  val noExposedKeyReuse: bool = published.size() <= 1
  // Publication is safe to retry only when every published payload remains in
  // the durable log after an immediate power loss.
  val publishedIsRemembered: bool =
    published.forall(payload => durable.contains(payload))
  // A failed replacement must leave the previous complete wallet readable.
  val walletFileSurvives: bool = fileValid

  action init = all {
    visible' = Set(),
    durable' = Set(),
    localA' = Set(),
    localB' = Set(),
    phaseA' = IDLE,
    phaseB' = IDLE,
    lockOwner' = "",
    published' = Set(),
    fileValid' = true,
  }

  action loadA = all {
    phaseA == IDLE,
    fileValid,
    not(LOCKED) or lockOwner == "",
    localA' = visible,
    phaseA' = LOADED,
    lockOwner' = if (LOCKED) "a" else lockOwner,
    visible' = visible,
    durable' = durable,
    localB' = localB,
    phaseB' = phaseB,
    published' = published,
    fileValid' = fileValid,
  }

  action loadB = all {
    phaseB == IDLE,
    fileValid,
    not(LOCKED) or lockOwner == "",
    localB' = visible,
    phaseB' = LOADED,
    lockOwner' = if (LOCKED) "b" else lockOwner,
    visible' = visible,
    durable' = durable,
    localA' = localA,
    phaseA' = phaseA,
    published' = published,
    fileValid' = fileValid,
  }

  // An empty snapshot authorizes a fresh payload.
  action signA = all {
    phaseA == LOADED,
    localA == Set(),
    nondet payload = oneOf(PAYLOADS)
    all {
      localA' = Set(payload),
      phaseA' = SIGNED,
      visible' = visible,
      durable' = durable,
      localB' = localB,
      phaseB' = phaseB,
      lockOwner' = lockOwner,
      published' = published,
      fileValid' = fileValid,
    }
  }

  action signB = all {
    phaseB == LOADED,
    localB == Set(),
    nondet payload = oneOf(PAYLOADS)
    all {
      localB' = Set(payload),
      phaseB' = SIGNED,
      visible' = visible,
      durable' = durable,
      localA' = localA,
      phaseA' = phaseA,
      lockOwner' = lockOwner,
      published' = published,
      fileValid' = fileValid,
    }
  }

  // A non-empty snapshot replays exactly what was already signed.
  action replayA = all {
    phaseA == LOADED,
    localA != Set(),
    phaseA' = SIGNED,
    visible' = visible,
    durable' = durable,
    localA' = localA,
    localB' = localB,
    phaseB' = phaseB,
    lockOwner' = lockOwner,
    published' = published,
    fileValid' = fileValid,
  }

  action replayB = all {
    phaseB == LOADED,
    localB != Set(),
    phaseB' = SIGNED,
    visible' = visible,
    durable' = durable,
    localA' = localA,
    localB' = localB,
    phaseA' = phaseA,
    lockOwner' = lockOwner,
    published' = published,
    fileValid' = fileValid,
  }

  action persistA = all {
    phaseA == SIGNED,
    visible' = localA,
    durable' = if (SYNCED) localA else durable,
    phaseA' = PERSISTED,
    localA' = localA,
    localB' = localB,
    phaseB' = phaseB,
    lockOwner' = lockOwner,
    published' = published,
    fileValid' = fileValid,
  }

  action persistB = all {
    phaseB == SIGNED,
    visible' = localB,
    durable' = if (SYNCED) localB else durable,
    phaseB' = PERSISTED,
    localA' = localA,
    localB' = localB,
    phaseA' = phaseA,
    lockOwner' = lockOwner,
    published' = published,
    fileValid' = fileValid,
  }

  action publishA = all {
    phaseA == PERSISTED,
    published' = published.union(localA),
    phaseA' = IDLE,
    localA' = Set(),
    lockOwner' = if (lockOwner == "a") "" else lockOwner,
    visible' = visible,
    durable' = durable,
    localB' = localB,
    phaseB' = phaseB,
    fileValid' = fileValid,
  }

  action publishB = all {
    phaseB == PERSISTED,
    published' = published.union(localB),
    phaseB' = IDLE,
    localB' = Set(),
    lockOwner' = if (lockOwner == "b") "" else lockOwner,
    visible' = visible,
    durable' = durable,
    localA' = localA,
    phaseA' = phaseA,
    fileValid' = fileValid,
  }

  // Power loss drops page-cache-only bytes and every in-process snapshot.
  action powerLoss = all {
    visible' = durable,
    durable' = durable,
    localA' = Set(),
    localB' = Set(),
    phaseA' = IDLE,
    phaseB' = IDLE,
    lockOwner' = "",
    published' = published,
    fileValid' = fileValid,
  }

  // In-place replacement may truncate the only good copy before failing.
  action tornWriteA = all {
    not(ATOMIC),
    phaseA == SIGNED,
    visible' = Set(),
    durable' = Set(),
    localA' = Set(),
    localB' = localB,
    phaseA' = IDLE,
    phaseB' = phaseB,
    lockOwner' = "",
    published' = published,
    fileValid' = false,
  }

  action tornWriteB = all {
    not(ATOMIC),
    phaseB == SIGNED,
    visible' = Set(),
    durable' = Set(),
    localA' = localA,
    localB' = Set(),
    phaseA' = phaseA,
    phaseB' = IDLE,
    lockOwner' = "",
    published' = published,
    fileValid' = false,
  }

  action stutter = all {
    visible' = visible, durable' = durable,
    localA' = localA, localB' = localB,
    phaseA' = phaseA, phaseB' = phaseB,
    lockOwner' = lockOwner, published' = published, fileValid' = fileValid,
  }

  action step = any {
    loadA, loadB, signA, signB, replayA, replayB,
    persistA, persistB, publishA, publishB,
    powerLoss, tornWriteA, tornWriteB, stutter,
  }
}

// Direct in-place write, no fsync, no inter-process serialization.
module current {
  import walletFile(LOCKED = false, SYNCED = false, ATOMIC = false).*
}

// Locking alone closes the process race but not the power-loss or torn-write
// failures.
module lockedBuffered {
  import walletFile(LOCKED = true, SYNCED = false, ATOMIC = false).*
}

// Atomic replacement preserves the previous complete file, but without sync a
// newly published payload can still exist only in volatile cache.
module lockedAtomicBuffered {
  import walletFile(LOCKED = true, SYNCED = false, ATOMIC = true).*
}

// Syncing closes the publication-before-durability gap, but an in-place write
// can still destroy the last complete wallet (including an earlier sign log)
// before the new bytes are valid.
module lockedSyncedInPlace {
  import walletFile(LOCKED = true, SYNCED = true, ATOMIC = false).*
}

// `cli/src/durable.rs`: exclusive transaction, synced replacement, atomic name.
module hardened {
  import walletFile(LOCKED = true, SYNCED = true, ATOMIC = true).*
}
