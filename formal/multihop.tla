--------------------------------- MODULE buggy ---------------------------------

EXTENDS Integers, Sequences, FiniteSets, TLC, Apalache, Variants

VARIABLE
  (*
    @type: (Int -> Int);
  *)
  buggy_protocol_recorded

VARIABLE
  (*
    @type: Set({ id: Int, input: Int, to: Str });
  *)
  buggy_protocol_bundles

VARIABLE
  (*
    @type: (Str -> Set(Int));
  *)
  buggy_protocol_held

(*
  @type: (() => Set(Str));
*)
buggy_protocol_HONEST == { "carol", "dave" }

(*
  @type: (() => Set(Str));
*)
buggy_protocol_ATTACKER == { "mallory", "mallory2" }

VARIABLE
  (*
    @type: (Int -> Set({ bundle: Int, nf: Int }));
  *)
  buggy_protocol_lineage

(*
  @type: (() => Set(Int));
*)
buggy_protocol_NOTE_IDS == 0 .. 4

VARIABLE
  (*
    @type: Int;
  *)
  buggy_protocol_nextNote

(*
  @type: (() => Bool);
*)
buggy_protocol_CHECK_ANCESTORS == FALSE

(*
  @type: (() => Set(Str));
*)
buggy_protocol_WALLETS == buggy_protocol_HONEST \union buggy_protocol_ATTACKER

(*
  @type: ((Int) => Bool);
*)
buggy_protocol_hasRecord(buggy_protocol_nf_54) ==
  buggy_protocol_nf_54 \in DOMAIN buggy_protocol_recorded

(*
  @type: (() => Bool);
*)
buggy_protocol_receiveAttacker ==
  (\E buggy_protocol_b \in buggy_protocol_bundles:
      buggy_protocol_b["to"] \in buggy_protocol_ATTACKER
        /\ buggy_protocol_held'
          := [
            buggy_protocol_held EXCEPT
              ![buggy_protocol_b["to"]] =
                buggy_protocol_held[buggy_protocol_b["to"]]
                  \union {buggy_protocol_b["id"]}
          ]
        /\ buggy_protocol_recorded' := buggy_protocol_recorded
        /\ buggy_protocol_bundles' := buggy_protocol_bundles
        /\ buggy_protocol_lineage' := buggy_protocol_lineage
        /\ buggy_protocol_nextNote' := buggy_protocol_nextNote)

(*
  @type: (() => Bool);
*)
buggy_protocol_init ==
  buggy_protocol_recorded = SetAsFun({})
    /\ buggy_protocol_bundles = {}
    /\ buggy_protocol_held
      = [
        buggy_protocol_w_161 \in buggy_protocol_WALLETS |->
          IF buggy_protocol_w_161 = "mallory" THEN {0} ELSE {}
      ]
    /\ buggy_protocol_lineage
      = [ buggy_protocol___168 \in buggy_protocol_NOTE_IDS |-> {} ]
    /\ buggy_protocol_nextNote = 1

(*
  @type: (() => Bool);
*)
buggy_protocol_buildBundle ==
  buggy_protocol_nextNote < 5
    /\ (\E buggy_protocol_from \in buggy_protocol_WALLETS:
      \E buggy_protocol_dest \in buggy_protocol_WALLETS:
        \E buggy_protocol_n \in buggy_protocol_held[buggy_protocol_from]
          \union {0}:
          buggy_protocol_n \in buggy_protocol_held[buggy_protocol_from]
            /\ buggy_protocol_bundles'
              := (buggy_protocol_bundles
                \union {[id |-> buggy_protocol_nextNote,
                  input |-> buggy_protocol_n,
                  to |-> buggy_protocol_dest]})
            /\ buggy_protocol_lineage'
              := [
                buggy_protocol_lineage EXCEPT
                  ![buggy_protocol_nextNote] =
                    buggy_protocol_lineage[buggy_protocol_n]
                      \union {[nf |-> buggy_protocol_n,
                        bundle |-> buggy_protocol_nextNote]}
              ]
            /\ buggy_protocol_nextNote' := (buggy_protocol_nextNote + 1)
            /\ buggy_protocol_recorded' := buggy_protocol_recorded
            /\ buggy_protocol_held' := buggy_protocol_held)

(*
  @type: (() => Bool);
*)
buggy_protocol_publishRecord ==
  (\E buggy_protocol_b \in buggy_protocol_bundles:
      ~(buggy_protocol_hasRecord(buggy_protocol_b["input"]))
        /\ buggy_protocol_recorded'
          := (LET (*
            @type: (() => (Int -> Int));
          *)
          __quint_var0 == buggy_protocol_recorded
          IN
          LET (*
            @type: (() => Set(Int));
          *)
          __quint_var1 == DOMAIN __quint_var0
          IN
          [
            __quint_var2 \in {buggy_protocol_b["input"]} \union __quint_var1 |->
              IF __quint_var2 = buggy_protocol_b["input"]
              THEN buggy_protocol_b["id"]
              ELSE (__quint_var0)[__quint_var2]
          ])
        /\ buggy_protocol_bundles' := buggy_protocol_bundles
        /\ buggy_protocol_held' := buggy_protocol_held
        /\ buggy_protocol_lineage' := buggy_protocol_lineage
        /\ buggy_protocol_nextNote' := buggy_protocol_nextNote)

(*
  @type: (({ id: Int, input: Int, to: Str }) => Bool);
*)
buggy_protocol_ancestryWins(buggy_protocol_b_107) ==
  \A buggy_protocol_h_105 \in buggy_protocol_lineage[buggy_protocol_b_107["id"]]:
    buggy_protocol_hasRecord(buggy_protocol_h_105["nf"])
      /\ buggy_protocol_recorded[buggy_protocol_h_105["nf"]]
        = buggy_protocol_h_105["bundle"]

(*
  @type: (({ id: Int, input: Int, to: Str }) => Bool);
*)
buggy_protocol_hopWins(buggy_protocol_b_80) ==
  buggy_protocol_hasRecord(buggy_protocol_b_80["input"])
    /\ buggy_protocol_recorded[buggy_protocol_b_80["input"]]
      = buggy_protocol_b_80["id"]

(*
  @type: ((Int) => Bool);
*)
buggy_protocol_isSpent(buggy_protocol_n_61) ==
  buggy_protocol_hasRecord(buggy_protocol_n_61)

(*
  @type: (() => Bool);
*)
q_init == buggy_protocol_init

(*
  @type: (({ id: Int, input: Int, to: Str }) => Bool);
*)
buggy_protocol_accepts(buggy_protocol_b_118) ==
  IF buggy_protocol_CHECK_ANCESTORS
  THEN buggy_protocol_ancestryWins(buggy_protocol_b_118)
  ELSE buggy_protocol_hopWins(buggy_protocol_b_118)

(*
  @type: (() => Set(Int));
*)
buggy_protocol_honestLive ==
  LET (*
    @type: ((Set(Int), Str) => Set(Int));
  *)
  __QUINT_LAMBDA0(buggy_protocol_acc_137, buggy_protocol_w_137) ==
    buggy_protocol_acc_137
      \union {
        buggy_protocol_n_134 \in buggy_protocol_held[buggy_protocol_w_137]:
          ~(buggy_protocol_isSpent(buggy_protocol_n_134))
      }
  IN
  ApaFoldSet(__QUINT_LAMBDA0, {}, (buggy_protocol_HONEST))

(*
  @type: (() => Bool);
*)
buggy_protocol_receiveHonest ==
  (\E buggy_protocol_b \in buggy_protocol_bundles:
      buggy_protocol_b["to"] \in buggy_protocol_HONEST
        /\ buggy_protocol_accepts(buggy_protocol_b)
        /\ buggy_protocol_held'
          := [
            buggy_protocol_held EXCEPT
              ![buggy_protocol_b["to"]] =
                buggy_protocol_held[buggy_protocol_b["to"]]
                  \union {buggy_protocol_b["id"]}
          ]
        /\ buggy_protocol_recorded' := buggy_protocol_recorded
        /\ buggy_protocol_bundles' := buggy_protocol_bundles
        /\ buggy_protocol_lineage' := buggy_protocol_lineage
        /\ buggy_protocol_nextNote' := buggy_protocol_nextNote)

(*
  @type: (() => Bool);
*)
buggy_protocol_noInflation == Cardinality((buggy_protocol_honestLive)) <= 1

(*
  @type: (() => Bool);
*)
buggy_protocol_step ==
  buggy_protocol_buildBundle
    \/ buggy_protocol_publishRecord
    \/ buggy_protocol_receiveHonest
    \/ buggy_protocol_receiveAttacker

(*
  @type: (() => Bool);
*)
q_inv == buggy_protocol_noInflation

(*
  @type: (() => Bool);
*)
q_step == buggy_protocol_step

================================================================================
