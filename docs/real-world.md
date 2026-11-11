# Real-world scan

What the scanner reports on public NEAR contract code that nobody wrote for it, and how many of those reports are right.

Run it yourself:

```
cargo build --release -p preflight
tools/realworld/scan.sh <workdir>
```

The script fetches the 14 repositories pinned by commit in `tools/realworld/repos.tsv`, scans them, and prints the findings
and the test files skipped per repository (sorted by findings, most first, then by test files skipped, and labelled repo-01 to repo-14 by that rank), the findings per rule and the verdict counts. The verdicts come from a
per-finding triage that is kept out of the repository (`tools/realworld/triage.local.tsv`, gitignored): it names files of
other people's projects beside verdicts, and that is the owner's call to publish. When the file is there, the script exits 1
when a finding has no row or a row has no finding, regenerates the counts from the rows and exits 1 when they differ from
the committed `tools/realworld/triage.tsv` (rule, verdict, count). Without it, only the per-rule totals are checked against
the committed counts. The cloned code is only read: never built, never run, and no project is contacted.

## What TRUE means

TRUE means the pattern the rule names is present in the pinned source. It is not a claim that any deployed contract is
exploitable: a deployed build may differ from the pinned source, a guard may live in an account or contract the scanner
cannot see, and the release profile decides whether an overflow wraps. Nothing here is a vulnerability report, and no
finding is attributed to a project in this document.

Verdicts, one per finding:

- TRUE: the pattern is there.
- DEFENSIBLE: the pattern is there, but a guard in another function, an invariant, a design choice, or the code being an example keeps the harm out.
- FALSE: the scanner is wrong.

## What was scanned

near-sdk-rs, core-contracts, intents, sputnik, linear, burrowland, metapool, paras, mintbase, rainbow, social-db, voting-v1,
near-linkdrop, gas-station (commits in `repos.tsv`).

Test code is not scanned: `#[cfg(test)]`, `#[test]` and `feature = "test"` items are stripped before any rule runs, and so
are the files below a `tests`, `compilation_tests` or `benches` directory that sits directly under a directory holding a
`Cargo.toml`. A directory that holds a `Cargo.toml` itself is a crate and is read even when it is called `tests` or lies
inside one (two stub contracts under `tests/` of the corpus are scanned this way), and a `src/tests` module is production
code and is read, and so is a file the manifest names as `[lib] path` or `[[bin]] path`. The report counts the files it skipped (104 on this corpus) and a scan that reads no file at all exits 2.
The web page runs the same code on the paths it is given (`scan_files`): a pasted file set or a GitHub tree is cut by the same
rule, with the `Cargo.toml` files among those paths, so a set with no manifest has no test directory; the page shows the count
of skipped files, and says in the result's sentence that they were skipped, when it is above zero, and a scan that reads no file is a failure message there too, never a clean result.
`examples/` is scanned: near-sdk-rs keeps whole contracts there.

## Before and after

"16 rules" is an early development state of the scanner (PF017 to PF026 did not exist, shown n/a). "26 rules" is the
first state with all 26 rules, before any was narrowed. "now" is the published code, after the blind-spot audit fixes,
the revert round that followed it and the precision round after that. The two earlier states are not in this repository's history, so only the "now"
column can be reproduced from it.

| rule | 16 rules | 26 rules | now |
|---|---|---|---|
| PF001 callback not private | 24 | 24 | 24 |
| PF002 one yocto | 30 | 30 | 7 |
| PF003 promise result | 14 | 14 | 4 |
| PF004 ghost balance | 1 | 1 | 0 |
| PF005 reentrancy | 0 | 0 | 0 |
| PF006 storage prefix | 9 | 9 | 0 |
| PF007 unguarded admin | 5 | 5 | 8 |
| PF008 storage deposit | 35 | 35 | 16 |
| PF009 unchecked token | 0 | 0 | 0 |
| PF010 self transfer mint | 0 | 0 | 0 |
| PF011 signer auth | 0 | 0 | 0 |
| PF012 div before mul | 5 | 5 | 2 |
| PF013 trait exposure | 1 | 1 | 0 |
| PF014 duplicate input | 0 | 0 | 0 |
| PF015 no rollback | 4 | 4 | 4 |
| PF016 unsaved state | 0 | 0 | 0 |
| PF017 ft receiver return | n/a | 0 | 0 |
| PF018 callback unwrap lock | n/a | 0 | 0 |
| PF019 resolve refund | n/a | 0 | 0 |
| PF020 uninitialized default | n/a | 29 | 2 |
| PF021 unbounded loop | n/a | 0 | 0 |
| PF022 overflow checks off | n/a | 31 | 22 |
| PF023 nep method auth | n/a | 0 | 0 |
| PF024 unregistered receiver | n/a | 0 | 0 |
| PF025 batch length | n/a | 1 | 1 |
| PF026 refund then panic | n/a | 0 | 0 |
| total | 128 | 189 | 90 |

Before the revert round this branch reported 67, 15 of them false. A re-audit found three narrowings that failed open on
snippets nobody had tried (a callback or setter skipped as harmless, a callback skipped because its guard looked hand-written,
a guard trusted for its name), and each went back to the stricter behaviour: the scanner no longer judges a callback by what
its body does, reports every self-callback without `#[private]`, and trusts no guard by its name. The 27 findings that came
back: 19 PF001 callbacks (14 guarded by hand with `assert_self()`, 5 example callbacks that only echo, log or sum an
argument), 5 findings in one contract whose methods are restricted by a library role check the crate does not define, 2 PF003
callbacks that do nothing with the result by design, and 1 PF012 rescale by a field. The 94 of that round were the price of a scanner that
cannot be talked out of a finding by a name or a shape. The precision round that followed cut 7 more, each by a guard or a
fact the scanner can see in the scanned files (below), and kept the rest, 87. A last audit found two of those cuts too wide:
a `#[private]` callback scheduled with an argument taken from the caller is still a write of the method that schedules it
(PF007), and an existing record may be overwritten for free only with a value of bounded size (PF008). Both went back, and
three findings came with them: 1 PF007 and 2 PF008, 90 now.

Rules that report nothing on these repositories were not exercised by this scan; their fixtures and unit tests are what
cover them.

## Triage

90 findings: 10 TRUE, 65 DEFENSIBLE, 15 FALSE.

| rule | TRUE | DEFENSIBLE | FALSE |
|---|---|---|---|
| PF001 | 1 | 23 | 0 |
| PF002 | 2 | 4 | 1 |
| PF003 | 0 | 3 | 1 |
| PF007 | 1 | 5 | 2 |
| PF008 | 1 | 5 | 10 |
| PF012 | 1 | 1 | 0 |
| PF015 | 1 | 3 | 0 |
| PF020 | 0 | 1 | 1 |
| PF022 | 3 | 19 | 0 |
| PF025 | 0 | 1 | 0 |

The TRUE findings are patterns in the pinned sources: a caller check missing from an `#[init(ignore_state)]` method, an
attached-deposit check missing from token-moving methods of an example, an unpaid storage entry in the same example, a
callback exported without `#[private]` in another example, an unchecked subtraction (three), a division before a
multiplication, and a balance removed before an unconfirmed transfer. Where they are, and whether the code is deployed, is
left out on purpose.

## Honest reading

15 of 90 findings are false, 17 percent. 65 more are defensible: real patterns with a reason the harm does not follow.
The false ones have these shapes:

1. Stub or mock contracts that only tests use, including workspace members under `tests/`: 4 findings (PF003, PF008, PF020).
   The scanner reads a crate that holds its own `Cargo.toml` even below `tests/`, and nothing in the source says the crate is a stub.
2. Prepaid storage accounting: 2 findings (PF008). The rule recognises a charge from the attached deposit or `storage_usage`,
   not a ledger of prepaid bytes.
3. A role-policy guard whose caller is always a contract: 1 finding (PF002).
4. A caller check written inside a closure (`opt.is_none_or(|a| a != caller)` followed by a returned error): 1 finding (PF007).
   Not cut: the value the caller is compared with comes from the call's own argument, not from the contract's state, and
   whether that restricts anyone depends on a hash the contract stored earlier, which is outside what the scan reads.
5. A role check made by a library call the crate does not define (`<Self as Rbac>::require_role(&Role::Administrator)`): the
   scanner trusts no guard by its name, so every method behind it is reported: 5 findings in one contract (PF007, PF008).
6. An existing record rewritten with a value the scanner follows from an unbounded parameter through types it cannot see: a
   parsed message whose fields are all `AccountId` and integers, and an enum argument that only decides a status: 2 findings (PF008).
   The new rule for an overwrite (a value of unbounded type from a parameter is still a finding) cannot tell what is inside a type
   it has no definition of, and it reports rather than guesses.

## Known false-alarm shapes

Not narrowed, because the scanner has no types and no cross-crate expansion:

- Guards that live in a library function from a crate outside the scan (shape 5), and in a macro from such a crate (a macro of a
  path dependency that is part of the scan is read, see below).
- Prepaid or ledger-style storage accounting (shape 2).
- Read-modify-write through an `Option`-returning helper whose `None` arm creates the entry. (One whose `None` arm panics or
  returns is an update and is recognised, see below.)
- `cfg(feature = ...)` other than `feature = "test"`: code gated behind any other feature is scanned as live.
- PF022 subtractions whose invariant is kept elsewhere: bookkeeping totals, percentages of an amount, and a deposit checked
  in the function that schedules the callback. They are reported as DEFENSIBLE because the pattern is genuinely there and
  only the build profile or one more check decides the outcome.
- PF002 on counters, not assets: a method that moves a storage-byte allowance or an escrow lock between entries of the same owner.
- PF007 with a check inside a closure (shape 4).
- PF008 on a record overwritten with a value computed from an unbounded parameter whose result is small (shape 6).

## What was narrowed, and why it does not blind the rule

Every narrowing below has a unit test that it holds and a test that the rule still fires on the unsafe sibling. The tests
are named; each is in the module of its rule (`scanner/src/rules/pfNNN_*.rs`, `guards.rs`, `scope.rs`, `scan.rs`).

Shared guard engine (`guards.rs`, used by PF001, PF007, PF008, PF013):

- A call counts as a caller check only when it is on every path through the function: a check inside an `if` branch, a
  `match` arm, a loop body or a closure is dropped. An equality counts only inside `require!`, `assert!`, `assert_eq!` or an
  `if` whose branch ends the call, never as a bare `==`. Test `an_equality_or_a_guard_that_does_not_decide_the_path_is_no_check`.
- No function or macro is trusted for its name. A call counts only when the crate defines it and its body checks the caller
  (through the graph), or when it is a known attribute (`#[private]`, near-plugins). A no-op `assert_owner` guards nothing, and
  neither does one the crate does not define (a sibling crate's `common::assert_owner`, a `use util::noop as assert_owner`).
  Tests `no_function_is_trusted_by_its_name` and `an_authority_name_the_crate_defines_is_decided_by_its_body`.
- A method call is followed as a call to the crate's own method only on `self` or on a field of `self` whose type the crate
  defines. `ext(..).x()` and `Promise::new(..).transfer()` never guard their caller, and a method of the same name on another
  type is a different method. Test `a_method_call_is_followed_only_on_self_or_on_a_field_of_that_type`.
- `#[pause]` and `#[if_paused]` gate on pause state, not on who calls. Test `a_pause_attribute_does_not_restrict_the_caller`.
- `#[private]` is checked in the exported wrapper, so it guards only the method it is written on; a near-plugins
  `#[access_control_any]` or `#[only]` writes its check into the function body, so it also guards the callers of that function.
  Test `private_guards_only_the_method_it_is_written_on_but_a_plugin_check_runs_in_its_callers_too`.

Per rule:

- PF001: not narrowed. Every self-callback without `#[private]` is reported, hand-guarded ones included (`assert_self()`,
  a caller comparison): the rule does not read bodies. A callback scheduled bare (`Self::ext(..)`) or from a helper is found
  (`a_self_call_written_bare_or_in_a_helper_is_a_callback`). Tests that the rule fires on what a reader might take for a guard:
  `a_callback_without_private_is_reported_however_it_is_guarded_by_hand`.
- PF002: a `#[macro_export]` macro of a crate this one depends on by `path`, when that crate is part of the same scan, is followed like a
  macro the crate defines (`a_macro_exported_by_a_path_dependency_that_reads_the_deposit_is_followed`, and for the linking itself
  `a_macro_is_imported_from_a_path_dependency_by_package_name_and_only_then`,
  `a_macro_that_is_not_exported_defined_twice_or_defined_by_the_crate_itself_is_not_imported` in `source.rs`). The dependency is found by
  package name in a `path` entry (or a `workspace = true` entry whose workspace definition has a `path`); a registry dependency, an
  unexported macro, a name two dependencies export and a name the crate defines itself are never imported. Fixes 2 false findings.
- PF002: the NEP receiver hooks by exact name only (`a_method_that_only_ends_in_on_transfer_is_not_a_receiver_hook`); a method
  every path of which panics, where any macro that is not a known panic may return
  (`nep_receiver_hooks_and_always_panicking_methods_are_clean`, `a_method_ending_in_an_unknown_macro_is_not_an_always_panic`);
  delegation to a library `internal_<name>` unless the crate defines it (`delegating_to_an_internal_function_of_a_library_is_clean_unless_the_crate_defines_it`);
  a method called on another value is not followed by name (`a_method_called_on_another_value_is_not_followed_by_name`).
- PF003: a result-reading wrapper by name, `promise_result*` or `*promise_success` (`a_wrapper_named_for_the_result_read_counts`). A callback
  that does nothing with the result is reported whatever it does otherwise.
- PF004: a callback attached with `.then(callback)` through a local, and every alternative of an `if`/`else` initializer must settle
  (`follows_a_promise_through_a_local_a_helper_and_a_wrapper`, `one_settling_callback_in_a_chain_is_enough`).
- PF007: a method named on a promise builder (`Promise::new(..)` or `Contract::ext(..)` and what is chained to it) runs in a later receipt, so it is
  no call to the crate's method of that name unless an argument passed to it comes from a parameter of the scheduling method: a write
  made by a `#[private]` callback handed nothing, a constant or contract state is not a write of the method that schedules it
  (`a_callback_scheduled_on_a_promise_builder_is_not_a_write_of_the_scheduler`; `self.on_done()`, `other.on_done()` and
  `Self::on_done(self)` are still followed). `#[private]` proves that the contract made the call, not that its arguments are
  trusted, so a callback handed caller data is followed
  (`a_callback_scheduled_with_data_from_the_caller_is_a_write_of_the_scheduler`,
  `a_private_callback_that_deploys_caller_supplied_code_is_flagged_through_its_scheduler`). Fixes 1 false finding, returns 1.
- PF007: an `#[init(ignore_state)]` method is a migration only when it reads the old state or is named for one
  (`ignore_state_is_a_migration_only_when_it_reads_state_or_is_named_for_one`); the guard rules above
  (`a_no_op_guard_a_promise_or_a_sibling_of_another_type_does_not_guard`, `a_guard_named_but_not_defined_in_the_crate_does_not_guard_a_setter`).
- PF008: a caller restriction by the shared guard engine (`only_an_equality_with_a_field_of_self_restricts_the_caller`); a
  read-modify-write of an entry fetched on every path to the store, with a panic on absence, by the same key
  (`a_fetch_that_does_not_insist_on_the_record_is_not_an_update`, `a_fetch_on_only_one_path_does_not_make_the_store_an_update`,
  `a_helper_name_defined_twice_in_the_crate_proves_nothing`).
- PF008 (continued): an entry is also known to exist inside `if let Some(..) = self.<field>.get(k)` (alone or before `&&`) and a `Some(..)` arm of
  a `match` on it, and after a `match` whose `None` arm panics or returns, and a method that is just `self.<field>.get(<parameter>)`, defined
  once, stands in for the `get`; an `else` or `None` arm that stores is still a new entry
  (`storing_back_a_record_found_or_refused_when_missing_is_an_update`, `a_method_that_is_not_just_a_lookup_proves_nothing`). Fixes 2 false findings.
- PF008 (overwrite): the existing-record exemption is for the entry, not for what is put in it. A value of unbounded type from a
  parameter, directly, through a local or written into the fetched record (`p.note = note`, `p.lines.extend(lines)`), is still a
  finding; a bounded value, and a record read back by a parameter that is only its key, are not
  (`overwriting_an_existing_record_with_unbounded_caller_data_is_still_a_finding`,
  `overwriting_an_existing_record_with_bounded_data_is_clean`, `a_name_shadowed_by_a_fetched_record_is_not_the_callers_data`).
  Returns 2 false findings (shape 6).
- PF012: a division of constants with no remainder, and a product divided again by the divisor of its quotient while the factor
  is a constant at most the divisor; a field, a parameter or a larger constant stays reported
  (`a_division_of_constants_with_a_remainder_or_a_variable_is_still_lossy`,
  `a_rescale_by_a_factor_larger_than_the_divisor_or_unknown_is_still_lossy`, `a_product_that_is_not_divided_by_the_same_divisor_is_still_lossy`);
  a local named for a count of whole units (`a_local_named_for_a_count_of_whole_units_is_an_intended_floor`, which lists names that stay reported).
- PF013: `set_` is privileged only when handed a value (`a_setter_that_is_handed_no_value_is_a_reset_not_configuration`), and the guard engine
  rules above (`a_no_op_owner_check_defined_in_the_crate_is_not_a_guard`).
- PF020: a manual `Default` that always panics, and a state with no fields
  (`a_default_that_does_anything_besides_panic_is_still_flagged`, `a_state_with_no_fields_is_not_flagged_but_a_state_with_fields_is`).
- PF022: a macro the crate defines once, or imports as above, whose pattern is a plain list of `$name:fragment` parameters is expanded where it is
  called, so `assert_storage_deposit!(cost)` over `if env::attached_deposit() < $required { .. }` is the comparison of the deposit with `cost` at that
  line; a subtraction inside a macro body is not reported at the call
  (`a_macro_that_compares_the_operands_is_a_guard_where_it_is_called`, `a_subtraction_inside_a_macro_body_is_not_reported_at_the_call`,
  `a_macro_exported_by_a_path_dependency_is_expanded_too`). A call after the subtraction, on other operands, with another argument count, to a
  macro defined twice or to an unknown one guards nothing. Fixes 2 false findings.
- PF022: `env::account_balance()` itself (`.as_yoctonear()` allowed) minus a storage cost, also through a local; a derived value such as
  `account_balance() / 2` or `.saturating_sub(locked)` stays reported (`the_balance_minus_the_storage_cost_cannot_wrap`,
  `other_subtractions_beside_storage_are_still_flagged`).
- Test scope: `feature = "test"` is test-only, other features and `not(test)` are kept (`a_cfg_predicate_is_test_only_only_when_it_cannot_hold_without_test`);
  `tests`, `compilation_tests` and `benches` are skipped only beside a `Cargo.toml` and never when they hold one, and `src/tests` is read
  (`integration_tests_and_benchmarks_are_not_walked_but_examples_are`, `a_crate_that_is_itself_called_tests_or_benches_is_walked`,
  `a_tests_module_below_src_is_production_code`); a file a manifest names as `[lib] path` or `[[bin]] path` is read wherever it lies
  (`a_target_the_manifest_declares_below_a_test_directory_is_read`, `declared_targets_are_the_lib_and_bin_paths_resolved`); a scan that reads no file is an error
  (`a_scan_that_reads_no_file_is_an_error_naming_the_skipped_test_files`, and the CLI test `a_scan_that_reads_no_file_exits_2_and_names_the_skipped_test_files`).
  The in-memory scan applies the same rule to the paths given (`test_directories_are_cut_in_memory_exactly_as_on_disk`,
  `a_file_set_is_cut_at_test_directories_beside_a_manifest_in_the_set`, and the wasm-versus-command-line test
  the test 'test directories are cut as on the command line' in `web/test/scanner.test.mjs`).

## Limits

What the scanner still gets wrong, one line each, so nobody reads a silent result as a clean one:

- PF020: a panicking `impl Default` is tied to the state type by its bare name, so one written for a same-named type in another module (`mod mock { pub struct Contract; }`) exempts the real state.
- PF012: constants are looked up by their last path segment, so two constants of one name in different modules can be confused (`SCALE` and `other::SCALE`), and a division is judged exact or lossy by the wrong one.
- A macro with a repetition (`$(..)*`) or a literal token in its pattern is not expanded (PF022) and a macro of a crate outside the scan is not read (PF002, PF022).
- PF004: a callback held in a local that a later branch reassigns (`let mut callback = ..undo(..); if c { callback = ..note(..); }`) is not followed, so the rule stays silent on a callback that does not settle.
- PF013: a trait method named `set_` with no argument (`set_frozen(&mut self)`) is read as a reset, not as configuration, so it is not reported without a caller check.
- PF003: a wrapper is trusted by its name, `promise_result*` or `*promise_success`; a crate function called `log_promise_success` that reads no result counts as reading one.
- PF007 and PF013 accept a caller that is merely named (`Mentioned`) as silence, so reading the caller on every path (a log line, a stored value) silences them without restricting anything. A caller comparison in only one branch does not silence them; one on every path does.
- PF001 does not follow a helper that returns the promise builder (`fn me() -> Contract { Self::ext(..) }`), so a callback scheduled through one is missed.
- A trait default method with a real check and an impl that overrides it with nothing: the default's check is counted for the impl, so the unguarded override is not reported.
- The type of a field is looked up by the field's name across the whole crate, not per struct: with `a: Real` in one struct and `a: Noop` in another, `self.a.check()` can be followed into the wrong type, so a no-op guard can pass for the real one (a missed finding).
- PF008: a caller checked against a getter (`require!(caller == self.owner())`, or through a local bound to one, `let owner = self.owner();`) is not recognised as a restriction, so the method is reported: a false alarm. A local bound to a field (`let owner = self.owner_id.clone();`) is recognised.
- `let ok = caller == owner; require!(ok)` is not recognised as a check; a guard call in only one branch, or in both, does not count.
- A call through a field whose type is not a struct of the same crate is not followed.
- PF022: locals are tracked by name over the whole function, so a storage-cost local that is reassigned (`cost = amount.0;`), or one rebound in an inner block (`let used = { let cost = storage..; cost };` after an outer `let cost = amount.0;`), is not told apart from the outer one; that can hide a real wrap or report a safe subtraction. For an account that holds locked stake, the balance-minus-storage exemption hides a real wrap (module doc of the rule).
- Test scope: an item gated by `cfg(feature = "test")` is dropped on the assumption it is test-only; a project that uses that feature name for production code has it skipped.
- A store or fetch made inside a helper rather than the exported method (PF008) is not seen.
