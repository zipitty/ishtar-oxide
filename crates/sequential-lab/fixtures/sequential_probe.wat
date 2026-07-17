(module
  ;; One 64-KiB state page followed by an 8-MiB cache working set.
  (memory (export "memory") 129 129)

  (func (export "run")
    (param $role i32)
    (param $bit i32)
    (param $iterations i32)
    (param $state_len i32)
    (result i32)
    (local $i i32)
    (local $address i32)
    (local $acc i32)

    ;; Exercise and update the caller-owned state with identical work for every role.
    (local.set $i (i32.const 0))
    (block $state_done
      (loop $state_loop
        (br_if $state_done (i32.ge_u (local.get $i) (local.get $state_len)))
        (i32.store8
          (local.get $i)
          (i32.xor (i32.load8_u (local.get $i)) (i32.const 90)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $state_loop)))

    ;; Sender/control and probe all execute the same instruction shape. Policy chooses
    ;; the iteration count; a hot sender sweeps the complete 8-MiB region.
    (local.set $i (i32.const 0))
    (local.set $acc (i32.const 0x243f6a88))
    (block $work_done
      (loop $work_loop
        (br_if $work_done (i32.ge_u (local.get $i) (local.get $iterations)))
        (local.set $address
          (i32.add
            (i32.const 65536)
            (i32.and
              (i32.mul (local.get $i) (i32.const 64))
              (i32.const 0x007ffffc))))
        (local.set $acc
          (i32.xor
            (local.get $acc)
            (i32.load (local.get $address))))
        (i32.store
          (local.get $address)
          (i32.add (local.get $acc) (local.get $i)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $work_loop)))
    (local.get $acc))
)
