(module
  ;; The parent lays out the accumulated session state followed immediately by
  ;; the next input chunk. The worker uppercases the new bytes in place and
  ;; returns the new accumulated length.
  (memory (export "memory") 16 16)

  (func (export "process")
    (param $previous_len i32)
    (param $chunk_len i32)
    (param $capacity i32)
    (result i32)
    (local $i i32)
    (local $end i32)
    (local $byte i32)

    (local.set $end (i32.add (local.get $previous_len) (local.get $chunk_len)))
    (if
      (i32.or
        (i32.lt_u (local.get $end) (local.get $previous_len))
        (i32.gt_u (local.get $end) (local.get $capacity)))
      (then (return (i32.const -1))))

    (local.set $i (local.get $previous_len))
    (block $done
      (loop $loop
        (br_if $done (i32.ge_u (local.get $i) (local.get $end)))
        (local.set $byte (i32.load8_u (local.get $i)))
        (if
          (i32.and
            (i32.ge_u (local.get $byte) (i32.const 97))
            (i32.le_u (local.get $byte) (i32.const 122)))
          (then
            (i32.store8
              (local.get $i)
              (i32.sub (local.get $byte) (i32.const 32)))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $loop)))
    (local.get $end))
)
