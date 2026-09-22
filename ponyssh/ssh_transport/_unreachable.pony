use @exit[None](status: I32)

primitive _Unreachable
  fun apply() => @exit(1)
