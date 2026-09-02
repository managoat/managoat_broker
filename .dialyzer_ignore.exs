# Dialyzer warnings that are understood and deliberately kept, each with its
# reason. Entries are {file, warning_type, location}.
#
# Prefer `@dialyzer {:nowarn_function, name: arity}` beside the function: a
# location pin here is only stable while nothing above it in the file moves.
# Reach for this file when the warning has no single owning function, or when
# the code is inside a dependency. A stale entry shows up in
# `mix dialyzer --list-unused-filters`.
[
  # x509 0.9.x (the derived CA) references two types dialyzer does not know:
  # its own X509.ASN1.record/1 macro-type and :public_key's unexported
  # ec_private_key/0. Both are inside the dependency, not ours. Carried over
  # from BinaryBourbon/fountain's .dialyzer_ignore.exs at graduation.
  {"lib/x509/certificate.ex", :unknown_type, {20, 23}},
  {"lib/x509/private_key.ex", :unknown_type, {33, 57}}
]
