use "pony_test"
use "tests"
use transport = "ssh_transport"

actor \nodoc\ Main is TestList
  new create(env: Env) =>
    PonyTest(env, this)

  new make() =>
    None

  fun tag tests(test: PonyTest) =>
    Tests.tests(test)
    transport.Main.make().tests(test)
