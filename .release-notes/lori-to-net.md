## Use the standard library's `net` package instead of lori

ponyssh's TCP layer now comes from the standard library's `net` package, which is lori brought into ponyc. lori is no longer a dependency, so `corral fetch` no longer downloads it, and `use "lori"` in your own code becomes `use "net"`. The types are unchanged: `TCPListenAuth`, `TCPConnectAuth`, `TCPConnection`, and the lifecycle receivers keep their names.

Before:

```pony
use "lori"
use "ssh_server"
```

After:

```pony
use "net"
use "ssh_server"
```

This requires ponyc 0.72.0 or later, the first release that ships `net`.
