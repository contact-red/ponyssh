/* This should probably be moved to the terminfo library */
use "files"
use "terminfo"
primitive TermInfos
  fun parse_term_info(term: String val, auth: FileAuth, vars: Array[String val] val = []): TermInfo val =>
    let dirs = recover val
      let a = Array[String val]
      // Standard terminfo search order
      try a.push(env_var(vars, "TERMINFO")?) end
      let home = try env_var(vars, "HOME")? else "" end
      if home.size() > 0 then a.push(home + "/.terminfo") end
      try
        let tdirs = env_var(vars, "TERMINFO_DIRS")?
        for d in tdirs.split(":").values() do
          if d.size() > 0 then a.push(d) end
        end
      end
      a.push("/usr/share/terminfo")
      a.push("/usr/lib/terminfo")
      a
    end

    let first_char = try
      String.from_array(recover val [term(0)?] end)
    else return TermInfo.none()
    end

    for dir in dirs.values() do
      let path = FilePath(auth, dir + "/" + first_char + "/" + term)
      match OpenFile(path)
      | let file: File =>
        match TIParser.parse(file)
        | let ti: TermInfo =>
          return ti
        | let e: TIParseError => None
        end
      end
    end
    TermInfo.none()

  fun env_var(vars: Array[String val] val, key: String): String ? =>
    """Look up an environment variable from Env.vars (Array of KEY=VALUE strings)."""
    let prefix: String val = key + "="
    for entry in vars.values() do
      if entry.at(prefix) then
        return entry.substring(prefix.size().isize())
      end
    end
    error
