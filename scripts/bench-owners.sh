#!/usr/bin/env bash
# callgrind instructions per request, grouped by who owns the code.
#
# Reads callgrind dumps (the output of scripts/bench-callgrind.sh, built with
# CARGO_PROFILE_RELEASE_DEBUG=line-tables-only) and adds up each function's own instructions by
# owner: quinn, h3, podgate's HTTP/3 front, the internal HTTP/2 hop, the shared pipeline, TLS, the
# allocator and the rest. The owners and their rules are bench/owners.tsv. With two dumps it adds
# the difference of the second from the first (HTTP/3 minus HTTPS, or one run minus its repeat: the
# spread of the method).
#
#   scripts/bench-owners.sh OUT1 [OUT2]          # a bench-callgrind.sh output dir (dump + result.json)
#   scripts/bench-owners.sh -n 50000 callgrind.out.1234.1
#   scripts/bench-owners.sh --by file --top 8 OUT1
#
# Options:
#   -n N          requests the dump counted (default: `requests` of result.json beside it; with two
#                 dumps, one value for both)
#   --by sym|file sym (default): a function's own instructions go to the crate in its symbol, with
#                 `core::`/`alloc::` generics resolved to the crate named inside them. file: each line
#                 goes to the crate of its source file (inlined code counts where it was written);
#                 lines that no file rule matches stay with their function.
#   --top N       also list each owner's N biggest functions
#   -r FILE       rules (default bench/owners.tsv)
#
# A second table lists the instructions of calls into the allocator, libc memory and system call
# wrappers by the owner that made the call (inclusive, so it includes what those functions did).
set -euo pipefail

cd "$(dirname "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")")"
root=$PWD

die() {
  echo "bench-owners: $*" >&2
  exit 1
}

requests=
by=sym
top=0
inherit=
rules=bench/owners.tsv
inputs=()
while [ $# -gt 0 ]; do
  case "$1" in
  -n) requests=${2:?-n needs a number}; shift 2 ;;
  --by) by=${2:?--by needs sym or file}; shift 2 ;;
  --top) top=${2:?--top needs a number}; shift 2 ;;
  --inherit) inherit=1; shift ;;
  -r) rules=${2:?-r needs a file}; shift 2 ;;
  -h | --help) sed -n '2,/^set -/p' "${BASH_SOURCE[0]}" | sed '$d;s/^# \{0,1\}//'; exit 0 ;;
  -*) die "unknown option $1" ;;
  *) inputs+=("$1"); shift ;;
  esac
done
[ "${#inputs[@]}" -ge 1 ] && [ "${#inputs[@]}" -le 2 ] || die "give one or two dumps or output dirs"
[ "$by" = sym ] || [ "$by" = file ] || die "--by is sym or file"
[ -r "$rules" ] || die "$rules not readable"

dumps=()
counts=()
labels=()
for input in "${inputs[@]}"; do
  dir=
  if [ -d "$input" ]; then
    dir=$input
    dump=$(find "$input" -maxdepth 1 -name 'callgrind.out.*' -size +0 | sort | head -n1)
    [ -n "$dump" ] || die "no callgrind.out.* in $input"
  else
    dump=$input
    dir=$(dirname "$input")
  fi
  [ -r "$dump" ] || die "$dump not readable"
  n=$requests
  if [ -z "$n" ] && [ -r "$dir/result.json" ]; then n=$(jq -r '.requests' "$dir/result.json"); fi
  [[ ${n:-} =~ ^[0-9]+$ ]] && [ "$n" -gt 0 ] || die "no request count for $dump: pass -n"
  dumps+=("$dump")
  counts+=("$n")
  labels+=("$(basename "$(readlink -f "$dir")")")
done

# One awk pass over a dump: self cost per (function, file), and the cost of calls into libc.
# Prints TSV: T total_self header_total | O owner ir | F owner ir function file | E caller callee ir.
parse() { # tag dump
  awk -v tag="$1" -v by="$by" -v rules="$rules" -v root="$root/" -v inherit="$inherit" '
    function resolve(spec, table,   id, rest) {
      if (match(spec, /^\([0-9]+\)/)) {
        id = substr(spec, 2, RLENGTH - 2)
        rest = substr(spec, RLENGTH + 1)
        sub(/^ /, "", rest)
        if (rest != "") table[id] = rest
        return table[id]
      }
      return spec
    }
    function is_std(path,   i) {
      for (i = 1; i <= nstd; i++) if (path ~ std_re[i]) return 1
      return 0
    }
    # The first path in a symbol that is not a standard library path.
    function first_path(s,   rest, at, start, path) {
      rest = s
      while (match(rest, /(^|[^A-Za-z0-9_:])[A-Za-z_][A-Za-z0-9_]*::/)) {
        start = RSTART
        if (substr(rest, start, 1) !~ /[A-Za-z_]/) start++
        path = substr(rest, start)
        match(path, /^[A-Za-z0-9_:{}]+/)
        path = substr(path, 1, RLENGTH)
        if (!is_std(path)) return path
        rest = substr(rest, start + length(path))
      }
      return ""
    }
    function raw_owner(name,   i) {
      for (i = 1; i <= nraw; i++) if (name ~ raw_re[i]) return raw_own[i]
      return ""
    }
    function sym_owner(name,   o, path, i) {
      if (name in sym_cache) return sym_cache[name]
      o = raw_owner(name)
      if (o == "") {
        path = first_path(name)
        if (path != "") for (i = 1; i <= npath; i++) if (path ~ path_re[i]) { o = path_own[i]; break }
      }
      if (o == "") o = "other"
      sym_cache[name] = o
      return o
    }
    function file_owner(file,   i, f) {
      if (file in file_cache) return file_cache[file]
      f = file
      if (index(f, root) == 1) f = substr(f, length(root) + 1)
      else if (index(f, "/proc/self/cwd/") == 1) f = substr(f, 16)
      file_cache[file] = ""
      for (i = 1; i <= nfile; i++) if (f ~ file_re[i]) { file_cache[file] = file_own[i]; break }
      return file_cache[file]
    }
    BEGIN {
      while ((getline line < rules) > 0) {
        if (line ~ /^#/ || line ~ /^[ \t]*$/) continue
        n = split(line, f, "\t")
        if (n < 3) { print "bad rule: " line > "/dev/stderr"; exit 2 }
        if (f[1] == "std") std_re[++nstd] = f[3]
        else if (f[1] == "raw") { nraw++; raw_own[nraw] = f[2]; raw_re[nraw] = f[3]; known[f[2]] = 1 }
        else if (f[1] == "path") { npath++; path_own[npath] = f[2]; path_re[npath] = f[3]; known[f[2]] = 1 }
        else if (f[1] == "file") { nfile++; file_own[nfile] = f[2]; file_re[nfile] = f[3]; known[f[2]] = 1 }
        else if (f[1] == "neutral") neutral[f[2]] = 1
        else { print "bad rule kind: " line > "/dev/stderr"; exit 2 }
      }
      npos = 1
    }
    /^positions:/ { split($0, pw, " "); npos = length(pw) - 1; next }
    /^(totals|summary):/ { header_total = $0; sub(/^[a-z]+:[ \t]*/, "", header_total); split(header_total, hw, " "); header_total = hw[1]; next }
    /^fl=/ { cur_file = resolve(substr($0, 4), flname); next }
    /^(fi|fe)=/ { cur_file = resolve(substr($0, 4), flname); next }
    /^fn=/ { cur_fn = resolve(substr($0, 4), fnname); next }
    /^cfn=/ { callee = resolve(substr($0, 5), fnname); next }
    /^(cfi|cfl)=/ { resolve(substr($0, 5), flname); next }
    /^calls=/ { call = 1; next }
    /^[0-9+*-]/ {
      split($0, w, " ")
      cost = w[npos + 1] + 0
      if (call) {
        call = 0
        co = raw_owner(callee)
        if (co != "" && co !~ /^(tls|internal)/) edge[cur_fn SUBSEP co] += cost
        if (inherit != "") edge_all[cur_fn SUBSEP callee] += cost
        next
      }
      self[cur_fn SUBSEP cur_file] += cost
      total += cost
      next
    }
    END {
      for (key in self) {
        split(key, kv, SUBSEP)
        o = ""
        if (by == "file" && kv[2] != "" && kv[2] != "???") o = file_owner(kv[2])
        if (o == "") o = sym_owner(kv[1])
        own[o] += self[key]
        fown[o SUBSEP kv[1] SUBSEP kv[2]] += self[key]
        if (o in neutral) nself[kv[1]] += self[key]
        else conc[o] += self[key]
      }
      if (inherit != "") {
        # Charge library code (the neutral owners) to the owners that call it, in proportion to the
        # inclusive cost of each caller edge, so that `http::HeaderMap` called from the HTTP/3 layer
        # counts as HTTP/3 and the same call from the pipeline as the pipeline.
        for (o in known) if (!(o in neutral)) conc[o] += 0
        nE = 0
        for (key in edge_all) {
          split(key, kv, SUBSEP)
          if (kv[2] in nself) { nE++; eg[nE] = kv[1]; ef[nE] = kv[2]; ec[nE] = edge_all[key]; callin[kv[2]] += edge_all[key] }
        }
        for (it = 0; it < 12; it++) {
          delete nextd
          for (i = 1; i <= nE; i++) {
            og = sym_owner(eg[i])
            wt = ec[i] / callin[ef[i]]
            if (!(og in neutral)) nextd[ef[i] SUBSEP og] += wt
            else for (o in conc) if ((eg[i] SUBSEP o) in dd) nextd[ef[i] SUBSEP o] += wt * dd[eg[i] SUBSEP o]
          }
          delete dd
          for (key in nextd) dd[key] = nextd[key]
        }
        for (o in conc) charged[o] = conc[o]
        unresolved = 0
        for (fnm in nself) {
          got = 0
          for (o in conc) if ((fnm SUBSEP o) in dd) { charged[o] += nself[fnm] * dd[fnm SUBSEP o]; got += dd[fnm SUBSEP o] }
          if (got < 1) unresolved += nself[fnm] * (1 - got)
        }
        for (o in charged) printf "%s\tI\t%s\t%.0f\n", tag, o, charged[o]
        printf "%s\tI\tno concrete caller (roots, runtime entry)\t%.0f\n", tag, unresolved
      }
      printf "%s\tT\t%.0f\t%s\n", tag, total, header_total
      for (o in own) printf "%s\tO\t%s\t%.0f\n", tag, o, own[o]
      for (key in fown) { split(key, kv, SUBSEP); printf "%s\tF\t%s\t%.0f\t%s\t%s\n", tag, kv[1], fown[key], kv[2], kv[3] }
      for (key in edge) { split(key, kv, SUBSEP); printf "%s\tE\t%s\t%s\t%.0f\n", tag, sym_owner(kv[1]), kv[2], edge[key] }
    }' "$2"
}

tsv=$(mktemp)
trap 'rm -f "$tsv"' EXIT
for i in "${!dumps[@]}"; do
  parse "$((i + 1))" "${dumps[$i]}" >>"$tsv"
done

awk -F'\t' -v counts="$(IFS=,; echo "${counts[*]}")" -v labels="$(IFS=,; echo "${labels[*]}")" -v top="$top" -v by="$by" '
  function pad(s, w) { return sprintf("%-" w "s", s) }
  # Owners named "group: part" are rolled up under "group"; the parts are listed beneath it.
  function grp(o,   at) { at = index(o, ": "); return at ? substr(o, 1, at - 1) : "" }
  # Sorts list[1..n] by sortkey[list[i]], biggest first.
  function sort_by(list, n,   i, j, t) {
    for (i = 1; i <= n; i++) for (j = i + 1; j <= n; j++)
      if (sortkey[list[j]] + 0 > sortkey[list[i]] + 0) { t = list[i]; list[i] = list[j]; list[j] = t }
  }
  function head_row(first,   h, t) {
    h = pad(first, 40)
    for (t = 1; t <= nfiles; t++) h = h sprintf("%12s %7s", "ir/req " t, "% " t)
    if (nfiles == 2) h = h sprintf("%14s %9s", "2 minus 1", "of dump 1")
    return h
  }
  function fmt_row(label, x1, x2,   line, d) {
    line = pad(label, 40) sprintf("%12.0f %6.1f%%", x1 / req[1], 100 * x1 / sum[1])
    if (nfiles == 2) {
      d = x2 / req[2] - x1 / req[1]
      line = line sprintf("%12.0f %6.1f%%", x2 / req[2], 100 * x2 / sum[2]) sprintf("%+14.0f %8.1f%%", d, 100 * d / (sum[1] / req[1]))
    }
    return line
  }
  # One owner table of v[dump, owner], groups first, their parts under them.
  function table(v,   k, p, o, g, names, tops, nt, tl, gv, i, j, subs, ns, sl, sv) {
    for (k in v) { split(k, p, SUBSEP); names[p[2]] = 1 }
    for (o in names) {
      g = grp(o)
      if (g == "") g = o
      tops[g] = 1
      gv[1, g] += v[1, o] + 0
      gv[2, g] += v[2, o] + 0
    }
    nt = 0
    delete sortkey
    for (o in tops) { tl[++nt] = o; sortkey[o] = gv[1, o] + gv[2, o] }
    sort_by(tl, nt)
    print head_row("owner")
    for (i = 1; i <= nt; i++) {
      o = tl[i]
      print fmt_row(o, gv[1, o], gv[2, o])
      ns = 0
      delete sortkey
      for (j in names) if (grp(j) == o) { sl[++ns] = j; sortkey[j] = v[1, j] + v[2, j] }
      sort_by(sl, ns)
      for (j = 1; j <= ns; j++) print fmt_row("  " substr(sl[j], length(o) + 3), v[1, sl[j]] + 0, v[2, sl[j]] + 0)
    }
  }
  BEGIN { nfiles = split(counts, req, ","); split(labels, label, ",") }
  $2 == "T" { sum[$1] = $3; header[$1] = $4 + 0 }
  $2 == "O" { seen_owner[$3] = 1; ir[$1, $3] = $4 }
  $2 == "F" { nf[$1, $3]++; fi[$1, $3, nf[$1, $3]] = $4; fname[$1, $3, nf[$1, $3]] = $5; ffile[$1, $3, nf[$1, $3]] = $6 }
  $2 == "E" && $3 != $4 { seen_callee[$4] = 1; seen_caller[$3] = 1; edge[$1, $3, $4] += $5; calls[$1, $3] += $5 }
  $2 == "I" { seen_charged[$3] = 1; charged[$1, $3] = $4 }
  END {
    for (t = 1; t <= nfiles; t++) {
      printf "dump %d: %s (%s requests, owners by %s)\n", t, label[t], req[t], by
      if (header[t] != sum[t]) printf "  warning: function costs add up to %.0f, the dump says %.0f\n", sum[t], header[t]
    }
    print ""
    table(ir)
    print fmt_row("total", sum[1], sum[2])
    if (length(seen_charged) > 0) {
      print ""
      print "library code (allocator, libc, http, bytes, std, ...) charged to the owners that call it:"
      table(charged)
    }
    nc = 0
    for (c in seen_callee) callees[++nc] = c
    no = 0
    delete sortkey
    for (o in seen_caller) { cl[++no] = o; sortkey[o] = calls[1, o] + calls[2, o] }
    sort_by(cl, no)
    for (t = 1; t <= nfiles; t++) {
      print ""
      printf "dump %d: instructions per request of calls into libc, by the owner that called (inclusive)\n", t
      head = pad("caller", 40)
      for (k = 1; k <= nc; k++) head = head sprintf("  %s", callees[k])
      print head
      for (i = 1; i <= no; i++) {
        o = cl[i]
        line = pad(o, 40)
        any = 0
        for (k = 1; k <= nc; k++) { v = edge[t, o, callees[k]] / req[t]; if (v > 0) any = 1; line = line sprintf("  %10.0f", v) }
        if (any) print line
      }
    }
    if (top > 0) {
      no = 0
      delete sortkey
      for (o in seen_owner) { ol[++no] = o; sortkey[o] = ir[1, o] + ir[2, o] }
      sort_by(ol, no)
      for (t = 1; t <= nfiles; t++) {
        print ""
        printf "dump %d: the %d biggest functions of each owner (own instructions per request)\n", t, top
        for (i = 1; i <= no; i++) {
          o = ol[i]
          printf "%s\n", o
          for (r = 1; r <= top; r++) {
            best = 0
            for (k = 1; k <= nf[t, o]; k++) if (!used[t, o, k] && fi[t, o, k] > fi[t, o, best] + 0) best = k
            if (best == 0) break
            used[t, o, best] = 1
            printf "  %9.1f  %s  (%s)\n", fi[t, o, best] / req[t], substr(fname[t, o, best], 1, 200), ffile[t, o, best]
          }
        }
      }
    }
  }' "$tsv"
