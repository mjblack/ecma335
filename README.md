# ecma335

ECMA 335 Parser

## Installation

1. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     ecma335:
       github: mjblack/ecma335
   ```

2. Run `shards install`

## Usage

```crystal
require "ecma335"

parsed = Ecma335.parse("winmd/Windows.Win32.winmd")

puts "Metadata version: #{parsed.metadata_root.version_string}"
parsed.metadata_root.streams.each do |stream|
  puts "#{stream.name}: offset=0x#{stream.offset.to_s(16)} size=#{stream.size}"
end

if tables = parsed.metadata_root.tables_stream
  puts "TypeDef rows: #{tables.row_count("TypeDef")}"
  puts "MethodDef rows: #{tables.row_count("MethodDef")}"
  puts "coverage: #{(tables.parse_coverage_ratio * 100).round(2)}%"
  p tables.skipped_tables

  tables.type_defs.first(5).each do |row|
    puts "TypeDef: #{row.type_namespace}.#{row.type_name}"
  end

  tables.method_defs.first(5).each do |row|
    puts "MethodDef: #{row.name} (rva=0x#{row.rva.to_s(16)})"
    if sig = row.decoded_signature
      params = sig.parameter_types.join(", ")
      puts "  signature: (#{params}) -> #{sig.return_type}"
      puts "  canonical: #{sig.to_signature_string(canonical: true)}"
    end
  end
end
```

## Consumer API

This library is parser-focused. It does not generate Crystal bindings directly.

`Ecma335.parse` also builds a normalized API model suitable for a separate generator app:

```crystal
parsed = Ecma335.parse("winmd/Windows.Win32.winmd")
api = parsed.api_model

if api
  type = api.type?("Windows.Win32.Foundation.HRESULT")
  p type.try(&.methods.size)
  p type.try(&.token)
  p type.try(&.generic_params)

  namespace_types = api.types_in_namespace("Windows.Win32.Foundation")
  puts "types in namespace: #{namespace_types.size}"

  method = api.method?("Windows.Win32.Foundation.HRESULT", "SomeMethod")
  p method.try(&.native_import)
  p method.try(&.token)
  p method.try(&.generic_params)
end

# Token-based metadata row helpers (TypeDef/MethodDef/Field)
p parsed.type_def_by_token?(0x02000001_u32).try(&.type_name)
p parsed.method_def_by_token?(0x06000001_u32).try(&.name)
p parsed.field_by_token?(0x04000001_u32).try(&.name)

# Optional strict mode: raise when parser has to skip undecoded tables.
strict_parsed = Ecma335.parse("winmd/Windows.Win32.winmd", strict: true)
```

## Development

Run tests:

```bash
crystal spec
```

Fetch `Windows.Win32.winmd` (uses the version pinned in `winmd.version`):

```bash
pwsh ./scripts/fetch-winmd.ps1
```

Override the version or output path:

```bash
pwsh ./scripts/fetch-winmd.ps1 -Version 70.0.11-preview
pwsh ./scripts/fetch-winmd.ps1 -OutputPath winmd/Windows.Win32.winmd
```

## WinMD Utility

This repo includes a small CLI utility for inspecting WinMD files:

```bash
crystal run src/ecma335_tool.cr -- winmd/Windows.Win32.winmd stats
crystal run src/ecma335_tool.cr -- winmd/Windows.Win32.winmd list types --limit 20
crystal run src/ecma335_tool.cr -- winmd/Windows.Win32.winmd list types --namespace Windows.Win32.UI.Controls
crystal run src/ecma335_tool.cr -- winmd/Windows.Win32.winmd list methods --type Windows.Win32.Foundation.HRESULT --limit 20
crystal run src/ecma335_tool.cr -- winmd/Windows.Win32.winmd list methods --all
crystal run src/ecma335_tool.cr -- winmd/Windows.Win32.winmd show type Windows.Win32.Foundation.HRESULT
crystal run src/ecma335_tool.cr -- winmd/Windows.Win32.winmd show method Windows.Win32.Foundation.HRESULT#SomeMethod
crystal run src/ecma335_tool.cr -- winmd/Windows.Win32.winmd show type Windows.Win32.Foundation.HRESULT --json
crystal run src/ecma335_tool.cr -- --json winmd/Windows.Win32.winmd stats
crystal run src/ecma335_tool.cr -- --json winmd/Windows.Win32.winmd list methods --limit 20
crystal run src/ecma335_tool.cr -- --json winmd/Windows.Win32.winmd search CreateFile --methods
crystal run src/ecma335_tool.cr -- winmd/Windows.Win32.winmd search CreateFile --methods --limit 20
crystal run src/ecma335_tool.cr -- winmd/Windows.Win32.winmd search CreateFile --methods --all
```

Notes:
- `list types` hides special metadata entries like `<Module>` by default.
- `list types` in text mode shows nested types as dotted paths (for example `ParentType._Anonymous_e__Union`).
- Use `--include-special` to include those entries.
- `--namespace` expects a namespace (for example `Windows.Win32.UI.Controls`), but if you pass an exact full type name it will still return that direct match.
- `list` and `search` default to `--limit 50`; use `--all` for uncapped output.

Or build and run the shard target:

```bash
shards build ecma335-tool
./bin/ecma335-tool winmd/Windows.Win32.winmd stats
```

Integration test behavior:

- `spec/ecma335_spec.cr` includes an integration example for `winmd/Windows.Win32.winmd`.
- If that file exists, the integration example runs by default.
- If the file is missing, that single integration example is marked pending with a helpful message.

## Contributing

1. Fork it (<https://github.com/mjblack/ecma335/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Matthew J. Black](https://github.com/mjblack) - creator and maintainer
