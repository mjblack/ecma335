require "option_parser"
require "json"
require "set"
require "./ecma335"

module Ecma335
  module Tool
    private def self.usage : String
      "Usage:\n" \
      "  ecma335-tool [--strict] [--json] <winmd-path> stats\n" \
      "  ecma335-tool [--strict] [--json] <winmd-path> list types [--namespace <ns>] [--limit <n> | --all] [--include-special]\n" \
      "  ecma335-tool [--strict] [--json] <winmd-path> list methods [--type <full-name>] [--limit <n> | --all]\n" \
      "  ecma335-tool [--strict] [--json] <winmd-path> show type <full-name>\n" \
      "  ecma335-tool [--strict] [--json] <winmd-path> show method <type#method>\n" \
      "  ecma335-tool [--strict] [--json] <winmd-path> show method --type <full-name> --name <method-name>\n" \
      "  ecma335-tool [--strict] [--json] <winmd-path> search <term> [--types] [--methods] [--case-sensitive] [--limit <n> | --all]\n\n" \
      "Commands:\n" \
      "  stats         Print metadata stream/table summary and parse diagnostics.\n" \
      "  list types    List parsed type full names.\n" \
      "  list methods  List parsed methods (optionally scoped to one type).\n" \
      "  show          Show detailed information for a type or method.\n" \
      "  search        Search types/methods by name.\n\n" \
      "Default limits:\n" \
      "  list/search   Results are capped at 50 unless --limit or --all is provided.\n\n" \
      "Global options:\n" \
      "  --strict      Enable strict parse mode (fails on skipped/unknown constructs).\n" \
      "  --json        Emit JSON output for all commands.\n" \
      "  -h, --help    Show this help."
    end

    private def self.fatal(message : String, code : Int32 = 1) : NoReturn
      STDERR.puts message
      STDERR.puts
      STDERR.puts usage
      exit(code)
    end

    private def self.normalize_global_args(args : Array(String)) : {Array(String), Bool, Bool}
      strict = false
      json_output = false
      remaining = [] of String
      args.each do |arg|
        if arg == "--strict"
          strict = true
        elsif arg == "--json"
          json_output = true
        else
          remaining << arg
        end
      end
      {remaining, strict, json_output}
    end

    def self.run(args : Array(String)) : Nil
      if args.empty? || args.includes?("--help") || args.includes?("-h")
        puts usage
        return
      end

      normalized_args, strict, json_output = normalize_global_args(args)
      winmd_path = normalized_args[0]?
      command = normalized_args[1]?
      fatal("Missing winmd path.") unless winmd_path
      fatal("Missing command.") unless command

      parsed = Ecma335.parse(winmd_path, strict: strict)
      command_args = normalized_args[2..]

      case command
      when "stats"
        cmd_stats(parsed, json_output)
      when "list"
        cmd_list(parsed, command_args, json_output)
      when "show"
        cmd_show(parsed, command_args, json_output)
      when "search"
        cmd_search(parsed, command_args, json_output)
      else
        fatal("Unknown command: #{command}")
      end
    rescue ex : ParseError
      fatal("Parse error: #{ex.message}")
    rescue ex : IO::Error
      message = ex.message || ""
      if message.downcase.includes?("broken pipe")
        exit(0)
      end
      fatal("I/O error: #{message}")
    rescue ex : Exception
      fatal("Error: #{ex.message}")
    end

    private def self.cmd_stats(parsed : ParsedAssembly, json_output : Bool) : Nil
      metadata = parsed.metadata_root
      tables = metadata.tables_stream
      interesting = [
        "TypeDef", "MethodDef", "Field", "Param", "AssemblyRef",
        "File", "ExportedType", "ManifestResource", "CustomAttribute",
      ]

      if json_output
        output = JSON.build(indent: "  ") do |json|
          json.object do
            json.field "kind", "stats"
            json.field "metadata_version", metadata.version_string
            json.field "streams" do
              json.array do
                metadata.streams.each do |stream|
                  json.object do
                    json.field "name", stream.name
                    json.field "offset", stream.offset
                    json.field "size", stream.size
                  end
                end
              end
            end
            if tables
              json.field "rows" do
                json.object do
                  interesting.each do |name|
                    json.field name, tables.row_count(name)
                  end
                end
              end
              json.field "coverage_ratio", tables.parse_coverage_ratio
              json.field "parsed_tables" do
                json.array { tables.parsed_tables.each { |name| json.string name } }
              end
              json.field "skipped_tables" do
                json.array { tables.skipped_tables.each { |name| json.string name } }
              end
            else
              json.field "tables_stream", nil
            end
          end
        end
        puts output
        return
      end

      puts "Metadata version: #{metadata.version_string}"
      puts "Streams:"
      metadata.streams.each do |stream|
        puts "  #{stream.name} offset=0x#{stream.offset.to_s(16)} size=#{stream.size}"
      end

      unless tables
        puts "No #~ tables stream was found."
        return
      end

      puts "Rows:"
      interesting.each do |name|
        puts "  #{name}: #{tables.row_count(name)}"
      end
      puts "Coverage: #{(tables.parse_coverage_ratio * 100).round(2)}%"
      puts "Parsed tables: #{tables.parsed_tables.join(", ")}"
      puts "Skipped tables: #{tables.skipped_tables.join(", ")}"
    end

    private def self.cmd_list(parsed : ParsedAssembly, args : Array(String), json_output : Bool) : Nil
      sub = args[0]?
      fatal("Missing list subcommand (types/methods).") unless sub
      list_args = args[1..]
      api = parsed.api_model
      fatal("API model is unavailable.") unless api

      case sub
      when "types"
        namespace_filter = nil
        limit = 50
        all = false
        include_special = false
        OptionParser.parse(list_args) do |parser|
          parser.on("--namespace NAMESPACE", "Filter by namespace") { |value| namespace_filter = value }
          parser.on("--limit N", "Result limit (default: 50)") { |value| limit = value.to_i }
          parser.on("--all", "Return all results (no limit)") { all = true }
          parser.on("--include-special", "Include special metadata types like <Module>") { include_special = true }
        end
        types = if namespace_filter
                  filter = namespace_filter.not_nil!
                  exact_or_nested = api.types.select do |type|
                    type.namespace_name == filter || type.namespace_name.starts_with?("#{filter}.")
                  end
                  if exact_or_nested.empty?
                    # If users pass what looks like a full type name (e.g. *.Apis),
                    # return that direct match instead of producing empty output.
                    direct = api.type?(filter)
                    direct ? [direct] : [] of ApiType
                  else
                    exact_or_nested
                  end
                else
                  api.types
                end
        unless include_special
          types = types.reject { |type| type.full_name == "<Module>" }
        end
        selected = all ? types : types.first(limit)
        if json_output
          output = JSON.build(indent: "  ") do |json|
            json.object do
              json.field "kind", "list.types"
              json.field "namespace_filter", namespace_filter
              json.field "include_special", include_special
              json.field "all", all
              json.field "limit", all ? nil : limit
              json.field "count", selected.size
              json.field "items" do
                json.array do
                  selected.each do |type|
                    json.object do
                      json.field "full_name", type.full_name
                      json.field "namespace", type.namespace_name
                      json.field "name", type.name
                      json.field "token", type.token ? "0x#{type.token.not_nil!.to_s(16)}" : nil
                    end
                  end
                end
              end
            end
          end
          puts output
        else
          print_type_list_nested_paths(selected, parsed)
        end
      when "methods"
        type_filter = nil
        limit = 50
        all = false
        OptionParser.parse(list_args) do |parser|
          parser.on("--type FULL_NAME", "Only methods from a specific type") { |value| type_filter = value }
          parser.on("--limit N", "Result limit (default: 50)") { |value| limit = value.to_i }
          parser.on("--all", "Return all results (no limit)") { all = true }
        end

        methods = [] of {String, String, String}
        api.types.each do |type|
          next if type_filter && type.full_name != type_filter
          type.methods.each do |method|
            signature = method.signature.try(&.to_signature_string(canonical: true)) || "<unknown>"
            methods << {type.full_name, method.name, signature}
          end
        end
        selected = all ? methods : methods.first(limit)
        if json_output
          output = JSON.build(indent: "  ") do |json|
            json.object do
              json.field "kind", "list.methods"
              json.field "type_filter", type_filter
              json.field "all", all
              json.field "limit", all ? nil : limit
              json.field "count", selected.size
              json.field "items" do
                json.array do
                  selected.each do |entry|
                    json.object do
                      json.field "type_full_name", entry[0]
                      json.field "method_name", entry[1]
                      json.field "signature_canonical", entry[2]
                    end
                  end
                end
              end
            end
          end
          puts output
        else
          selected.each do |entry|
            puts "#{entry[0]}##{entry[1]} #{entry[2]}"
          end
        end
      else
        fatal("Unknown list subcommand: #{sub}")
      end
    end

    private def self.cmd_search(parsed : ParsedAssembly, args : Array(String), json_output : Bool) : Nil
      term = args[0]?
      fatal("Missing search term.") unless term
      search_args = args[1..]
      api = parsed.api_model
      fatal("API model is unavailable.") unless api

      in_types = true
      in_methods = true
      case_sensitive = false
      limit = 50
      all = false

      OptionParser.parse(search_args) do |parser|
        parser.on("--types", "Search only types") do
          in_types = true
          in_methods = false
        end
        parser.on("--methods", "Search only methods") do
          in_methods = true
          in_types = false
        end
        parser.on("--case-sensitive", "Use case-sensitive matching") { case_sensitive = true }
        parser.on("--limit N", "Result limit (default: 50)") { |value| limit = value.to_i }
        parser.on("--all", "Return all results (no limit)") { all = true }
      end

      matches = [] of {String, String, String?}
      needle = case_sensitive ? term : term.downcase

      if in_types
        api.types.each do |type|
          hay = case_sensitive ? type.full_name : type.full_name.downcase
          if hay.includes?(needle)
            matches << {"type", type.full_name, nil}
          end
        end
      end

      if in_methods
        api.types.each do |type|
          type.methods.each do |method|
            candidate = "#{type.full_name}##{method.name}"
            hay = case_sensitive ? candidate : candidate.downcase
            if hay.includes?(needle)
              signature = method.signature.try(&.to_signature_string(canonical: true)) || "<unknown>"
              matches << {"method", candidate, signature}
            end
          end
        end
      end

      selected = all ? matches : matches.first(limit)
      if json_output
        output = JSON.build(indent: "  ") do |json|
          json.object do
            json.field "kind", "search"
            json.field "term", term
            json.field "case_sensitive", case_sensitive
            json.field "search_types", in_types
            json.field "search_methods", in_methods
            json.field "all", all
            json.field "limit", all ? nil : limit
            json.field "count", selected.size
            json.field "items" do
              json.array do
                selected.each do |match|
                  json.object do
                    json.field "match_kind", match[0]
                    json.field "name", match[1]
                    json.field "signature_canonical", match[2]
                  end
                end
              end
            end
          end
        end
        puts output
      else
        if selected.empty?
          puts "No matches."
        else
          selected.each do |match|
            if match[0] == "type"
              puts "type    #{match[1]}"
            else
              puts "method  #{match[1]} #{match[2] || "<unknown>"}"
            end
          end
        end
      end
    end

    private def self.cmd_show(parsed : ParsedAssembly, args : Array(String), global_json_output : Bool) : Nil
      sub = args[0]?
      fatal("Missing show subcommand (type/method).") unless sub
      raw_show_args = args[1..]
      show_args = [] of String
      json_output = global_json_output
      raw_show_args.each do |arg|
        if arg == "--json"
          json_output = true
        else
          show_args << arg
        end
      end
      api = parsed.api_model
      fatal("API model is unavailable.") unless api

      case sub
      when "type"
        full_name = show_args.join(" ").strip
        fatal("Missing full type name.") if full_name.empty?
        type = api.type?(full_name)
        fatal("Type not found: #{full_name}") unless type

        if json_output
          puts type_to_json(type)
        else
          puts "Type: #{type.full_name}"
          puts "Namespace: #{type.namespace_name}"
          puts "Name: #{type.name}"
          puts "Token: #{type.token ? "0x#{type.token.not_nil!.to_s(16)}" : "<none>"}"
          unless type.generic_params.empty?
            puts "Generic params: #{type.generic_params.join(", ")}"
          end
          if enclosing = type.enclosing_type
            puts "Enclosing type: #{enclosing}"
          end
          unless type.nested_types.empty?
            puts "Nested types: #{type.nested_types.join(", ")}"
          end
          unless type.interfaces.empty?
            puts "Interfaces: #{type.interfaces.join(", ")}"
          end
          unless type.custom_attributes.empty?
            puts "Attributes:"
            type.custom_attributes.each { |attr| puts "  - #{attr}" }
          end

          puts "Fields (#{type.fields.size}):"
          type.fields.each do |field|
            token = field.token ? "0x#{field.token.not_nil!.to_s(16)}" : "<none>"
            signature = field.signature || "<unknown>"
            canonical = SignatureCanonicalizer.new.canonicalize(signature)
            const = field.constant_value ? " const=#{field.constant_value}" : ""
            puts "  - #{field.name} [#{token}] :: #{canonical}#{const}"
          end

          puts "Methods (#{type.methods.size}):"
          type.methods.each do |method|
            token = method.token ? "0x#{method.token.not_nil!.to_s(16)}" : "<none>"
            signature = method.signature.try(&.to_signature_string(canonical: true)) || "<unknown>"
            native = if method.native_import
                       " native=#{method.native_module || "<unknown>"}!#{method.native_import}"
                     else
                       ""
                     end
            puts "  - #{method.name} [#{token}] #{signature}#{native}"
          end
        end
      when "method"
        type_name = nil
        method_name = nil
        parser = OptionParser.new
        parser.on("--type FULL_NAME", "Type full name") { |value| type_name = value }
        parser.on("--name METHOD_NAME", "Method name") { |value| method_name = value }
        parser.parse(show_args)

        if type_name.nil? || method_name.nil?
          joined = show_args.join(" ").strip
          if !joined.empty? && joined.includes?("#")
            parts = joined.split("#", 2)
            type_name = parts[0]?
            method_name = parts[1]?
          end
        end

        fatal("Provide method as <type#method> or with --type and --name.") unless type_name && method_name
        type = api.type?(type_name.not_nil!)
        fatal("Type not found: #{type_name}") unless type
        method = type.methods.find { |m| m.name == method_name }
        fatal("Method not found: #{type_name}##{method_name}") unless method

        if json_output
          puts method_to_json(type.full_name, method)
        else
          puts "Method: #{type.full_name}##{method.name}"
          puts "Token: #{method.token ? "0x#{method.token.not_nil!.to_s(16)}" : "<none>"}"
          if signature = method.signature
            puts "Signature (raw): #{signature.to_signature_string}"
            puts "Signature (canonical): #{signature.to_signature_string(canonical: true)}"
          else
            puts "Signature: <unknown>"
          end
          unless method.generic_params.empty?
            puts "Generic params: #{method.generic_params.join(", ")}"
          end
          if method.native_import
            puts "Native import: #{method.native_module || "<unknown>"}!#{method.native_import}"
          end

          if method.params.empty?
            puts "Params: <none>"
          else
            puts "Params:"
            method.params.each do |param|
              token = param.token ? "0x#{param.token.not_nil!.to_s(16)}" : "<none>"
              ptype = param.signature_type ? SignatureCanonicalizer.new.canonicalize(param.signature_type.not_nil!) : "<unknown>"
              const = param.constant_value ? " const=#{param.constant_value}" : ""
              puts "  - ##{param.sequence} #{param.name} [#{token}] :: #{ptype}#{const}"
            end
          end
        end
      else
        fatal("Unknown show subcommand: #{sub}")
      end
    end

    private def self.type_to_json(type : ApiType) : String
      canonicalizer = SignatureCanonicalizer.new
      JSON.build(indent: "  ") do |json|
        json.object do
          json.field "kind", "type"
          json.field "full_name", type.full_name
          json.field "namespace", type.namespace_name
          json.field "name", type.name
          json.field "token", type.token ? "0x#{type.token.not_nil!.to_s(16)}" : nil
          json.field "generic_params" do
            json.array do
              type.generic_params.each { |value| json.string value }
            end
          end
          json.field "enclosing_type", type.enclosing_type
          json.field "nested_types" do
            json.array do
              type.nested_types.each { |value| json.string value }
            end
          end
          json.field "interfaces" do
            json.array do
              type.interfaces.each { |value| json.string value }
            end
          end
          json.field "custom_attributes" do
            json.array do
              type.custom_attributes.each { |value| json.string value }
            end
          end
          json.field "fields" do
            json.array do
              type.fields.each do |field|
                json.object do
                  json.field "name", field.name
                  json.field "token", field.token ? "0x#{field.token.not_nil!.to_s(16)}" : nil
                  json.field "signature_raw", field.signature
                  json.field "signature_canonical", field.signature ? canonicalizer.canonicalize(field.signature.not_nil!) : nil
                  json.field "constant_value", field.constant_value
                end
              end
            end
          end
          json.field "methods" do
            json.array do
              type.methods.each do |method|
                json.object do
                  json.field "name", method.name
                  json.field "token", method.token ? "0x#{method.token.not_nil!.to_s(16)}" : nil
                  json.field "signature_raw", method.signature.try(&.to_signature_string)
                  json.field "signature_canonical", method.signature.try(&.to_signature_string(canonical: true))
                  json.field "generic_params" do
                    json.array do
                      method.generic_params.each { |value| json.string value }
                    end
                  end
                  json.field "native_module", method.native_module
                  json.field "native_import", method.native_import
                end
              end
            end
          end
        end
      end
    end

    private def self.method_to_json(type_full_name : String, method : ApiMethod) : String
      canonicalizer = SignatureCanonicalizer.new
      JSON.build(indent: "  ") do |json|
        json.object do
          json.field "kind", "method"
          json.field "type_full_name", type_full_name
          json.field "name", method.name
          json.field "token", method.token ? "0x#{method.token.not_nil!.to_s(16)}" : nil
          json.field "signature_raw", method.signature.try(&.to_signature_string)
          json.field "signature_canonical", method.signature.try(&.to_signature_string(canonical: true))
          json.field "generic_params" do
            json.array do
              method.generic_params.each { |value| json.string value }
            end
          end
          json.field "native_module", method.native_module
          json.field "native_import", method.native_import
          json.field "params" do
            json.array do
              method.params.each do |param|
                json.object do
                  json.field "name", param.name
                  json.field "sequence", param.sequence
                  json.field "token", param.token ? "0x#{param.token.not_nil!.to_s(16)}" : nil
                  json.field "signature_raw", param.signature_type
                  json.field "signature_canonical", param.signature_type ? canonicalizer.canonicalize(param.signature_type.not_nil!) : nil
                  json.field "constant_value", param.constant_value
                end
              end
            end
          end
        end
      end
    end

    private def self.print_type_list_nested_paths(types : Array(ApiType), parsed : ParsedAssembly) : Nil
      return if types.empty?

      types_by_token = Hash(UInt32, ApiType).new
      token_to_index = Hash(UInt32, Int32).new
      index_without_token = [] of Int32
      types.each_with_index do |type, idx|
        if token = type.token
          types_by_token[token] = type
          token_to_index[token] = idx
        else
          index_without_token << idx
        end
      end

      children_by_parent = Hash(Int32, Array(Int32)).new { |h, k| h[k] = [] of Int32 }
      child_index_set = Set(Int32).new

      if tables = parsed.metadata_root.tables_stream
        tables.nested_classes.each do |row|
          parent_token = 0x02000000_u32 | row.enclosing_class
          child_token = 0x02000000_u32 | row.nested_class
          parent_idx = token_to_index[parent_token]?
          child_idx = token_to_index[child_token]?
          next unless parent_idx && child_idx
          children_by_parent[parent_idx] << child_idx
          child_index_set.add(child_idx)
        end
      end

      roots = [] of Int32
      token_to_index.values.each do |idx|
        roots << idx unless child_index_set.includes?(idx)
      end
      roots.concat(index_without_token)

      roots = roots.sort_by { |idx| types[idx].full_name }
      printed = Set(Int32).new
      display_counts = Hash(String, Int32).new(0)
      roots.each do |root_idx|
        print_type_with_children(root_idx, types, children_by_parent, printed, types[root_idx].full_name, display_counts)
      end

      # Fallback for any disconnected/cyclic entries.
      leftovers = (0...types.size).to_a.reject { |idx| printed.includes?(idx) }.sort_by { |idx| types[idx].full_name }
      leftovers.each do |idx|
        print_type_with_children(idx, types, children_by_parent, printed, types[idx].full_name, display_counts)
      end
    end

    private def self.print_type_with_children(
      idx : Int32,
      types : Array(ApiType),
      children_by_parent : Hash(Int32, Array(Int32)),
      printed : Set(Int32),
      display_name : String,
      display_counts : Hash(String, Int32),
    ) : Nil
      return if printed.includes?(idx)
      printed.add(idx)
      type = types[idx]
      count = display_counts[display_name]
      display_counts[display_name] = count + 1
      if count == 0
        puts display_name
      else
        token_suffix = type.token ? " [0x#{type.token.not_nil!.to_s(16)}]" : " [dup #{count + 1}]"
        puts "#{display_name}#{token_suffix}"
      end

      children = children_by_parent[idx]? || [] of Int32
      children = children.reject { |child_idx| printed.includes?(child_idx) }
      children = children.sort_by { |child_idx| types[child_idx].full_name }
      children.each do |child_idx|
        child = types[child_idx]
        child_display = "#{display_name}.#{child.name}"
        print_type_with_children(child_idx, types, children_by_parent, printed, child_display, display_counts)
      end
    end
  end
end

Ecma335::Tool.run(ARGV)
