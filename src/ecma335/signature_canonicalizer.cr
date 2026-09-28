module Ecma335
  # Rewrites signature-decoder type strings into a compact C#-like notation:
  #
  #   valuetype(Foo)            -> Foo
  #   ptr(int32)                -> int32*
  #   byref(Foo)                -> ref Foo
  #   szarray(uint8)            -> uint8[]
  #   array(Foo)[rank=2]        -> Foo[,]
  #   array(Foo)[32]            -> Foo[32]      (fixed-size, from WinMD)
  #   nativeint / nativeuint    -> nint / nuint
  #   object                    -> System.Object
  class SignatureCanonicalizer
    def canonicalize(type_name : String) : String
      value = type_name
      # Each pass only rewrites innermost forms (no nested parentheses), so
      # repeat until nothing changes to handle e.g. ptr(array(uint8)[4]).
      loop do
        next_value = canonicalize_pass(value)
        break if next_value == value
        value = next_value
      end
      value
    end

    private def canonicalize_pass(type_name : String) : String
      value = type_name
      value = unwrap_named(value, "valuetype")
      value = unwrap_named(value, "class")
      value = transform_unary(value, "ptr") { |inner| "#{inner}*" }
      value = transform_unary(value, "byref") { |inner| "ref #{inner}" }
      value = transform_unary(value, "szarray") { |inner| "#{inner}[]" }
      value = transform_array(value)
      value = transform_unary(value, "genericinst") { |inner| inner }
      value = value.gsub(/typedbyref/, "typedref")
      value = value.gsub(/nativeint/, "nint")
      value = value.gsub(/nativeuint/, "nuint")
      value = value.gsub(/\bobject\b/, "System.Object")
      value
    end

    private def unwrap_named(value : String, tag : String) : String
      value.gsub(/#{Regex.escape(tag)}\(([^()]*)\)/, "\\1")
    end

    private def transform_unary(value : String, tag : String, &block : String -> String) : String
      pattern = /#{Regex.escape(tag)}\(([^()]*)\)/
      current = value
      while match = pattern.match(current)
        current = splice(current, match.begin(0), match.end(0), yield(match[1]))
      end
      current
    end

    private def transform_array(value : String) : String
      current = value
      loop do
        next_value = current.gsub(/array\(([^()]*)\)\[\]/, "\\1[]")
        while match = /array\(([^()]*)\)\[rank=(\d+)\]/.match(next_value)
          rank = match[2].to_i
          commas = rank > 1 ? "," * (rank - 1) : ""
          next_value = splice(next_value, match.begin(0), match.end(0), "#{match[1]}[#{commas}]")
        end
        while match = /array\(([^()]*)\)\[(\d+(?:,\d+)*)\]/.match(next_value)
          next_value = splice(next_value, match.begin(0), match.end(0), "#{match[1]}[#{match[2]}]")
        end
        break if next_value == current
        current = next_value
      end
      current
    end

    private def splice(value : String, start : Int32, finish : Int32, replacement : String) : String
      prefix = start > 0 ? value[0, start] : ""
      suffix = finish < value.size ? value[finish, value.size - finish] : ""
      "#{prefix}#{replacement}#{suffix}"
    end
  end
end
