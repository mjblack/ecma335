module Ecma335
  class SignatureCanonicalizer
    def canonicalize(type_name : String) : String
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
      value = value.gsub(/object/, "System.Object")
      value
    end

    private def unwrap_named(value : String, tag : String) : String
      value.gsub(/#{Regex.escape(tag)}\(([^()]*)\)/, "\\1")
    end

    private def transform_unary(value : String, tag : String, &block : String -> String) : String
      pattern = /#{Regex.escape(tag)}\(([^()]*)\)/
      current = value
      while match = pattern.match(current)
        start = match.begin(0)
        finish = match.end(0)
        replacement = yield(match[1])
        prefix = start > 0 ? current[0, start] : ""
        suffix = finish < current.bytesize ? current[finish, current.bytesize - finish] : ""
        current = "#{prefix}#{replacement}#{suffix}"
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
          replacement = "#{match[1]}[#{commas}]"
          start = match.begin(0)
          finish = match.end(0)
          prefix = start > 0 ? next_value[0, start] : ""
          suffix = finish < next_value.bytesize ? next_value[finish, next_value.bytesize - finish] : ""
          next_value = "#{prefix}#{replacement}#{suffix}"
        end
        break if next_value == current
        current = next_value
      end
      current
    end
  end
end
