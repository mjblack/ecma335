module Ecma335
  class CustomAttributeDecoder
    ELEMENT_BOOL    = 0x02_u8
    ELEMENT_CHAR    = 0x03_u8
    ELEMENT_I1      = 0x04_u8
    ELEMENT_U1      = 0x05_u8
    ELEMENT_I2      = 0x06_u8
    ELEMENT_U2      = 0x07_u8
    ELEMENT_I4      = 0x08_u8
    ELEMENT_U4      = 0x09_u8
    ELEMENT_I8      = 0x0A_u8
    ELEMENT_U8      = 0x0B_u8
    ELEMENT_R4      = 0x0C_u8
    ELEMENT_R8      = 0x0D_u8
    ELEMENT_STRING  = 0x0E_u8
    ELEMENT_SZARRAY = 0x1D_u8
    ELEMENT_TYPE    = 0x50_u8
    ELEMENT_BOXED   = 0x51_u8
    ELEMENT_FIELD   = 0x53_u8
    ELEMENT_PROP    = 0x54_u8
    ELEMENT_ENUM    = 0x55_u8

    # Legacy single-string rendering of an attribute blob. Kept for display and
    # for attributes whose constructor signature is unknown.
    def decode(blob : Bytes, type_name : String?) : String?
      return nil if blob.size < 2
      return nil unless blob[0] == 0x01_u8 && blob[1] == 0x00_u8

      if type_name
        if decoded = decode_known_attribute(type_name, blob)
          return decoded
        end
      end

      if type_name.try &.ends_with?("GuidAttribute")
        return decode_guid_attribute_blob(blob) || decode_single_string_attribute_blob(blob)
      end

      decode_simple_attribute_blob(blob)
    rescue ParseError
      nil
    end

    # Structured decoding (ECMA-335 II.23.3). `ctor_param_types` are the
    # constructor parameter types in signature-decoder notation ("int32",
    # "string", "valuetype(X)", "class(System.Type)", "object", "szarray(T)").
    # Returns the fixed arguments in order plus the named arguments by name, or
    # nil when the blob cannot be decoded with the given signature.
    def decode_args(blob : Bytes, ctor_param_types : Array(String)) : {Array(String), Hash(String, String)}?
      return nil if blob.size < 2
      return nil unless blob[0] == 0x01_u8 && blob[1] == 0x00_u8

      cursor = 2
      fixed = [] of String
      ctor_param_types.each do |param_type|
        element = element_for_param_type(param_type)
        return nil unless element
        value, cursor = read_typed_value(blob, cursor, element)
        fixed << value
      end

      named = Hash(String, String).new
      if cursor + 2 <= blob.size
        named_count = read_u16_le(blob, cursor)
        cursor += 2
        named_count.times do
          raise ParseError.new("Named argument is truncated") if cursor >= blob.size
          kind = blob[cursor]
          cursor += 1
          raise ParseError.new("Invalid named argument kind") unless kind == ELEMENT_FIELD || kind == ELEMENT_PROP
          element, cursor = read_field_or_prop_type(blob, cursor)
          name, cursor = read_ser_string(blob, cursor)
          value, cursor = read_typed_value(blob, cursor, element)
          named[name || "?"] = value
        end
      end

      {fixed, named}
    rescue ParseError | IndexError
      nil
    end

    # ---------------------------------------------------------------
    # Structured decoding helpers
    # ---------------------------------------------------------------

    private def element_for_param_type(param_type : String) : String?
      case param_type
      when "bool", "char", "int8", "uint8", "int16", "uint16", "int32", "uint32",
           "int64", "uint64", "float32", "float64", "string"
        param_type
      when "object"
        "boxed"
      when "class(System.Type)"
        "type"
      else
        if param_type.starts_with?("valuetype(")
          # Enum constructor parameter: the blob stores the underlying integer.
          # Every enum used by WinMD attribute constructors is Int32-backed.
          "enum"
        elsif param_type.starts_with?("szarray(") && param_type.ends_with?(")")
          inner = element_for_param_type(param_type[8...-1])
          inner ? "szarray:#{inner}" : nil
        else
          nil
        end
      end
    end

    private def read_field_or_prop_type(blob : Bytes, cursor : Int32) : {String, Int32}
      raise ParseError.new("Named argument type is truncated") if cursor >= blob.size
      tag = blob[cursor]
      cursor += 1
      case tag
      when ELEMENT_BOOL   then {"bool", cursor}
      when ELEMENT_CHAR   then {"char", cursor}
      when ELEMENT_I1     then {"int8", cursor}
      when ELEMENT_U1     then {"uint8", cursor}
      when ELEMENT_I2     then {"int16", cursor}
      when ELEMENT_U2     then {"uint16", cursor}
      when ELEMENT_I4     then {"int32", cursor}
      when ELEMENT_U4     then {"uint32", cursor}
      when ELEMENT_I8     then {"int64", cursor}
      when ELEMENT_U8     then {"uint64", cursor}
      when ELEMENT_R4     then {"float32", cursor}
      when ELEMENT_R8     then {"float64", cursor}
      when ELEMENT_STRING then {"string", cursor}
      when ELEMENT_TYPE   then {"type", cursor}
      when ELEMENT_BOXED  then {"boxed", cursor}
      when ELEMENT_ENUM
        _enum_type, cursor = read_ser_string(blob, cursor)
        {"enum", cursor}
      when ELEMENT_SZARRAY
        inner, cursor = read_field_or_prop_type(blob, cursor)
        {"szarray:#{inner}", cursor}
      else
        raise ParseError.new("Unsupported named argument element type 0x#{tag.to_s(16)}")
      end
    end

    private def read_typed_value(blob : Bytes, cursor : Int32, element : String) : {String, Int32}
      case element
      when "bool"
        {(blob[cursor] != 0_u8).to_s, cursor + 1}
      when "char"
        {read_u16_le(blob, cursor).chr.to_s, cursor + 2}
      when "int8"
        {blob[cursor].unsafe_as(Int8).to_s, cursor + 1}
      when "uint8"
        {blob[cursor].to_s, cursor + 1}
      when "int16"
        {read_u16_le(blob, cursor).unsafe_as(Int16).to_s, cursor + 2}
      when "uint16"
        {read_u16_le(blob, cursor).to_s, cursor + 2}
      when "int32", "enum"
        {read_u32_le(blob, cursor).unsafe_as(Int32).to_s, cursor + 4}
      when "uint32"
        {read_u32_le(blob, cursor).to_s, cursor + 4}
      when "int64"
        {read_u64_le(blob, cursor).unsafe_as(Int64).to_s, cursor + 8}
      when "uint64"
        {read_u64_le(blob, cursor).to_s, cursor + 8}
      when "float32"
        {IO::ByteFormat::LittleEndian.decode(Float32, blob[cursor, 4]).to_s, cursor + 4}
      when "float64"
        {IO::ByteFormat::LittleEndian.decode(Float64, blob[cursor, 8]).to_s, cursor + 8}
      when "string", "type"
        value, cursor = read_ser_string(blob, cursor)
        {value || "null", cursor}
      when "boxed"
        inner, cursor = read_field_or_prop_type(blob, cursor)
        read_typed_value(blob, cursor, inner)
      else
        if element.starts_with?("szarray:")
          inner = element[8..]
          count = read_u32_le(blob, cursor)
          cursor += 4
          return {"null", cursor} if count == 0xFFFFFFFF_u32
          items = [] of String
          count.times do
            item, cursor = read_typed_value(blob, cursor, inner)
            items << item
          end
          {"[#{items.join(", ")}]", cursor}
        else
          raise ParseError.new("Unsupported attribute element #{element}")
        end
      end
    end

    # SerString: 0xFF for null, otherwise compressed length + UTF-8 bytes.
    private def read_ser_string(blob : Bytes, cursor : Int32) : {String?, Int32}
      raise ParseError.new("SerString is truncated") if cursor >= blob.size
      return {nil, cursor + 1} if blob[cursor] == 0xFF_u8
      length, cursor = read_compressed_uint(blob, cursor)
      finish = cursor + length.to_i
      raise ParseError.new("SerString is truncated") if finish > blob.size
      {String.new(blob[cursor, length.to_i]), finish}
    end

    # ---------------------------------------------------------------
    # Legacy string rendering
    # ---------------------------------------------------------------

    private def decode_simple_attribute_blob(blob : Bytes) : String?
      payload_size = blob.size - 2
      return "blob(0 bytes)" if payload_size == 0
      return "blob(#{payload_size} bytes)" if payload_size < 2

      named_count = blob[-2].to_u16 | (blob[-1].to_u16 << 8)
      fixed_payload = blob[2, blob.size - 4]

      if named_count == 0_u16
        return "no-args" if fixed_payload.empty?

        string_arg = read_ser_string_if_exact(fixed_payload)
        return "string(#{string_arg})" if string_arg

        case fixed_payload.size
        when 1
          return "bool(#{fixed_payload[0] != 0_u8})"
        when 2
          value = fixed_payload[0].to_u16 | (fixed_payload[1].to_u16 << 8)
          return "u16(#{value})"
        when 4
          value = fixed_payload[0].to_u32 |
                  (fixed_payload[1].to_u32 << 8) |
                  (fixed_payload[2].to_u32 << 16) |
                  (fixed_payload[3].to_u32 << 24)
          return "u32(#{value})"
        end
      end

      "blob(#{payload_size} bytes)"
    end

    private def decode_known_attribute(type_name : String, blob : Bytes) : String?
      case attribute_base_name(type_name)
      when "SupportedArchitectureAttribute"
        decode_single_u32_attribute(blob).try { |value| "supported_architecture(0x#{value.to_s(16)})" }
      when "ContractVersionAttribute"
        decode_contract_version_attribute(blob)
      when "VersionAttribute"
        decode_single_u32_attribute(blob).try { |value| "version(#{value})" }
      when "ThreadingAttribute"
        decode_single_u32_attribute(blob).try { |value| "threading(#{value})" }
      when "MarshalingBehaviorAttribute"
        decode_single_u16_attribute(blob).try { |value| "marshaling_behavior(#{value})" }
      when "DeprecatedAttribute"
        decode_deprecated_attribute(blob)
      else
        nil
      end
    end

    private def decode_contract_version_attribute(blob : Bytes) : String?
      fixed = fixed_payload_when_no_named_args(blob)
      return nil unless fixed

      # ContractVersionAttribute commonly appears as either:
      # - (UInt32 version)
      # - (String contract, UInt32 version)
      if fixed.size == 4
        value = read_u32_le(fixed, 0)
        return "contract_version(#{value})"
      end

      if contract_name = try_read_leading_ser_string(fixed)
        return nil unless contract_name
        cursor = ser_string_end_offset(fixed)
        return nil unless cursor
        return nil unless cursor + 4 == fixed.size
        version = read_u32_le(fixed, cursor)
        return "contract_version(#{contract_name}, #{version})"
      end

      nil
    end

    private def decode_deprecated_attribute(blob : Bytes) : String?
      fixed = fixed_payload_when_no_named_args(blob)
      return nil unless fixed

      message = try_read_leading_ser_string(fixed)
      return nil unless message
      cursor = ser_string_end_offset(fixed)
      return nil unless cursor
      return nil if cursor + 4 > fixed.size
      dep_kind = read_u32_le(fixed, cursor)
      cursor += 4

      if cursor < fixed.size
        platform = try_read_ser_string_from(fixed, cursor)
        return nil unless platform
        return "deprecated(#{message}, #{dep_kind}, #{platform})"
      end

      "deprecated(#{message}, #{dep_kind})"
    end

    private def decode_single_u16_attribute(blob : Bytes) : UInt16?
      fixed = fixed_payload_when_no_named_args(blob)
      return nil unless fixed
      return nil unless fixed.size == 2
      read_u16_le(fixed, 0)
    end

    private def decode_single_u32_attribute(blob : Bytes) : UInt32?
      fixed = fixed_payload_when_no_named_args(blob)
      return nil unless fixed
      return nil unless fixed.size == 4
      read_u32_le(fixed, 0)
    end

    private def decode_single_string_attribute_blob(blob : Bytes) : String?
      payload_size = blob.size - 2
      return nil if payload_size < 2
      named_count = blob[-2].to_u16 | (blob[-1].to_u16 << 8)
      return nil unless named_count == 0_u16
      fixed_payload = blob[2, blob.size - 4]
      value = read_ser_string_if_exact(fixed_payload)
      return nil unless value
      value
    end

    private def read_ser_string_if_exact(payload : Bytes) : String?
      return nil if payload.empty?
      return nil if payload[0] == 0xFF_u8

      length, cursor = read_compressed_uint(payload, 0)
      return nil if cursor + length.to_i != payload.size
      String.new(payload[cursor, length.to_i])
    rescue ParseError
      nil
    end

    private def try_read_ser_string_from(payload : Bytes, offset : Int32) : String?
      return nil if offset >= payload.size
      return nil if payload[offset] == 0xFF_u8
      length, cursor = read_compressed_uint(payload, offset)
      return nil if cursor + length.to_i > payload.size
      return nil unless cursor + length.to_i == payload.size
      String.new(payload[cursor, length.to_i])
    rescue ParseError
      nil
    end

    private def try_read_leading_ser_string(payload : Bytes) : String?
      return nil if payload.empty?
      return nil if payload[0] == 0xFF_u8
      length, cursor = read_compressed_uint(payload, 0)
      return nil if cursor + length.to_i > payload.size
      String.new(payload[cursor, length.to_i])
    rescue ParseError
      nil
    end

    private def ser_string_end_offset(payload : Bytes) : Int32?
      return nil if payload.empty?
      return nil if payload[0] == 0xFF_u8
      length, cursor = read_compressed_uint(payload, 0)
      end_offset = cursor + length.to_i
      return nil if end_offset > payload.size
      end_offset
    rescue ParseError
      nil
    end

    private def fixed_payload_when_no_named_args(blob : Bytes) : Bytes?
      payload_size = blob.size - 2
      return nil if payload_size < 2
      named_count = blob[-2].to_u16 | (blob[-1].to_u16 << 8)
      return nil unless named_count == 0_u16
      blob[2, blob.size - 4]
    end

    private def attribute_base_name(type_name : String) : String
      type_name.split('.').last? || type_name
    end

    private def read_u16_le(bytes : Bytes, offset : Int32) : UInt16
      bytes[offset].to_u16 | (bytes[offset + 1].to_u16 << 8)
    end

    private def read_u32_le(bytes : Bytes, offset : Int32) : UInt32
      bytes[offset].to_u32 |
        (bytes[offset + 1].to_u32 << 8) |
        (bytes[offset + 2].to_u32 << 16) |
        (bytes[offset + 3].to_u32 << 24)
    end

    private def read_u64_le(bytes : Bytes, offset : Int32) : UInt64
      read_u32_le(bytes, offset).to_u64 | (read_u32_le(bytes, offset + 4).to_u64 << 32)
    end

    private def decode_guid_attribute_blob(blob : Bytes) : String?
      return nil if blob.size < 18
      a = blob[2].to_u32 | (blob[3].to_u32 << 8) | (blob[4].to_u32 << 16) | (blob[5].to_u32 << 24)
      b = blob[6].to_u16 | (blob[7].to_u16 << 8)
      c = blob[8].to_u16 | (blob[9].to_u16 << 8)
      tail = blob[10, 8]
      "#{a.to_s(16).rjust(8, '0')}-#{b.to_s(16).rjust(4, '0')}-#{c.to_s(16).rjust(4, '0')}-#{tail[0].to_s(16).rjust(2, '0')}#{tail[1].to_s(16).rjust(2, '0')}-#{tail[2].to_s(16).rjust(2, '0')}#{tail[3].to_s(16).rjust(2, '0')}#{tail[4].to_s(16).rjust(2, '0')}#{tail[5].to_s(16).rjust(2, '0')}#{tail[6].to_s(16).rjust(2, '0')}#{tail[7].to_s(16).rjust(2, '0')}"
    end

    private def read_compressed_uint(bytes : Bytes, offset : Int32) : {UInt32, Int32}
      if offset >= bytes.size
        raise ParseError.new("Compressed integer is truncated")
      end

      first = bytes[offset]
      if (first & 0x80_u8) == 0_u8
        {first.to_u32, offset + 1}
      elsif (first & 0xC0_u8) == 0x80_u8
        if offset + 1 >= bytes.size
          raise ParseError.new("Compressed integer is truncated")
        end
        value = ((first & 0x3F_u8).to_u32 << 8) | bytes[offset + 1].to_u32
        {value, offset + 2}
      elsif (first & 0xE0_u8) == 0xC0_u8
        if offset + 3 >= bytes.size
          raise ParseError.new("Compressed integer is truncated")
        end
        value = ((first & 0x1F_u8).to_u32 << 24) |
                (bytes[offset + 1].to_u32 << 16) |
                (bytes[offset + 2].to_u32 << 8) |
                bytes[offset + 3].to_u32
        {value, offset + 4}
      else
        raise ParseError.new("Invalid compressed integer encoding")
      end
    end
  end
end
