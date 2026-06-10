module Ecma335
  class CustomAttributeDecoder
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
