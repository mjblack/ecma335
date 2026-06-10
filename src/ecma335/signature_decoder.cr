module Ecma335
  class SignatureDecoder
    IMAGE_CEE_CS_CALLCONV_DEFAULT      = 0x0_u8
    IMAGE_CEE_CS_CALLCONV_C            = 0x1_u8
    IMAGE_CEE_CS_CALLCONV_STDCALL      = 0x2_u8
    IMAGE_CEE_CS_CALLCONV_THISCALL     = 0x3_u8
    IMAGE_CEE_CS_CALLCONV_FASTCALL     = 0x4_u8
    IMAGE_CEE_CS_CALLCONV_VARARG       = 0x5_u8
    IMAGE_CEE_CS_CALLCONV_FIELD        = 0x6_u8
    IMAGE_CEE_CS_CALLCONV_HASTHIS      = 0x20_u8
    IMAGE_CEE_CS_CALLCONV_EXPLICITTHIS = 0x40_u8
    IMAGE_CEE_CS_CALLCONV_GENERIC      = 0x10_u8
    IMAGE_CEE_CS_CALLCONV_MASK         = 0x0F_u8

    def initialize(@type_refs : Array(TypeRefRow), @type_defs : Array(TypeDefRow))
    end

    def decode_method(blob : Bytes) : MethodSignature?
      signature, _next_cursor = read_method_signature_from_blob(blob, 0)
      signature
    rescue ParseError
      nil
    end

    def decode_field(blob : Bytes) : String?
      return nil if blob.empty?
      cursor = 0
      first = blob[cursor]
      cursor += 1
      return nil unless (first & IMAGE_CEE_CS_CALLCONV_MASK) == IMAGE_CEE_CS_CALLCONV_FIELD
      field_type, _next_cursor = read_type_signature(blob, cursor)
      field_type
    rescue ParseError
      nil
    end

    def decode_member_ref(blob : Bytes) : String?
      return nil if blob.empty?
      first = blob[0]
      kind = first & IMAGE_CEE_CS_CALLCONV_MASK
      case kind
      when IMAGE_CEE_CS_CALLCONV_FIELD
        decode_field(blob).try { |sig| "field #{sig}" }
      when IMAGE_CEE_CS_CALLCONV_DEFAULT, IMAGE_CEE_CS_CALLCONV_VARARG
        decode_method(blob).try do |sig|
          "(#{sig.parameter_types.join(", ")}) -> #{sig.return_type}"
        end
      else
        nil
      end
    end

    def decode_property(blob : Bytes) : String?
      return nil if blob.empty?
      cursor = 0
      first = blob[cursor]
      cursor += 1
      return nil if (first & IMAGE_CEE_CS_CALLCONV_MASK) != 0x08_u8

      has_this = (first & IMAGE_CEE_CS_CALLCONV_HASTHIS) != 0
      parameter_count, cursor = read_compressed_uint(blob, cursor)
      property_type, cursor = read_type_signature(blob, cursor)

      parameter_types = [] of String
      parameter_count.times do
        type_name, next_cursor = read_type_signature(blob, cursor)
        parameter_types << type_name
        cursor = next_cursor
      end

      prefix = has_this ? "instance " : ""
      "#{prefix}property(#{parameter_types.join(", ")}) -> #{property_type}"
    rescue ParseError
      nil
    end

    def decode_method_spec_instantiation(blob : Bytes) : String?
      return nil if blob.empty?
      cursor = 0
      first = blob[cursor]
      cursor += 1
      return nil unless first == 0x0A_u8

      arg_count, cursor = read_compressed_uint(blob, cursor)
      args = [] of String
      arg_count.times do
        arg, next_cursor = read_type_signature(blob, cursor)
        args << arg
        cursor = next_cursor
      end
      "<#{args.join(", ")}>"
    rescue ParseError
      nil
    end

    def decode_type_spec(blob : Bytes) : String?
      return nil if blob.empty?
      type_name, _next_offset = read_type_signature(blob, 0)
      type_name
    rescue ParseError
      nil
    end

    private def read_method_signature_from_blob(blob : Bytes, start_offset : Int32) : {MethodSignature?, Int32}
      cursor = start_offset
      if cursor >= blob.size
        raise ParseError.new("Method signature is truncated")
      end

      first = blob[cursor]
      cursor += 1

      has_this = (first & IMAGE_CEE_CS_CALLCONV_HASTHIS) != 0
      explicit_this = (first & IMAGE_CEE_CS_CALLCONV_EXPLICITTHIS) != 0
      generic = (first & IMAGE_CEE_CS_CALLCONV_GENERIC) != 0
      kind = first & IMAGE_CEE_CS_CALLCONV_MASK
      return {nil, cursor} unless method_callconv_supported?(kind)

      generic_parameter_count = nil
      if generic
        generic_parameter_count, cursor = read_compressed_uint(blob, cursor)
      end
      parameter_count, cursor = read_compressed_uint(blob, cursor)
      return_type, cursor = read_type_signature(blob, cursor)

      parameter_types = Array(String).new(parameter_count.to_i)
      saw_sentinel = false
      while parameter_types.size < parameter_count
        if kind == IMAGE_CEE_CS_CALLCONV_VARARG && cursor < blob.size && blob[cursor] == 0x41_u8
          saw_sentinel = true
          cursor += 1
          next
        end

        type_name, next_cursor = read_type_signature(blob, cursor)
        cursor = next_cursor
        if saw_sentinel
          parameter_types << "sentinel #{type_name}"
          saw_sentinel = false
        else
          parameter_types << type_name
        end
      end

      {MethodSignature.new(has_this, explicit_this, generic_parameter_count, parameter_count, return_type, parameter_types), cursor}
    end

    private def method_callconv_supported?(kind : UInt8) : Bool
      case kind
      when IMAGE_CEE_CS_CALLCONV_DEFAULT,
           IMAGE_CEE_CS_CALLCONV_C,
           IMAGE_CEE_CS_CALLCONV_STDCALL,
           IMAGE_CEE_CS_CALLCONV_THISCALL,
           IMAGE_CEE_CS_CALLCONV_FASTCALL,
           IMAGE_CEE_CS_CALLCONV_VARARG
        true
      else
        false
      end
    end

    private def read_type_signature(blob : Bytes, offset : Int32) : {String, Int32}
      raise ParseError.new("Type signature is truncated") if offset >= blob.size

      etype = blob[offset]
      offset += 1
      case etype
      when 0x01_u8 then {"void", offset}
      when 0x02_u8 then {"bool", offset}
      when 0x03_u8 then {"char", offset}
      when 0x04_u8 then {"int8", offset}
      when 0x05_u8 then {"uint8", offset}
      when 0x06_u8 then {"int16", offset}
      when 0x07_u8 then {"uint16", offset}
      when 0x08_u8 then {"int32", offset}
      when 0x09_u8 then {"uint32", offset}
      when 0x0A_u8 then {"int64", offset}
      when 0x0B_u8 then {"uint64", offset}
      when 0x0C_u8 then {"float32", offset}
      when 0x0D_u8 then {"float64", offset}
      when 0x0E_u8 then {"string", offset}
      when 0x0F_u8
        inner_type, next_offset = read_type_signature(blob, offset)
        {"ptr(#{inner_type})", next_offset}
      when 0x10_u8
        inner_type, next_offset = read_type_signature(blob, offset)
        {"byref(#{inner_type})", next_offset}
      when 0x11_u8
        coded, next_offset = read_compressed_uint(blob, offset)
        {"valuetype(#{resolve_type_def_or_ref(coded)})", next_offset}
      when 0x12_u8
        coded, next_offset = read_compressed_uint(blob, offset)
        {"class(#{resolve_type_def_or_ref(coded)})", next_offset}
      when 0x14_u8
        element_type, cursor = read_type_signature(blob, offset)
        rank, cursor = read_compressed_uint(blob, cursor)
        num_sizes, cursor = read_compressed_uint(blob, cursor)
        sizes = [] of UInt32
        num_sizes.times do
          size, next_cursor = read_compressed_uint(blob, cursor)
          sizes << size
          cursor = next_cursor
        end
        num_lobounds, cursor = read_compressed_uint(blob, cursor)
        num_lobounds.times do
          _lobound, next_cursor = read_compressed_uint(blob, cursor)
          cursor = next_cursor
        end
        shape = if sizes.empty?
                  rank == 1_u32 ? "[]" : "[rank=#{rank}]"
                else
                  "[#{sizes.join(",")}]"
                end
        {"array(#{element_type})#{shape}", cursor}
      when 0x15_u8
        kind = blob[offset]
        offset += 1
        type_token, offset = read_compressed_uint(blob, offset)
        arg_count, offset = read_compressed_uint(blob, offset)
        args = [] of String
        arg_count.times do
          arg, next_offset = read_type_signature(blob, offset)
          args << arg
          offset = next_offset
        end
        type_name = if kind == 0x11_u8 || kind == 0x12_u8
                      resolve_type_def_or_ref(type_token)
                    else
                      "token(#{type_token})"
                    end
        {"genericinst(#{type_name}<#{args.join(", ")}>)", offset}
      when 0x16_u8 then {"typedbyref", offset}
      when 0x18_u8 then {"nativeint", offset}
      when 0x19_u8 then {"nativeuint", offset}
      when 0x1C_u8 then {"object", offset}
      when 0x1D_u8
        element_type, next_offset = read_type_signature(blob, offset)
        {"szarray(#{element_type})", next_offset}
      when 0x1B_u8
        signature, next_offset = read_method_signature_from_blob(blob, offset)
        raise ParseError.new("Function pointer signature is invalid") unless signature
        {"fnptr((#{signature.parameter_types.join(", ")}) -> #{signature.return_type})", next_offset}
      when 0x1F_u8
        modifier_type, cursor = read_compressed_uint(blob, offset)
        inner_type, next_offset = read_type_signature(blob, cursor)
        {"cmod_reqd(#{modifier_type}, #{inner_type})", next_offset}
      when 0x20_u8
        modifier_type, cursor = read_compressed_uint(blob, offset)
        inner_type, next_offset = read_type_signature(blob, cursor)
        {"cmod_opt(#{modifier_type}, #{inner_type})", next_offset}
      when 0x1E_u8
        idx, next_offset = read_compressed_uint(blob, offset)
        {"mvar(#{idx})", next_offset}
      when 0x13_u8
        idx, next_offset = read_compressed_uint(blob, offset)
        {"var(#{idx})", next_offset}
      else
        {"unknown(0x#{etype.to_s(16)})", offset}
      end
    end

    private def resolve_type_def_or_ref(coded_index : UInt32) : String
      tag = coded_index & 0x3_u32
      row_index = (coded_index >> 2).to_i
      return "<null>" if row_index <= 0

      case tag
      when 0_u32
        type = @type_defs[row_index - 1]?
        return "<typedef:#{row_index}>" unless type
        qualify_type_name(type.type_namespace, type.type_name)
      when 1_u32
        type = @type_refs[row_index - 1]?
        return "<typeref:#{row_index}>" unless type
        qualify_type_name(type.type_namespace, type.type_name)
      when 2_u32
        "<typespec:#{row_index}>"
      else
        "<invalid-typedeforref:#{coded_index}>"
      end
    end

    private def qualify_type_name(namespace_name : String, type_name : String) : String
      return type_name if namespace_name.empty?
      "#{namespace_name}.#{type_name}"
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
