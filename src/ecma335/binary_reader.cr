module Ecma335
  class BinaryReader
    getter bytes : Bytes
    property offset : Int32

    def initialize(@bytes : Bytes)
      @offset = 0
    end

    def seek(offset : Int32) : Nil
      ensure_available(offset, 0, :seek)
      @offset = offset
    end

    def skip(count : Int32) : Nil
      ensure_available(@offset, count, :skip)
      @offset += count
    end

    def read_u8 : UInt8
      value = read_at_u8(@offset)
      @offset += 1
      value
    end

    def read_u16 : UInt16
      value = read_at_u16(@offset)
      @offset += 2
      value
    end

    def read_u32 : UInt32
      value = read_at_u32(@offset)
      @offset += 4
      value
    end

    def read_u64 : UInt64
      value = read_at_u64(@offset)
      @offset += 8
      value
    end

    def read_bytes(count : Int32) : Bytes
      ensure_available(@offset, count, :read_bytes)
      value = @bytes[@offset, count]
      @offset += count
      value
    end

    def read_bytes_at(offset : Int32, count : Int32) : Bytes
      ensure_available(offset, count, :read_bytes)
      @bytes[offset, count]
    end

    def read_cstring(max_bytes : Int32) : String
      ensure_available(@offset, max_bytes, :read_cstring)
      start = @offset
      max_bytes.times do |idx|
        if @bytes[@offset + idx] == 0_u8
          @offset += idx + 1
          return String.new(@bytes[start, idx])
        end
      end
      raise ParseError.new("Unterminated string in metadata stream header")
    end

    def read_at_u8(offset : Int32) : UInt8
      ensure_available(offset, 1, :read_u8)
      @bytes[offset]
    end

    def read_at_u16(offset : Int32) : UInt16
      ensure_available(offset, 2, :read_u16)
      b0 = @bytes[offset].to_u16
      b1 = @bytes[offset + 1].to_u16
      b0 | (b1 << 8)
    end

    def read_at_u32(offset : Int32) : UInt32
      ensure_available(offset, 4, :read_u32)
      b0 = @bytes[offset].to_u32
      b1 = @bytes[offset + 1].to_u32
      b2 = @bytes[offset + 2].to_u32
      b3 = @bytes[offset + 3].to_u32
      b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    end

    def read_at_u64(offset : Int32) : UInt64
      ensure_available(offset, 8, :read_u64)
      b0 = @bytes[offset].to_u64
      b1 = @bytes[offset + 1].to_u64
      b2 = @bytes[offset + 2].to_u64
      b3 = @bytes[offset + 3].to_u64
      b4 = @bytes[offset + 4].to_u64
      b5 = @bytes[offset + 5].to_u64
      b6 = @bytes[offset + 6].to_u64
      b7 = @bytes[offset + 7].to_u64
      b0 | (b1 << 8) | (b2 << 16) | (b3 << 24) | (b4 << 32) | (b5 << 40) | (b6 << 48) | (b7 << 56)
    end

    def align4 : Nil
      remainder = @offset % 4
      return if remainder == 0
      skip(4 - remainder)
    end

    private def ensure_available(offset : Int32, count : Int32, action : Symbol) : Nil
      if offset < 0 || count < 0 || offset + count > @bytes.size
        raise ParseError.new("Truncated file while trying to #{action} at offset #{offset}")
      end
    end
  end
end
