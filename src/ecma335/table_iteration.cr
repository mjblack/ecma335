module Ecma335
  class TableIteration
    record Result, parsed_row_counts : Hash(String, UInt32), skipped_row_counts : Hash(String, UInt32)

    def initialize(
      @valid_mask : UInt64,
      @row_counts_by_id : Array(UInt32),
      @string_index_size : Int32,
      @guid_index_size : Int32,
      @blob_index_size : Int32,
      @strict_mode : Bool,
    )
    end

    def run(reader : BinaryReader, &block : Int32, Int32, UInt32, Int32, String -> Bool) : Result
      current_offset = reader.offset
      parsed_row_counts = Hash(String, UInt32).new
      skipped_row_counts = Hash(String, UInt32).new

      (Parser::TABLE_MODULE..Parser::TABLE_GENERIC_PARAM_CONSTRAINT).each do |table_id|
        next if (@valid_mask & (1_u64 << table_id)) == 0_u64

        row_count = @row_counts_by_id[table_id]
        table_name = table_name_for(table_id)
        row_size = row_size_for_table(table_id)
        if row_size <= 0
          if @strict_mode && row_count > 0_u32
            raise ParseError.new("Strict mode: unsupported table #{table_name} (#{row_count} rows)")
          end
          skipped_row_counts[table_name] = row_count if row_count > 0_u32
          break
        end

        handled = yield(table_id, current_offset, row_count, row_size, table_name)
        if row_count > 0_u32
          if handled
            parsed_row_counts[table_name] = row_count
          else
            if @strict_mode
              raise ParseError.new("Strict mode: table #{table_name} is not decoded")
            end
            skipped_row_counts[table_name] = row_count
          end
        end

        current_offset += row_count.to_i * row_size
      end

      Result.new(parsed_row_counts, skipped_row_counts)
    end

    private def table_name_for(index : Int32) : String
      Parser::TABLE_NAMES[index]? || "Table#{index}"
    end

    private def row_size_for_table(table_id : Int32) : Int32
      case table_id
      when Parser::TABLE_MODULE
        2 + @string_index_size + @guid_index_size + @guid_index_size + @guid_index_size
      when Parser::TABLE_TYPE_REF
        coded_index_size([Parser::TABLE_MODULE, Parser::TABLE_MODULE_REF, Parser::TABLE_ASSEMBLY_REF, Parser::TABLE_TYPE_REF], 2) + @string_index_size + @string_index_size
      when Parser::TABLE_TYPE_DEF
        4 + @string_index_size + @string_index_size + coded_index_size([Parser::TABLE_TYPE_DEF, Parser::TABLE_TYPE_REF, Parser::TABLE_TYPE_SPEC], 2) + simple_index_size(Parser::TABLE_FIELD) + simple_index_size(Parser::TABLE_METHOD_DEF)
      when Parser::TABLE_FIELD_PTR
        simple_index_size(Parser::TABLE_FIELD)
      when Parser::TABLE_FIELD
        2 + @string_index_size + @blob_index_size
      when Parser::TABLE_METHOD_PTR
        simple_index_size(Parser::TABLE_METHOD_DEF)
      when Parser::TABLE_METHOD_DEF
        4 + 2 + 2 + @string_index_size + @blob_index_size + simple_index_size(Parser::TABLE_PARAM)
      when Parser::TABLE_PARAM_PTR
        simple_index_size(Parser::TABLE_PARAM)
      when Parser::TABLE_PARAM
        2 + 2 + @string_index_size
      when Parser::TABLE_INTERFACE_IMPL
        simple_index_size(Parser::TABLE_TYPE_DEF) + coded_index_size([Parser::TABLE_TYPE_DEF, Parser::TABLE_TYPE_REF, Parser::TABLE_TYPE_SPEC], 2)
      when Parser::TABLE_MEMBER_REF
        coded_index_size([Parser::TABLE_TYPE_DEF, Parser::TABLE_TYPE_REF, Parser::TABLE_MODULE_REF, Parser::TABLE_METHOD_DEF, Parser::TABLE_TYPE_SPEC], 3) + @string_index_size + @blob_index_size
      when Parser::TABLE_CONSTANT
        2 + coded_index_size([Parser::TABLE_FIELD, Parser::TABLE_PARAM, Parser::TABLE_PROPERTY], 2) + @blob_index_size
      when Parser::TABLE_CUSTOM_ATTRIBUTE
        coded_index_size([Parser::TABLE_METHOD_DEF, Parser::TABLE_FIELD, Parser::TABLE_TYPE_REF, Parser::TABLE_TYPE_DEF, Parser::TABLE_PARAM, Parser::TABLE_INTERFACE_IMPL, Parser::TABLE_MEMBER_REF, Parser::TABLE_MODULE, Parser::TABLE_DECL_SECURITY, Parser::TABLE_PROPERTY, Parser::TABLE_EVENT, Parser::TABLE_STAND_ALONE_SIG, Parser::TABLE_MODULE_REF, Parser::TABLE_TYPE_SPEC, Parser::TABLE_ASSEMBLY, Parser::TABLE_ASSEMBLY_REF, Parser::TABLE_FILE, Parser::TABLE_EXPORTED_TYPE, Parser::TABLE_MANIFEST_RESOURCE, Parser::TABLE_GENERIC_PARAM, Parser::TABLE_GENERIC_PARAM_CONSTRAINT, Parser::TABLE_METHOD_SPEC], 5) +
          coded_index_size([Parser::TABLE_METHOD_DEF, Parser::TABLE_MEMBER_REF], 3) +
          @blob_index_size
      when Parser::TABLE_FIELD_MARSHAL
        coded_index_size([Parser::TABLE_FIELD, Parser::TABLE_PARAM], 1) + @blob_index_size
      when Parser::TABLE_DECL_SECURITY
        2 + coded_index_size([Parser::TABLE_TYPE_DEF, Parser::TABLE_METHOD_DEF, Parser::TABLE_ASSEMBLY], 2) + @blob_index_size
      when Parser::TABLE_CLASS_LAYOUT
        2 + 4 + simple_index_size(Parser::TABLE_TYPE_DEF)
      when Parser::TABLE_FIELD_LAYOUT
        4 + simple_index_size(Parser::TABLE_FIELD)
      when Parser::TABLE_STAND_ALONE_SIG
        @blob_index_size
      when Parser::TABLE_EVENT_MAP
        simple_index_size(Parser::TABLE_TYPE_DEF) + simple_index_size(Parser::TABLE_EVENT)
      when Parser::TABLE_EVENT_PTR
        simple_index_size(Parser::TABLE_EVENT)
      when Parser::TABLE_EVENT
        2 + @string_index_size + coded_index_size([Parser::TABLE_TYPE_DEF, Parser::TABLE_TYPE_REF, Parser::TABLE_TYPE_SPEC], 2)
      when Parser::TABLE_PROPERTY_MAP
        simple_index_size(Parser::TABLE_TYPE_DEF) + simple_index_size(Parser::TABLE_PROPERTY)
      when Parser::TABLE_PROPERTY_PTR
        simple_index_size(Parser::TABLE_PROPERTY)
      when Parser::TABLE_PROPERTY
        2 + @string_index_size + @blob_index_size
      when Parser::TABLE_METHOD_SEMANTICS
        2 + simple_index_size(Parser::TABLE_METHOD_DEF) + coded_index_size([Parser::TABLE_EVENT, Parser::TABLE_PROPERTY], 1)
      when Parser::TABLE_METHOD_IMPL
        simple_index_size(Parser::TABLE_TYPE_DEF) + coded_index_size([Parser::TABLE_METHOD_DEF, Parser::TABLE_MEMBER_REF], 1) + coded_index_size([Parser::TABLE_METHOD_DEF, Parser::TABLE_MEMBER_REF], 1)
      when Parser::TABLE_MODULE_REF
        @string_index_size
      when Parser::TABLE_TYPE_SPEC
        @blob_index_size
      when Parser::TABLE_IMPL_MAP
        2 + coded_index_size([Parser::TABLE_FIELD, Parser::TABLE_METHOD_DEF], 1) + @string_index_size + simple_index_size(Parser::TABLE_MODULE_REF)
      when Parser::TABLE_FIELD_RVA
        4 + simple_index_size(Parser::TABLE_FIELD)
      when Parser::TABLE_ENC_LOG
        8
      when Parser::TABLE_ENC_MAP
        4
      when Parser::TABLE_ASSEMBLY
        4 + 2 + 2 + 2 + 2 + 4 + @blob_index_size + @string_index_size + @string_index_size
      when Parser::TABLE_ASSEMBLY_PROCESSOR
        4
      when Parser::TABLE_ASSEMBLY_OS
        12
      when Parser::TABLE_ASSEMBLY_REF
        2 + 2 + 2 + 2 + 4 + @blob_index_size + @string_index_size + @string_index_size + @blob_index_size
      when Parser::TABLE_ASSEMBLY_REF_PROCESSOR
        4 + simple_index_size(Parser::TABLE_ASSEMBLY_REF)
      when Parser::TABLE_ASSEMBLY_REF_OS
        12 + simple_index_size(Parser::TABLE_ASSEMBLY_REF)
      when Parser::TABLE_FILE
        4 + @string_index_size + @blob_index_size
      when Parser::TABLE_EXPORTED_TYPE
        4 + 4 + @string_index_size + @string_index_size + coded_index_size([Parser::TABLE_FILE, Parser::TABLE_ASSEMBLY_REF, Parser::TABLE_EXPORTED_TYPE], 2)
      when Parser::TABLE_MANIFEST_RESOURCE
        4 + 4 + @string_index_size + coded_index_size([Parser::TABLE_FILE, Parser::TABLE_ASSEMBLY_REF, Parser::TABLE_EXPORTED_TYPE], 2)
      when Parser::TABLE_NESTED_CLASS
        simple_index_size(Parser::TABLE_TYPE_DEF) + simple_index_size(Parser::TABLE_TYPE_DEF)
      when Parser::TABLE_GENERIC_PARAM
        2 + 2 + coded_index_size([Parser::TABLE_TYPE_DEF, Parser::TABLE_METHOD_DEF], 1) + @string_index_size
      when Parser::TABLE_METHOD_SPEC
        coded_index_size([Parser::TABLE_METHOD_DEF, Parser::TABLE_MEMBER_REF], 1) + @blob_index_size
      when Parser::TABLE_GENERIC_PARAM_CONSTRAINT
        simple_index_size(Parser::TABLE_GENERIC_PARAM) + coded_index_size([Parser::TABLE_TYPE_DEF, Parser::TABLE_TYPE_REF, Parser::TABLE_TYPE_SPEC], 2)
      else
        0
      end
    end

    private def simple_index_size(target_table : Int32) : Int32
      @row_counts_by_id[target_table] < 0x10000_u32 ? 2 : 4
    end

    private def coded_index_size(target_tables : Array(Int32), tag_bits : Int32) : Int32
      max_rows = target_tables.max_of { |table_id| @row_counts_by_id[table_id]? || 0_u32 }
      limit = 1_u32 << (16 - tag_bits)
      max_rows < limit ? 2 : 4
    end
  end
end
