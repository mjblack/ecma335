module Ecma335
  class Parser
    PE_SIGNATURE                       = 0x00004550_u32
    DOS_SIGNATURE                      =     0x5A4D_u16
    OPTIONAL_PE32                      =      0x10B_u16
    OPTIONAL_PE32P                     =      0x20B_u16
    CLI_DATA_DIR_IDX                   =             14
    METADATA_SIG                       = 0x424A5342_u32
    STRING_HEAP_WIDE                   =        0x01_u8
    GUID_HEAP_WIDE                     =        0x02_u8
    BLOB_HEAP_WIDE                     =        0x04_u8

    TABLE_MODULE                   =  0
    TABLE_TYPE_REF                 =  1
    TABLE_TYPE_DEF                 =  2
    TABLE_FIELD_PTR                =  3
    TABLE_FIELD                    =  4
    TABLE_METHOD_PTR               =  5
    TABLE_METHOD_DEF               =  6
    TABLE_PARAM_PTR                =  7
    TABLE_PARAM                    =  8
    TABLE_INTERFACE_IMPL           =  9
    TABLE_MEMBER_REF               = 10
    TABLE_CONSTANT                 = 11
    TABLE_CUSTOM_ATTRIBUTE         = 12
    TABLE_FIELD_MARSHAL            = 13
    TABLE_DECL_SECURITY            = 14
    TABLE_CLASS_LAYOUT             = 15
    TABLE_FIELD_LAYOUT             = 16
    TABLE_STAND_ALONE_SIG          = 17
    TABLE_EVENT_MAP                = 18
    TABLE_EVENT_PTR                = 19
    TABLE_EVENT                    = 20
    TABLE_PROPERTY_MAP             = 21
    TABLE_PROPERTY_PTR             = 22
    TABLE_PROPERTY                 = 23
    TABLE_METHOD_SEMANTICS         = 24
    TABLE_METHOD_IMPL              = 25
    TABLE_MODULE_REF               = 26
    TABLE_TYPE_SPEC                = 27
    TABLE_IMPL_MAP                 = 28
    TABLE_FIELD_RVA                = 29
    TABLE_ENC_LOG                  = 30
    TABLE_ENC_MAP                  = 31
    TABLE_ASSEMBLY                 = 32
    TABLE_ASSEMBLY_PROCESSOR       = 33
    TABLE_ASSEMBLY_OS              = 34
    TABLE_ASSEMBLY_REF             = 35
    TABLE_ASSEMBLY_REF_PROCESSOR   = 36
    TABLE_ASSEMBLY_REF_OS          = 37
    TABLE_FILE                     = 38
    TABLE_EXPORTED_TYPE            = 39
    TABLE_MANIFEST_RESOURCE        = 40
    TABLE_NESTED_CLASS             = 41
    TABLE_GENERIC_PARAM            = 42
    TABLE_METHOD_SPEC              = 43
    TABLE_GENERIC_PARAM_CONSTRAINT = 44

    TABLE_NAMES = [
      "Module", "TypeRef", "TypeDef", "FieldPtr", "Field", "MethodPtr", "MethodDef", "ParamPtr", "Param",
      "InterfaceImpl", "MemberRef", "Constant", "CustomAttribute", "FieldMarshal", "DeclSecurity", "ClassLayout",
      "FieldLayout", "StandAloneSig", "EventMap", "EventPtr", "Event", "PropertyMap", "PropertyPtr", "Property",
      "MethodSemantics", "MethodImpl", "ModuleRef", "TypeSpec", "ImplMap", "FieldRVA", "ENCLog", "ENCMap",
      "Assembly", "AssemblyProcessor", "AssemblyOS", "AssemblyRef", "AssemblyRefProcessor", "AssemblyRefOS", "File",
      "ExportedType", "ManifestResource", "NestedClass", "GenericParam", "MethodSpec", "GenericParamConstraint",
    ]

    def initialize(@bytes : Bytes, @strict_mode : Bool = false)
    end

    def parse : ParsedAssembly
      reader = BinaryReader.new(@bytes)
      pe_header_offset = read_pe_header_offset(reader)
      sections, cli_header_rva = parse_pe_and_cli(reader, pe_header_offset)
      cli_header_offset = rva_to_file_offset(sections, cli_header_rva)
      metadata_rva = read_metadata_rva(reader, cli_header_offset)
      metadata_offset = rva_to_file_offset(sections, metadata_rva)
      metadata_root = parse_metadata_root(reader, metadata_offset, metadata_rva, sections)
      api_model = ApiModelBuilder.new.build(metadata_root.tables_stream)
      ParsedAssembly.new(cli_header_rva, metadata_rva, metadata_root, api_model)
    end

    private def read_pe_header_offset(reader : BinaryReader) : Int32
      reader.seek(0)
      dos_signature = reader.read_u16
      if dos_signature != DOS_SIGNATURE
        raise ParseError.new("Invalid DOS signature: expected MZ header")
      end

      pe_header_offset = reader.read_at_u32(0x3C).to_i
      if pe_header_offset <= 0 || pe_header_offset + 4 > @bytes.size
        raise ParseError.new("Invalid PE header offset")
      end
      pe_header_offset
    end

    private def parse_pe_and_cli(reader : BinaryReader, pe_header_offset : Int32) : {Array(SectionHeader), UInt32}
      reader.seek(pe_header_offset)
      pe_signature = reader.read_u32
      if pe_signature != PE_SIGNATURE
        raise ParseError.new("Invalid PE signature")
      end

      reader.skip(2) # machine
      section_count = reader.read_u16.to_i
      reader.skip(12) # timestamp, symbol pointers/count
      optional_header_size = reader.read_u16.to_i
      reader.skip(2) # characteristics

      optional_header_offset = reader.offset
      optional_magic = reader.read_u16

      data_directory_offset = case optional_magic
                              when OPTIONAL_PE32
                                optional_header_offset + 96
                              when OPTIONAL_PE32P
                                optional_header_offset + 112
                              else
                                raise ParseError.new("Unsupported PE optional header magic: 0x#{optional_magic.to_s(16)}")
                              end

      cli_data_directory_offset = data_directory_offset + (CLI_DATA_DIR_IDX * 8)
      cli_header_rva = reader.read_at_u32(cli_data_directory_offset)
      if cli_header_rva == 0_u32
        raise ParseError.new("CLI header data directory is missing")
      end

      section_table_offset = optional_header_offset + optional_header_size
      sections = parse_sections(reader, section_table_offset, section_count)
      {sections, cli_header_rva}
    end

    private def parse_sections(reader : BinaryReader, section_table_offset : Int32, section_count : Int32) : Array(SectionHeader)
      sections = Array(SectionHeader).new(section_count)
      entry_offset = section_table_offset
      section_count.times do
        name = read_section_name(reader, entry_offset)
        virtual_size = reader.read_at_u32(entry_offset + 8)
        virtual_address = reader.read_at_u32(entry_offset + 12)
        size_of_raw_data = reader.read_at_u32(entry_offset + 16)
        pointer_to_raw_data = reader.read_at_u32(entry_offset + 20)
        sections << SectionHeader.new(name, virtual_size, virtual_address, size_of_raw_data, pointer_to_raw_data)
        entry_offset += 40
      end
      sections
    end

    private def read_section_name(reader : BinaryReader, offset : Int32) : String
      bytes = reader.read_bytes_at(offset, 8)
      stop = bytes.index(0_u8) || bytes.size
      String.new(bytes[0, stop])
    end

    private def read_metadata_rva(reader : BinaryReader, cli_header_offset : Int32) : UInt32
      metadata_rva = reader.read_at_u32(cli_header_offset + 8)
      if metadata_rva == 0_u32
        raise ParseError.new("CLI metadata directory RVA is missing")
      end
      metadata_rva
    end

    private def parse_metadata_root(reader : BinaryReader, metadata_offset : Int32, metadata_rva : UInt32, sections : Array(SectionHeader)) : MetadataRoot
      reader.seek(metadata_offset)
      signature = reader.read_u32
      if signature != METADATA_SIG
        raise ParseError.new("Invalid metadata signature at CLI metadata root")
      end

      major_version = reader.read_u16
      minor_version = reader.read_u16
      reader.skip(4) # reserved
      version_length = reader.read_u32.to_i
      version_string = String.new(reader.read_bytes(version_length)).delete('\u0000')
      reader.align4
      reader.skip(2) # flags
      stream_count = reader.read_u16.to_i

      streams = Array(StreamHeader).new(stream_count)
      stream_count.times do
        stream_offset = reader.read_u32
        stream_size = reader.read_u32
        stream_name = reader.read_cstring(32)
        reader.align4
        streams << StreamHeader.new(stream_name, stream_offset, stream_size)
      end

      tables_stream = parse_tables_stream(reader, metadata_rva, streams, sections)
      MetadataRoot.new(signature, major_version, minor_version, version_string, streams, tables_stream)
    end

    private def parse_tables_stream(reader : BinaryReader, metadata_rva : UInt32, streams : Array(StreamHeader), sections : Array(SectionHeader)) : TablesStream?
      stream = streams.find { |item| item.name == "#~" }
      return nil unless stream

      stream_rva = metadata_rva + stream.offset
      stream_offset = rva_to_file_offset(sections, stream_rva)
      reader.seek(stream_offset)

      reader.skip(4) # reserved
      major_version = reader.read_u8
      minor_version = reader.read_u8
      heap_sizes = reader.read_u8
      reader.skip(1) # reserved
      valid_mask = reader.read_u64
      sorted_mask = reader.read_u64

      row_counts = Hash(String, UInt32).new
      row_counts_by_id = Array(UInt32).new(64, 0_u32)
      64.times do |table_index|
        bit = 1_u64 << table_index
        next if (valid_mask & bit) == 0_u64
        count = reader.read_u32
        row_counts_by_id[table_index] = count
        table_name = table_name_for(table_index)
        row_counts[table_name] = count
      end

      modules = [] of ModuleRow
      type_refs = [] of TypeRefRow
      type_defs = [] of TypeDefRow
      fields = [] of FieldRow
      method_defs = [] of MethodDefRow
      params = [] of ParamRow
      constants = [] of ConstantRow
      interface_impls = [] of InterfaceImplRow
      member_refs = [] of MemberRefRow
      event_maps = [] of EventMapRow
      events = [] of EventRow
      property_maps = [] of PropertyMapRow
      properties = [] of PropertyRow
      method_semantics = [] of MethodSemanticsRow
      method_impls = [] of MethodImplRow
      assemblies = [] of AssemblyRow
      assembly_refs = [] of AssemblyRefRow
      class_layouts = [] of ClassLayoutRow
      field_layouts = [] of FieldLayoutRow
      files = [] of FileRow
      exported_types = [] of ExportedTypeRow
      manifest_resources = [] of ManifestResourceRow
      generic_params = [] of GenericParamRow
      method_specs = [] of MethodSpecRow
      generic_param_constraints = [] of GenericParamConstraintRow
      type_specs = [] of TypeSpecRow
      module_refs = [] of ModuleRefRow
      impl_maps = [] of ImplMapRow
      custom_attributes = [] of CustomAttributeRow
      nested_classes = [] of NestedClassRow

      strings_heap = read_stream_bytes(reader, streams, metadata_rva, sections, "#Strings")
      blob_heap = read_stream_bytes(reader, streams, metadata_rva, sections, "#Blob")
      string_index_size = heap_index_size(heap_sizes, STRING_HEAP_WIDE)
      guid_index_size = heap_index_size(heap_sizes, GUID_HEAP_WIDE)
      blob_index_size = heap_index_size(heap_sizes, BLOB_HEAP_WIDE)

      iteration = TableIteration.new(valid_mask, row_counts_by_id, string_index_size, guid_index_size, blob_index_size, @strict_mode)
      diagnostics = iteration.run(reader) do |table_id, current_offset, row_count, _row_size, _table_name|
        handled = true
        case table_id
        when TABLE_MODULE
          modules = parse_module_rows(reader, current_offset, row_count, string_index_size, guid_index_size, strings_heap)
        when TABLE_TYPE_REF
          type_refs = parse_type_ref_rows(reader, current_offset, row_count, row_counts_by_id, string_index_size, strings_heap)
        when TABLE_TYPE_DEF
          type_defs = parse_type_def_rows(reader, current_offset, row_count, row_counts_by_id, string_index_size, strings_heap)
        when TABLE_FIELD
          fields = parse_field_rows(reader, current_offset, row_count, string_index_size, blob_index_size, strings_heap, blob_heap, type_refs, type_defs)
        when TABLE_METHOD_DEF
          method_defs = parse_method_def_rows(reader, current_offset, row_count, row_counts_by_id, string_index_size, blob_index_size, strings_heap, blob_heap, type_refs, type_defs)
        when TABLE_PARAM
          params = parse_param_rows(reader, current_offset, row_count, string_index_size, strings_heap)
        when TABLE_CONSTANT
          constants = parse_constant_rows(reader, current_offset, row_count, row_counts_by_id, blob_index_size, blob_heap, fields, params)
        when TABLE_INTERFACE_IMPL
          interface_impls = parse_interface_impl_rows(reader, current_offset, row_count, row_counts_by_id, type_defs, type_refs)
        when TABLE_MEMBER_REF
          member_refs = parse_member_ref_rows(reader, current_offset, row_count, row_counts_by_id, string_index_size, blob_index_size, strings_heap, blob_heap, type_defs, type_refs, method_defs, type_specs, module_refs)
        when TABLE_EVENT_MAP
          event_maps = parse_event_map_rows(reader, current_offset, row_count, row_counts_by_id, type_defs)
        when TABLE_EVENT
          events = parse_event_rows(reader, current_offset, row_count, row_counts_by_id, string_index_size, strings_heap, type_refs, type_defs)
        when TABLE_PROPERTY_MAP
          property_maps = parse_property_map_rows(reader, current_offset, row_count, row_counts_by_id, type_defs)
        when TABLE_PROPERTY
          properties = parse_property_rows(reader, current_offset, row_count, string_index_size, blob_index_size, strings_heap, blob_heap, type_refs, type_defs)
        when TABLE_METHOD_SEMANTICS
          method_semantics = parse_method_semantics_rows(reader, current_offset, row_count, row_counts_by_id, method_defs, events, properties)
        when TABLE_METHOD_IMPL
          method_impls = parse_method_impl_rows(reader, current_offset, row_count, row_counts_by_id, type_defs, method_defs, member_refs)
        when TABLE_ASSEMBLY
          assemblies = parse_assembly_rows(reader, current_offset, row_count, string_index_size, blob_index_size, strings_heap)
        when TABLE_ASSEMBLY_REF
          assembly_refs = parse_assembly_ref_rows(reader, current_offset, row_count, string_index_size, blob_index_size, strings_heap)
        when TABLE_CLASS_LAYOUT
          class_layouts = parse_class_layout_rows(reader, current_offset, row_count, row_counts_by_id, type_defs)
        when TABLE_FIELD_LAYOUT
          field_layouts = parse_field_layout_rows(reader, current_offset, row_count, row_counts_by_id, fields)
        when TABLE_FILE
          files = parse_file_rows(reader, current_offset, row_count, string_index_size, blob_index_size, strings_heap)
        when TABLE_EXPORTED_TYPE
          exported_types = parse_exported_type_rows(reader, current_offset, row_count, row_counts_by_id, string_index_size, strings_heap, files, assembly_refs, exported_types)
        when TABLE_MANIFEST_RESOURCE
          manifest_resources = parse_manifest_resource_rows(reader, current_offset, row_count, row_counts_by_id, string_index_size, strings_heap, files, assembly_refs, exported_types)
        when TABLE_NESTED_CLASS
          nested_classes = parse_nested_class_rows(reader, current_offset, row_count, row_counts_by_id, type_defs)
        when TABLE_GENERIC_PARAM
          generic_params = parse_generic_param_rows(reader, current_offset, row_count, row_counts_by_id, string_index_size, strings_heap, type_defs, method_defs)
        when TABLE_METHOD_SPEC
          method_specs = parse_method_spec_rows(reader, current_offset, row_count, row_counts_by_id, blob_index_size, blob_heap, type_refs, type_defs, method_defs, member_refs)
        when TABLE_GENERIC_PARAM_CONSTRAINT
          generic_param_constraints = parse_generic_param_constraint_rows(reader, current_offset, row_count, row_counts_by_id, generic_params, type_refs, type_defs)
        when TABLE_TYPE_SPEC
          type_specs = parse_type_spec_rows(reader, current_offset, row_count, blob_index_size, blob_heap, type_defs, type_refs)
        when TABLE_MODULE_REF
          module_refs = parse_module_ref_rows(reader, current_offset, row_count, string_index_size, strings_heap)
        when TABLE_IMPL_MAP
          impl_maps = parse_impl_map_rows(reader, current_offset, row_count, row_counts_by_id, string_index_size, strings_heap, module_refs, fields, method_defs)
        when TABLE_CUSTOM_ATTRIBUTE
          custom_attributes = parse_custom_attribute_rows(reader, current_offset, row_count, row_counts_by_id, blob_index_size, blob_heap, type_defs, type_refs, fields, method_defs, params, interface_impls, member_refs, module_refs)
        else
          handled = false
        end
        handled
      end
      parsed_row_counts = diagnostics.parsed_row_counts
      skipped_row_counts = diagnostics.skipped_row_counts

      params = attach_param_signature_types(params, method_defs)
      member_refs = resolve_member_ref_parents(member_refs, type_defs, type_refs, method_defs, type_specs, module_refs)
      constants = resolve_constant_owners(constants, fields, params)
      custom_attributes = resolve_custom_attribute_parents(custom_attributes, type_defs, type_refs, fields, method_defs, params, interface_impls, member_refs, module_refs)

      TablesStream.new(
        major_version,
        minor_version,
        heap_sizes,
        valid_mask,
        sorted_mask,
        row_counts,
        modules,
        type_refs,
        type_defs,
        fields,
        method_defs,
        params,
        constants,
        interface_impls,
        member_refs,
        event_maps,
        events,
        property_maps,
        properties,
        method_semantics,
        method_impls,
        assemblies,
        assembly_refs,
        class_layouts,
        field_layouts,
        files,
        exported_types,
        manifest_resources,
        generic_params,
        method_specs,
        generic_param_constraints,
        type_specs,
        module_refs,
        impl_maps,
        custom_attributes,
        nested_classes,
        parsed_row_counts,
        skipped_row_counts
      )
    end

    private def rva_to_file_offset(sections : Array(SectionHeader), rva : UInt32) : Int32
      section = sections.find { |entry| entry.contains_rva?(rva) }
      unless section
        raise ParseError.new("RVA 0x#{rva.to_s(16)} is not covered by any section")
      end

      delta = (rva - section.virtual_address).to_i
      (section.pointer_to_raw_data + delta).to_i
    end

    private def table_name_for(index : Int32) : String
      TABLE_NAMES[index]? || "Table#{index}"
    end

    private def row_size_for_table(table_id : Int32, row_counts_by_id : Array(UInt32), string_index_size : Int32, guid_index_size : Int32, blob_index_size : Int32) : Int32
      case table_id
      when TABLE_MODULE
        2 + string_index_size + guid_index_size + guid_index_size + guid_index_size
      when TABLE_TYPE_REF
        coded_index_size(row_counts_by_id, [TABLE_MODULE, TABLE_MODULE_REF, TABLE_ASSEMBLY_REF, TABLE_TYPE_REF], 2) + string_index_size + string_index_size
      when TABLE_TYPE_DEF
        4 + string_index_size + string_index_size + coded_index_size(row_counts_by_id, [TABLE_TYPE_DEF, TABLE_TYPE_REF, TABLE_TYPE_SPEC], 2) + simple_index_size(row_counts_by_id, TABLE_FIELD) + simple_index_size(row_counts_by_id, TABLE_METHOD_DEF)
      when TABLE_FIELD_PTR
        simple_index_size(row_counts_by_id, TABLE_FIELD)
      when TABLE_FIELD
        2 + string_index_size + blob_index_size
      when TABLE_METHOD_PTR
        simple_index_size(row_counts_by_id, TABLE_METHOD_DEF)
      when TABLE_METHOD_DEF
        4 + 2 + 2 + string_index_size + blob_index_size + simple_index_size(row_counts_by_id, TABLE_PARAM)
      when TABLE_PARAM_PTR
        simple_index_size(row_counts_by_id, TABLE_PARAM)
      when TABLE_PARAM
        2 + 2 + string_index_size
      when TABLE_INTERFACE_IMPL
        simple_index_size(row_counts_by_id, TABLE_TYPE_DEF) + coded_index_size(row_counts_by_id, [TABLE_TYPE_DEF, TABLE_TYPE_REF, TABLE_TYPE_SPEC], 2)
      when TABLE_MEMBER_REF
        coded_index_size(row_counts_by_id, [TABLE_TYPE_DEF, TABLE_TYPE_REF, TABLE_MODULE_REF, TABLE_METHOD_DEF, TABLE_TYPE_SPEC], 3) + string_index_size + blob_index_size
      when TABLE_CONSTANT
        2 + coded_index_size(row_counts_by_id, [TABLE_FIELD, TABLE_PARAM, TABLE_PROPERTY], 2) + blob_index_size
      when TABLE_CUSTOM_ATTRIBUTE
        coded_index_size(row_counts_by_id, [TABLE_METHOD_DEF, TABLE_FIELD, TABLE_TYPE_REF, TABLE_TYPE_DEF, TABLE_PARAM, TABLE_INTERFACE_IMPL, TABLE_MEMBER_REF, TABLE_MODULE, TABLE_DECL_SECURITY, TABLE_PROPERTY, TABLE_EVENT, TABLE_STAND_ALONE_SIG, TABLE_MODULE_REF, TABLE_TYPE_SPEC, TABLE_ASSEMBLY, TABLE_ASSEMBLY_REF, TABLE_FILE, TABLE_EXPORTED_TYPE, TABLE_MANIFEST_RESOURCE, TABLE_GENERIC_PARAM, TABLE_GENERIC_PARAM_CONSTRAINT, TABLE_METHOD_SPEC], 5) +
          coded_index_size(row_counts_by_id, [TABLE_METHOD_DEF, TABLE_MEMBER_REF], 3) +
          blob_index_size
      when TABLE_FIELD_MARSHAL
        coded_index_size(row_counts_by_id, [TABLE_FIELD, TABLE_PARAM], 1) + blob_index_size
      when TABLE_DECL_SECURITY
        2 + coded_index_size(row_counts_by_id, [TABLE_TYPE_DEF, TABLE_METHOD_DEF, TABLE_ASSEMBLY], 2) + blob_index_size
      when TABLE_CLASS_LAYOUT
        2 + 4 + simple_index_size(row_counts_by_id, TABLE_TYPE_DEF)
      when TABLE_FIELD_LAYOUT
        4 + simple_index_size(row_counts_by_id, TABLE_FIELD)
      when TABLE_STAND_ALONE_SIG
        blob_index_size
      when TABLE_EVENT_MAP
        simple_index_size(row_counts_by_id, TABLE_TYPE_DEF) + simple_index_size(row_counts_by_id, TABLE_EVENT)
      when TABLE_EVENT_PTR
        simple_index_size(row_counts_by_id, TABLE_EVENT)
      when TABLE_EVENT
        2 + string_index_size + coded_index_size(row_counts_by_id, [TABLE_TYPE_DEF, TABLE_TYPE_REF, TABLE_TYPE_SPEC], 2)
      when TABLE_PROPERTY_MAP
        simple_index_size(row_counts_by_id, TABLE_TYPE_DEF) + simple_index_size(row_counts_by_id, TABLE_PROPERTY)
      when TABLE_PROPERTY_PTR
        simple_index_size(row_counts_by_id, TABLE_PROPERTY)
      when TABLE_PROPERTY
        2 + string_index_size + blob_index_size
      when TABLE_METHOD_SEMANTICS
        2 + simple_index_size(row_counts_by_id, TABLE_METHOD_DEF) + coded_index_size(row_counts_by_id, [TABLE_EVENT, TABLE_PROPERTY], 1)
      when TABLE_METHOD_IMPL
        simple_index_size(row_counts_by_id, TABLE_TYPE_DEF) + coded_index_size(row_counts_by_id, [TABLE_METHOD_DEF, TABLE_MEMBER_REF], 1) + coded_index_size(row_counts_by_id, [TABLE_METHOD_DEF, TABLE_MEMBER_REF], 1)
      when TABLE_MODULE_REF
        string_index_size
      when TABLE_TYPE_SPEC
        blob_index_size
      when TABLE_IMPL_MAP
        2 + coded_index_size(row_counts_by_id, [TABLE_FIELD, TABLE_METHOD_DEF], 1) + string_index_size + simple_index_size(row_counts_by_id, TABLE_MODULE_REF)
      when TABLE_FIELD_RVA
        4 + simple_index_size(row_counts_by_id, TABLE_FIELD)
      when TABLE_ENC_LOG
        8
      when TABLE_ENC_MAP
        4
      when TABLE_ASSEMBLY
        4 + 2 + 2 + 2 + 2 + 4 + blob_index_size + string_index_size + string_index_size
      when TABLE_ASSEMBLY_PROCESSOR
        4
      when TABLE_ASSEMBLY_OS
        12
      when TABLE_ASSEMBLY_REF
        2 + 2 + 2 + 2 + 4 + blob_index_size + string_index_size + string_index_size + blob_index_size
      when TABLE_ASSEMBLY_REF_PROCESSOR
        4 + simple_index_size(row_counts_by_id, TABLE_ASSEMBLY_REF)
      when TABLE_ASSEMBLY_REF_OS
        12 + simple_index_size(row_counts_by_id, TABLE_ASSEMBLY_REF)
      when TABLE_FILE
        4 + string_index_size + blob_index_size
      when TABLE_EXPORTED_TYPE
        4 + 4 + string_index_size + string_index_size + coded_index_size(row_counts_by_id, [TABLE_FILE, TABLE_ASSEMBLY_REF, TABLE_EXPORTED_TYPE], 2)
      when TABLE_MANIFEST_RESOURCE
        4 + 4 + string_index_size + coded_index_size(row_counts_by_id, [TABLE_FILE, TABLE_ASSEMBLY_REF, TABLE_EXPORTED_TYPE], 2)
      when TABLE_NESTED_CLASS
        simple_index_size(row_counts_by_id, TABLE_TYPE_DEF) + simple_index_size(row_counts_by_id, TABLE_TYPE_DEF)
      when TABLE_GENERIC_PARAM
        2 + 2 + coded_index_size(row_counts_by_id, [TABLE_TYPE_DEF, TABLE_METHOD_DEF], 1) + string_index_size
      when TABLE_METHOD_SPEC
        coded_index_size(row_counts_by_id, [TABLE_METHOD_DEF, TABLE_MEMBER_REF], 1) + blob_index_size
      when TABLE_GENERIC_PARAM_CONSTRAINT
        simple_index_size(row_counts_by_id, TABLE_GENERIC_PARAM) + coded_index_size(row_counts_by_id, [TABLE_TYPE_DEF, TABLE_TYPE_REF, TABLE_TYPE_SPEC], 2)
      else
        0
      end
    end

    private def simple_index_size(row_counts_by_id : Array(UInt32), target_table : Int32) : Int32
      row_counts_by_id[target_table] < 0x10000_u32 ? 2 : 4
    end

    private def coded_index_size(row_counts_by_id : Array(UInt32), target_tables : Array(Int32), tag_bits : Int32) : Int32
      max_rows = target_tables.max_of { |table_id| row_counts_by_id[table_id]? || 0_u32 }
      limit = 1_u32 << (16 - tag_bits)
      max_rows < limit ? 2 : 4
    end

    private def heap_index_size(heap_sizes : UInt8, bit : UInt8) : Int32
      (heap_sizes & bit) == 0_u8 ? 2 : 4
    end

    private def read_heap_index(reader : BinaryReader, size : Int32) : UInt32
      size == 2 ? reader.read_u16.to_u32 : reader.read_u32
    end

    private def parse_module_rows(
      reader : BinaryReader,
      table_offset : Int32,
      row_count : UInt32,
      string_index_size : Int32,
      guid_index_size : Int32,
      strings_heap : Bytes?,
    ) : Array(ModuleRow)
      rows = Array(ModuleRow).new(row_count.to_i)
      reader.seek(table_offset)
      row_count.times do
        generation = reader.read_u16
        name = read_string_index(reader, strings_heap, string_index_size)
        mvid = read_heap_index(reader, guid_index_size)
        enc_id = read_heap_index(reader, guid_index_size)
        enc_base_id = read_heap_index(reader, guid_index_size)
        rows << ModuleRow.new(generation, name, mvid, enc_id, enc_base_id)
      end
      rows
    end

    private def parse_type_ref_rows(reader : BinaryReader, table_offset : Int32, row_count : UInt32, row_counts_by_id : Array(UInt32), string_index_size : Int32, strings_heap : Bytes?) : Array(TypeRefRow)
      rows = Array(TypeRefRow).new(row_count.to_i)
      resolution_scope_size = coded_index_size(row_counts_by_id, [TABLE_MODULE, TABLE_MODULE_REF, TABLE_ASSEMBLY_REF, TABLE_TYPE_REF], 2)
      reader.seek(table_offset)
      row_count.times do
        resolution_scope = read_heap_index(reader, resolution_scope_size)
        type_name = read_string_index(reader, strings_heap, string_index_size)
        type_namespace = read_string_index(reader, strings_heap, string_index_size)
        rows << TypeRefRow.new(resolution_scope, type_name, type_namespace)
      end
      rows
    end

    private def parse_type_def_rows(reader : BinaryReader, table_offset : Int32, row_count : UInt32, row_counts_by_id : Array(UInt32), string_index_size : Int32, strings_heap : Bytes?) : Array(TypeDefRow)
      rows = Array(TypeDefRow).new(row_count.to_i)
      extends_size = coded_index_size(row_counts_by_id, [TABLE_TYPE_DEF, TABLE_TYPE_REF, TABLE_TYPE_SPEC], 2)
      field_list_size = simple_index_size(row_counts_by_id, TABLE_FIELD)
      method_list_size = simple_index_size(row_counts_by_id, TABLE_METHOD_DEF)
      reader.seek(table_offset)
      row_count.times do
        flags = reader.read_u32
        type_name = read_string_index(reader, strings_heap, string_index_size)
        type_namespace = read_string_index(reader, strings_heap, string_index_size)
        extends = read_heap_index(reader, extends_size)
        field_list = read_heap_index(reader, field_list_size)
        method_list = read_heap_index(reader, method_list_size)
        rows << TypeDefRow.new(flags, type_name, type_namespace, extends, field_list, method_list)
      end
      rows
    end

    private def parse_method_def_rows(
      reader : BinaryReader,
      table_offset : Int32,
      row_count : UInt32,
      row_counts_by_id : Array(UInt32),
      string_index_size : Int32,
      blob_index_size : Int32,
      strings_heap : Bytes?,
      blob_heap : Bytes?,
      type_refs : Array(TypeRefRow),
      type_defs : Array(TypeDefRow),
    ) : Array(MethodDefRow)
      rows = Array(MethodDefRow).new(row_count.to_i)
      param_list_size = simple_index_size(row_counts_by_id, TABLE_PARAM)
      reader.seek(table_offset)
      row_count.times do
        rva = reader.read_u32
        impl_flags = reader.read_u16
        flags = reader.read_u16
        name = read_string_index(reader, strings_heap, string_index_size)
        signature = read_heap_index(reader, blob_index_size)
        param_list = read_heap_index(reader, param_list_size)
        decoded_signature = read_method_signature(blob_heap, signature, type_refs, type_defs)
        if @strict_mode && method_signature_has_unknown?(decoded_signature)
          raise ParseError.new("Strict mode: unsupported method signature in MethodDef '#{name}'")
        end
        rows << MethodDefRow.new(rva, impl_flags, flags, name, signature, param_list, decoded_signature)
      end
      rows
    end

    private def parse_field_rows(
      reader : BinaryReader,
      table_offset : Int32,
      row_count : UInt32,
      string_index_size : Int32,
      blob_index_size : Int32,
      strings_heap : Bytes?,
      blob_heap : Bytes?,
      type_refs : Array(TypeRefRow),
      type_defs : Array(TypeDefRow),
    ) : Array(FieldRow)
      rows = Array(FieldRow).new(row_count.to_i)
      reader.seek(table_offset)
      row_count.times do
        flags = reader.read_u16
        name = read_string_index(reader, strings_heap, string_index_size)
        signature = read_heap_index(reader, blob_index_size)
        decoded_signature = read_field_signature(blob_heap, signature, type_refs, type_defs)
        if @strict_mode && signature_has_unknown?(decoded_signature)
          raise ParseError.new("Strict mode: unsupported field signature in Field '#{name}'")
        end
        rows << FieldRow.new(flags, name, signature, decoded_signature)
      end
      rows
    end

    private def parse_param_rows(
      reader : BinaryReader,
      table_offset : Int32,
      row_count : UInt32,
      string_index_size : Int32,
      strings_heap : Bytes?,
    ) : Array(ParamRow)
      rows = Array(ParamRow).new(row_count.to_i)
      reader.seek(table_offset)
      row_count.times do
        flags = reader.read_u16
        sequence = reader.read_u16
        name = read_string_index(reader, strings_heap, string_index_size)
        rows << ParamRow.new(flags, sequence, name)
      end
      rows
    end

    private def parse_constant_rows(
      reader : BinaryReader,
      table_offset : Int32,
      row_count : UInt32,
      row_counts_by_id : Array(UInt32),
      blob_index_size : Int32,
      blob_heap : Bytes?,
      fields : Array(FieldRow),
      params : Array(ParamRow),
    ) : Array(ConstantRow)
      rows = Array(ConstantRow).new(row_count.to_i)
      parent_size = coded_index_size(row_counts_by_id, [TABLE_FIELD, TABLE_PARAM, TABLE_PROPERTY], 2)
      reader.seek(table_offset)
      row_count.times do
        value_type = reader.read_u8
        reader.skip(1) # reserved
        parent = read_heap_index(reader, parent_size)
        value_blob_index = read_heap_index(reader, blob_index_size)
        decoded_value = decode_constant_value(blob_heap, value_blob_index, value_type)
        owner_kind, owner_name = decode_has_constant_owner(parent, fields, params)
        rows << ConstantRow.new(value_type, parent, value_blob_index, decoded_value, owner_kind, owner_name)
      end
      rows
    end

    private def parse_interface_impl_rows(
      reader : BinaryReader,
      table_offset : Int32,
      row_count : UInt32,
      row_counts_by_id : Array(UInt32),
      type_defs : Array(TypeDefRow),
      type_refs : Array(TypeRefRow),
    ) : Array(InterfaceImplRow)
      rows = Array(InterfaceImplRow).new(row_count.to_i)
      class_index_size = simple_index_size(row_counts_by_id, TABLE_TYPE_DEF)
      interface_index_size = coded_index_size(row_counts_by_id, [TABLE_TYPE_DEF, TABLE_TYPE_REF, TABLE_TYPE_SPEC], 2)
      reader.seek(table_offset)
      row_count.times do
        class_index = read_heap_index(reader, class_index_size)
        interface_token = read_heap_index(reader, interface_index_size)
        class_name = resolve_type_def_name(class_index, type_defs)
        interface_name = resolve_type_def_or_ref(interface_token, type_refs, type_defs)
        rows << InterfaceImplRow.new(class_index, interface_token, class_name, interface_name)
      end
      rows
    end

    private def parse_member_ref_rows(
      reader : BinaryReader,
      table_offset : Int32,
      row_count : UInt32,
      row_counts_by_id : Array(UInt32),
      string_index_size : Int32,
      blob_index_size : Int32,
      strings_heap : Bytes?,
      blob_heap : Bytes?,
      type_defs : Array(TypeDefRow),
      type_refs : Array(TypeRefRow),
      method_defs : Array(MethodDefRow),
      type_specs : Array(TypeSpecRow),
      module_refs : Array(ModuleRefRow),
    ) : Array(MemberRefRow)
      rows = Array(MemberRefRow).new(row_count.to_i)
      class_index_size = coded_index_size(row_counts_by_id, [TABLE_TYPE_DEF, TABLE_TYPE_REF, TABLE_MODULE_REF, TABLE_METHOD_DEF, TABLE_TYPE_SPEC], 3)
      reader.seek(table_offset)
      row_count.times do
        class_token = read_heap_index(reader, class_index_size)
        name = read_string_index(reader, strings_heap, string_index_size)
        signature = read_heap_index(reader, blob_index_size)
        parent_kind, parent_name = decode_member_ref_parent(class_token, type_defs, type_refs, method_defs, type_specs, module_refs)
        decoded_signature = read_member_ref_signature(blob_heap, signature, type_refs, type_defs)
        if @strict_mode && signature_has_unknown?(decoded_signature)
          raise ParseError.new("Strict mode: unsupported signature in MemberRef '#{name}'")
        end
        rows << MemberRefRow.new(class_token, name, signature, parent_kind, parent_name, decoded_signature)
      end
      rows
    end

    private def parse_event_map_rows(
      reader : BinaryReader,
      table_offset : Int32,
      row_count : UInt32,
      row_counts_by_id : Array(UInt32),
      type_defs : Array(TypeDefRow),
    ) : Array(EventMapRow)
      rows = Array(EventMapRow).new(row_count.to_i)
      parent_size = simple_index_size(row_counts_by_id, TABLE_TYPE_DEF)
      event_list_size = simple_index_size(row_counts_by_id, TABLE_EVENT)
      reader.seek(table_offset)
      row_count.times do
        parent = read_heap_index(reader, parent_size)
        event_list = read_heap_index(reader, event_list_size)
        parent_name = resolve_type_def_name(parent, type_defs)
        rows << EventMapRow.new(parent, event_list, parent_name)
      end
      rows
    end

    private def parse_event_rows(
      reader : BinaryReader,
      table_offset : Int32,
      row_count : UInt32,
      row_counts_by_id : Array(UInt32),
      string_index_size : Int32,
      strings_heap : Bytes?,
      type_refs : Array(TypeRefRow),
      type_defs : Array(TypeDefRow),
    ) : Array(EventRow)
      rows = Array(EventRow).new(row_count.to_i)
      event_type_size = coded_index_size(row_counts_by_id, [TABLE_TYPE_DEF, TABLE_TYPE_REF, TABLE_TYPE_SPEC], 2)
      reader.seek(table_offset)
      row_count.times do
        flags = reader.read_u16
        name = read_string_index(reader, strings_heap, string_index_size)
        event_type = read_heap_index(reader, event_type_size)
        event_type_name = resolve_type_def_or_ref(event_type, type_refs, type_defs)
        rows << EventRow.new(flags, name, event_type, event_type_name)
      end
      rows
    end

    private def parse_property_map_rows(
      reader : BinaryReader,
      table_offset : Int32,
      row_count : UInt32,
      row_counts_by_id : Array(UInt32),
      type_defs : Array(TypeDefRow),
    ) : Array(PropertyMapRow)
      rows = Array(PropertyMapRow).new(row_count.to_i)
      parent_size = simple_index_size(row_counts_by_id, TABLE_TYPE_DEF)
      property_list_size = simple_index_size(row_counts_by_id, TABLE_PROPERTY)
      reader.seek(table_offset)
      row_count.times do
        parent = read_heap_index(reader, parent_size)
        property_list = read_heap_index(reader, property_list_size)
        parent_name = resolve_type_def_name(parent, type_defs)
        rows << PropertyMapRow.new(parent, property_list, parent_name)
      end
      rows
    end

    private def parse_property_rows(
      reader : BinaryReader,
      table_offset : Int32,
      row_count : UInt32,
      string_index_size : Int32,
      blob_index_size : Int32,
      strings_heap : Bytes?,
      blob_heap : Bytes?,
      type_refs : Array(TypeRefRow),
      type_defs : Array(TypeDefRow),
    ) : Array(PropertyRow)
      rows = Array(PropertyRow).new(row_count.to_i)
      reader.seek(table_offset)
      row_count.times do
        flags = reader.read_u16
        name = read_string_index(reader, strings_heap, string_index_size)
        type = read_heap_index(reader, blob_index_size)
        decoded_signature = read_property_signature(blob_heap, type, type_refs, type_defs)
        if @strict_mode && signature_has_unknown?(decoded_signature)
          raise ParseError.new("Strict mode: unsupported property signature in Property '#{name}'")
        end
        rows << PropertyRow.new(flags, name, type, decoded_signature)
      end
      rows
    end

    private def parse_method_semantics_rows(
      reader : BinaryReader,
      table_offset : Int32,
      row_count : UInt32,
      row_counts_by_id : Array(UInt32),
      method_defs : Array(MethodDefRow),
      events : Array(EventRow),
      properties : Array(PropertyRow),
    ) : Array(MethodSemanticsRow)
      rows = Array(MethodSemanticsRow).new(row_count.to_i)
      method_size = simple_index_size(row_counts_by_id, TABLE_METHOD_DEF)
      association_size = coded_index_size(row_counts_by_id, [TABLE_EVENT, TABLE_PROPERTY], 1)
      reader.seek(table_offset)
      row_count.times do
        semantics = reader.read_u16
        method = read_heap_index(reader, method_size)
        association = read_heap_index(reader, association_size)
        method_name = resolve_method_name(method, method_defs)
        association_kind, association_name = decode_has_semantics_association(association, events, properties)
        rows << MethodSemanticsRow.new(semantics, method, association, method_name, association_kind, association_name)
      end
      rows
    end

    private def parse_method_impl_rows(
      reader : BinaryReader,
      table_offset : Int32,
      row_count : UInt32,
      row_counts_by_id : Array(UInt32),
      type_defs : Array(TypeDefRow),
      method_defs : Array(MethodDefRow),
      member_refs : Array(MemberRefRow),
    ) : Array(MethodImplRow)
      rows = Array(MethodImplRow).new(row_count.to_i)
      class_size = simple_index_size(row_counts_by_id, TABLE_TYPE_DEF)
      method_def_or_ref_size = coded_index_size(row_counts_by_id, [TABLE_METHOD_DEF, TABLE_MEMBER_REF], 1)
      reader.seek(table_offset)
      row_count.times do
        klass = read_heap_index(reader, class_size)
        method_body = read_heap_index(reader, method_def_or_ref_size)
        method_declaration = read_heap_index(reader, method_def_or_ref_size)
        class_name = resolve_type_def_name(klass, type_defs)
        method_body_kind, method_body_name = decode_method_def_or_ref(method_body, method_defs, member_refs)
        method_declaration_kind, method_declaration_name = decode_method_def_or_ref(method_declaration, method_defs, member_refs)
        rows << MethodImplRow.new(
          klass,
          method_body,
          method_declaration,
          class_name,
          method_body_kind,
          method_body_name,
          method_declaration_kind,
          method_declaration_name
        )
      end
      rows
    end

    private def parse_assembly_ref_rows(
      reader : BinaryReader,
      table_offset : Int32,
      row_count : UInt32,
      string_index_size : Int32,
      blob_index_size : Int32,
      strings_heap : Bytes?,
    ) : Array(AssemblyRefRow)
      rows = Array(AssemblyRefRow).new(row_count.to_i)
      reader.seek(table_offset)
      row_count.times do
        major_version = reader.read_u16
        minor_version = reader.read_u16
        build_number = reader.read_u16
        revision_number = reader.read_u16
        flags = reader.read_u32
        public_key_or_token = read_heap_index(reader, blob_index_size)
        name = read_string_index(reader, strings_heap, string_index_size)
        culture = read_string_index(reader, strings_heap, string_index_size)
        hash_value = read_heap_index(reader, blob_index_size)
        rows << AssemblyRefRow.new(
          major_version,
          minor_version,
          build_number,
          revision_number,
          flags,
          public_key_or_token,
          name,
          culture,
          hash_value
        )
      end
      rows
    end

    private def parse_assembly_rows(
      reader : BinaryReader,
      table_offset : Int32,
      row_count : UInt32,
      string_index_size : Int32,
      blob_index_size : Int32,
      strings_heap : Bytes?,
    ) : Array(AssemblyRow)
      rows = Array(AssemblyRow).new(row_count.to_i)
      reader.seek(table_offset)
      row_count.times do
        hash_alg_id = reader.read_u32
        major_version = reader.read_u16
        minor_version = reader.read_u16
        build_number = reader.read_u16
        revision_number = reader.read_u16
        flags = reader.read_u32
        public_key = read_heap_index(reader, blob_index_size)
        name = read_string_index(reader, strings_heap, string_index_size)
        culture = read_string_index(reader, strings_heap, string_index_size)
        rows << AssemblyRow.new(
          hash_alg_id,
          major_version,
          minor_version,
          build_number,
          revision_number,
          flags,
          public_key,
          name,
          culture
        )
      end
      rows
    end

    private def parse_class_layout_rows(
      reader : BinaryReader,
      table_offset : Int32,
      row_count : UInt32,
      row_counts_by_id : Array(UInt32),
      type_defs : Array(TypeDefRow),
    ) : Array(ClassLayoutRow)
      rows = Array(ClassLayoutRow).new(row_count.to_i)
      parent_size = simple_index_size(row_counts_by_id, TABLE_TYPE_DEF)
      reader.seek(table_offset)
      row_count.times do
        packing_size = reader.read_u16
        class_size = reader.read_u32
        parent = read_heap_index(reader, parent_size)
        parent_name = resolve_type_def_name(parent, type_defs)
        rows << ClassLayoutRow.new(packing_size, class_size, parent, parent_name)
      end
      rows
    end

    private def parse_field_layout_rows(
      reader : BinaryReader,
      table_offset : Int32,
      row_count : UInt32,
      row_counts_by_id : Array(UInt32),
      fields : Array(FieldRow),
    ) : Array(FieldLayoutRow)
      rows = Array(FieldLayoutRow).new(row_count.to_i)
      field_size = simple_index_size(row_counts_by_id, TABLE_FIELD)
      reader.seek(table_offset)
      row_count.times do
        offset = reader.read_u32
        field = read_heap_index(reader, field_size)
        field_name = resolve_field_name(field, fields)
        rows << FieldLayoutRow.new(offset, field, field_name)
      end
      rows
    end

    private def parse_file_rows(
      reader : BinaryReader,
      table_offset : Int32,
      row_count : UInt32,
      string_index_size : Int32,
      blob_index_size : Int32,
      strings_heap : Bytes?,
    ) : Array(FileRow)
      rows = Array(FileRow).new(row_count.to_i)
      reader.seek(table_offset)
      row_count.times do
        flags = reader.read_u32
        name = read_string_index(reader, strings_heap, string_index_size)
        hash_value = read_heap_index(reader, blob_index_size)
        rows << FileRow.new(flags, name, hash_value)
      end
      rows
    end

    private def parse_exported_type_rows(
      reader : BinaryReader,
      table_offset : Int32,
      row_count : UInt32,
      row_counts_by_id : Array(UInt32),
      string_index_size : Int32,
      strings_heap : Bytes?,
      files : Array(FileRow),
      assembly_refs : Array(AssemblyRefRow),
      exported_types : Array(ExportedTypeRow),
    ) : Array(ExportedTypeRow)
      rows = Array(ExportedTypeRow).new(row_count.to_i)
      implementation_size = coded_index_size(row_counts_by_id, [TABLE_FILE, TABLE_ASSEMBLY_REF, TABLE_EXPORTED_TYPE], 2)
      reader.seek(table_offset)
      row_count.times do
        flags = reader.read_u32
        type_def_id = reader.read_u32
        type_name = read_string_index(reader, strings_heap, string_index_size)
        type_namespace = read_string_index(reader, strings_heap, string_index_size)
        implementation = read_heap_index(reader, implementation_size)
        implementation_kind, implementation_name = decode_implementation(implementation, files, assembly_refs, exported_types)
        rows << ExportedTypeRow.new(
          flags,
          type_def_id,
          type_name,
          type_namespace,
          implementation,
          implementation_kind,
          implementation_name
        )
      end
      rows
    end

    private def parse_manifest_resource_rows(
      reader : BinaryReader,
      table_offset : Int32,
      row_count : UInt32,
      row_counts_by_id : Array(UInt32),
      string_index_size : Int32,
      strings_heap : Bytes?,
      files : Array(FileRow),
      assembly_refs : Array(AssemblyRefRow),
      exported_types : Array(ExportedTypeRow),
    ) : Array(ManifestResourceRow)
      rows = Array(ManifestResourceRow).new(row_count.to_i)
      implementation_size = coded_index_size(row_counts_by_id, [TABLE_FILE, TABLE_ASSEMBLY_REF, TABLE_EXPORTED_TYPE], 2)
      reader.seek(table_offset)
      row_count.times do
        offset = reader.read_u32
        flags = reader.read_u32
        name = read_string_index(reader, strings_heap, string_index_size)
        implementation = read_heap_index(reader, implementation_size)
        implementation_kind, implementation_name = decode_implementation(implementation, files, assembly_refs, exported_types)
        rows << ManifestResourceRow.new(offset, flags, name, implementation, implementation_kind, implementation_name)
      end
      rows
    end

    private def parse_generic_param_rows(
      reader : BinaryReader,
      table_offset : Int32,
      row_count : UInt32,
      row_counts_by_id : Array(UInt32),
      string_index_size : Int32,
      strings_heap : Bytes?,
      type_defs : Array(TypeDefRow),
      method_defs : Array(MethodDefRow),
    ) : Array(GenericParamRow)
      rows = Array(GenericParamRow).new(row_count.to_i)
      owner_size = coded_index_size(row_counts_by_id, [TABLE_TYPE_DEF, TABLE_METHOD_DEF], 1)
      reader.seek(table_offset)
      row_count.times do
        number = reader.read_u16
        flags = reader.read_u16
        owner = read_heap_index(reader, owner_size)
        name = read_string_index(reader, strings_heap, string_index_size)
        owner_kind, owner_name = decode_type_or_method_def(owner, type_defs, method_defs)
        rows << GenericParamRow.new(number, flags, owner, name, owner_kind, owner_name)
      end
      rows
    end

    private def parse_method_spec_rows(
      reader : BinaryReader,
      table_offset : Int32,
      row_count : UInt32,
      row_counts_by_id : Array(UInt32),
      blob_index_size : Int32,
      blob_heap : Bytes?,
      type_refs : Array(TypeRefRow),
      type_defs : Array(TypeDefRow),
      method_defs : Array(MethodDefRow),
      member_refs : Array(MemberRefRow),
    ) : Array(MethodSpecRow)
      rows = Array(MethodSpecRow).new(row_count.to_i)
      method_size = coded_index_size(row_counts_by_id, [TABLE_METHOD_DEF, TABLE_MEMBER_REF], 1)
      reader.seek(table_offset)
      row_count.times do
        method = read_heap_index(reader, method_size)
        instantiation = read_heap_index(reader, blob_index_size)
        method_kind, method_name = decode_method_def_or_ref(method, method_defs, member_refs)
        decoded_instantiation = read_method_spec_instantiation(blob_heap, instantiation, type_refs, type_defs)
        if @strict_mode && signature_has_unknown?(decoded_instantiation)
          raise ParseError.new("Strict mode: unsupported MethodSpec instantiation")
        end
        rows << MethodSpecRow.new(method, instantiation, method_kind, method_name, decoded_instantiation)
      end
      rows
    end

    private def parse_generic_param_constraint_rows(
      reader : BinaryReader,
      table_offset : Int32,
      row_count : UInt32,
      row_counts_by_id : Array(UInt32),
      generic_params : Array(GenericParamRow),
      type_refs : Array(TypeRefRow),
      type_defs : Array(TypeDefRow),
    ) : Array(GenericParamConstraintRow)
      rows = Array(GenericParamConstraintRow).new(row_count.to_i)
      owner_size = simple_index_size(row_counts_by_id, TABLE_GENERIC_PARAM)
      constraint_size = coded_index_size(row_counts_by_id, [TABLE_TYPE_DEF, TABLE_TYPE_REF, TABLE_TYPE_SPEC], 2)
      reader.seek(table_offset)
      row_count.times do
        owner = read_heap_index(reader, owner_size)
        constraint = read_heap_index(reader, constraint_size)
        owner_name = resolve_generic_param_name(owner, generic_params)
        constraint_name = resolve_type_def_or_ref(constraint, type_refs, type_defs)
        rows << GenericParamConstraintRow.new(owner, constraint, owner_name, constraint_name)
      end
      rows
    end

    private def parse_type_spec_rows(
      reader : BinaryReader,
      table_offset : Int32,
      row_count : UInt32,
      blob_index_size : Int32,
      blob_heap : Bytes?,
      type_defs : Array(TypeDefRow),
      type_refs : Array(TypeRefRow),
    ) : Array(TypeSpecRow)
      rows = Array(TypeSpecRow).new(row_count.to_i)
      reader.seek(table_offset)
      row_count.times do
        signature = read_heap_index(reader, blob_index_size)
        decoded_type = read_type_spec_signature(blob_heap, signature, type_refs, type_defs)
        if @strict_mode && signature_has_unknown?(decoded_type)
          raise ParseError.new("Strict mode: unsupported TypeSpec signature")
        end
        rows << TypeSpecRow.new(signature, decoded_type)
      end
      rows
    end

    private def parse_module_ref_rows(
      reader : BinaryReader,
      table_offset : Int32,
      row_count : UInt32,
      string_index_size : Int32,
      strings_heap : Bytes?,
    ) : Array(ModuleRefRow)
      rows = Array(ModuleRefRow).new(row_count.to_i)
      reader.seek(table_offset)
      row_count.times do
        name = read_string_index(reader, strings_heap, string_index_size)
        rows << ModuleRefRow.new(name)
      end
      rows
    end

    private def parse_impl_map_rows(
      reader : BinaryReader,
      table_offset : Int32,
      row_count : UInt32,
      row_counts_by_id : Array(UInt32),
      string_index_size : Int32,
      strings_heap : Bytes?,
      module_refs : Array(ModuleRefRow),
      fields : Array(FieldRow),
      method_defs : Array(MethodDefRow),
    ) : Array(ImplMapRow)
      rows = Array(ImplMapRow).new(row_count.to_i)
      forwarded_size = coded_index_size(row_counts_by_id, [TABLE_FIELD, TABLE_METHOD_DEF], 1)
      scope_size = simple_index_size(row_counts_by_id, TABLE_MODULE_REF)
      reader.seek(table_offset)
      row_count.times do
        mapping_flags = reader.read_u16
        member_forwarded = read_heap_index(reader, forwarded_size)
        import_name = read_string_index(reader, strings_heap, string_index_size)
        import_scope = read_heap_index(reader, scope_size)
        scope_name = resolve_module_ref_name(import_scope, module_refs)
        target_kind, target_name = decode_member_forwarded(member_forwarded, fields, method_defs)
        rows << ImplMapRow.new(mapping_flags, member_forwarded, import_name, import_scope, scope_name, target_kind, target_name)
      end
      rows
    end

    private def parse_custom_attribute_rows(
      reader : BinaryReader,
      table_offset : Int32,
      row_count : UInt32,
      row_counts_by_id : Array(UInt32),
      blob_index_size : Int32,
      blob_heap : Bytes?,
      type_defs : Array(TypeDefRow),
      type_refs : Array(TypeRefRow),
      fields : Array(FieldRow),
      method_defs : Array(MethodDefRow),
      params : Array(ParamRow),
      interface_impls : Array(InterfaceImplRow),
      member_refs : Array(MemberRefRow),
      module_refs : Array(ModuleRefRow),
    ) : Array(CustomAttributeRow)
      rows = Array(CustomAttributeRow).new(row_count.to_i)
      parent_size = coded_index_size(row_counts_by_id, [TABLE_METHOD_DEF, TABLE_FIELD, TABLE_TYPE_REF, TABLE_TYPE_DEF, TABLE_PARAM, TABLE_INTERFACE_IMPL, TABLE_MEMBER_REF, TABLE_MODULE, TABLE_DECL_SECURITY, TABLE_PROPERTY, TABLE_EVENT, TABLE_STAND_ALONE_SIG, TABLE_MODULE_REF, TABLE_TYPE_SPEC, TABLE_ASSEMBLY, TABLE_ASSEMBLY_REF, TABLE_FILE, TABLE_EXPORTED_TYPE, TABLE_MANIFEST_RESOURCE, TABLE_GENERIC_PARAM, TABLE_GENERIC_PARAM_CONSTRAINT, TABLE_METHOD_SPEC], 5)
      type_size = coded_index_size(row_counts_by_id, [TABLE_METHOD_DEF, TABLE_MEMBER_REF], 3)
      reader.seek(table_offset)
      row_count.times do
        parent = read_heap_index(reader, parent_size)
        attribute_type = read_heap_index(reader, type_size)
        value = read_heap_index(reader, blob_index_size)

        parent_kind, parent_name = decode_custom_attribute_parent(parent, type_defs, type_refs, fields, method_defs, params, interface_impls, member_refs, module_refs)
        type_name = decode_custom_attribute_type(attribute_type, method_defs, member_refs)
        decoded_value = decode_custom_attribute_value(blob_heap, value, type_name)
        rows << CustomAttributeRow.new(parent, attribute_type, value, parent_kind, parent_name, type_name, decoded_value)
      end
      rows
    end

    private def parse_nested_class_rows(
      reader : BinaryReader,
      table_offset : Int32,
      row_count : UInt32,
      row_counts_by_id : Array(UInt32),
      type_defs : Array(TypeDefRow),
    ) : Array(NestedClassRow)
      rows = Array(NestedClassRow).new(row_count.to_i)
      type_def_index_size = simple_index_size(row_counts_by_id, TABLE_TYPE_DEF)
      reader.seek(table_offset)
      row_count.times do
        nested_class = read_heap_index(reader, type_def_index_size)
        enclosing_class = read_heap_index(reader, type_def_index_size)
        nested_name = resolve_type_def_name(nested_class, type_defs)
        enclosing_name = resolve_type_def_name(enclosing_class, type_defs)
        rows << NestedClassRow.new(nested_class, enclosing_class, nested_name, enclosing_name)
      end
      rows
    end

    private def read_string_index(reader : BinaryReader, strings_heap : Bytes?, index_size : Int32) : String
      index = read_heap_index(reader, index_size)
      read_string_at(strings_heap, index)
    end

    private def read_stream_bytes(reader : BinaryReader, streams : Array(StreamHeader), metadata_rva : UInt32, sections : Array(SectionHeader), name : String) : Bytes?
      stream = streams.find { |item| item.name == name }
      return nil unless stream
      stream_rva = metadata_rva + stream.offset
      stream_offset = rva_to_file_offset(sections, stream_rva)
      reader.read_bytes_at(stream_offset, stream.size.to_i)
    end

    private def read_string_at(strings_heap : Bytes?, index : UInt32) : String
      return "" unless strings_heap
      return "" if index == 0_u32
      offset = index.to_i
      if offset < 0 || offset >= strings_heap.size
        raise ParseError.new("String heap index out of range: #{index}")
      end

      ending = strings_heap.size
      cursor = offset
      while cursor < strings_heap.size
        if strings_heap[cursor] == 0_u8
          ending = cursor
          break
        end
        cursor += 1
      end
      String.new(strings_heap[offset, ending - offset])
    end

    private def read_method_signature(blob_heap : Bytes?, index : UInt32, type_refs : Array(TypeRefRow), type_defs : Array(TypeDefRow)) : MethodSignature?
      blob = read_blob_at(blob_heap, index)
      return nil unless blob
      SignatureDecoder.new(type_refs, type_defs).decode_method(blob)
    rescue ParseError
      nil
    end

    private def read_field_signature(blob_heap : Bytes?, index : UInt32, type_refs : Array(TypeRefRow), type_defs : Array(TypeDefRow)) : String?
      blob = read_blob_at(blob_heap, index)
      return nil unless blob
      SignatureDecoder.new(type_refs, type_defs).decode_field(blob)
    rescue ParseError
      nil
    end

    private def read_member_ref_signature(blob_heap : Bytes?, index : UInt32, type_refs : Array(TypeRefRow), type_defs : Array(TypeDefRow)) : String?
      blob = read_blob_at(blob_heap, index)
      return nil unless blob
      SignatureDecoder.new(type_refs, type_defs).decode_member_ref(blob)
    end

    private def read_property_signature(blob_heap : Bytes?, index : UInt32, type_refs : Array(TypeRefRow), type_defs : Array(TypeDefRow)) : String?
      blob = read_blob_at(blob_heap, index)
      return nil unless blob
      SignatureDecoder.new(type_refs, type_defs).decode_property(blob)
    rescue ParseError
      nil
    end

    private def read_method_spec_instantiation(blob_heap : Bytes?, index : UInt32, type_refs : Array(TypeRefRow), type_defs : Array(TypeDefRow)) : String?
      blob = read_blob_at(blob_heap, index)
      return nil unless blob
      SignatureDecoder.new(type_refs, type_defs).decode_method_spec_instantiation(blob)
    rescue ParseError
      nil
    end

    private def read_type_spec_signature(blob_heap : Bytes?, index : UInt32, type_refs : Array(TypeRefRow), type_defs : Array(TypeDefRow)) : String?
      blob = read_blob_at(blob_heap, index)
      return nil unless blob
      SignatureDecoder.new(type_refs, type_defs).decode_type_spec(blob)
    rescue ParseError
      nil
    end

    private def read_blob_at(blob_heap : Bytes?, index : UInt32) : Bytes?
      return nil unless blob_heap
      return nil if index == 0_u32
      cursor = index.to_i
      if cursor < 0 || cursor >= blob_heap.size
        raise ParseError.new("Blob heap index out of range: #{index}")
      end

      length, next_cursor = read_compressed_uint(blob_heap, cursor)
      if next_cursor + length.to_i > blob_heap.size
        raise ParseError.new("Blob heap data is truncated")
      end
      blob_heap[next_cursor, length.to_i]
    end

    private def decode_constant_value(blob_heap : Bytes?, index : UInt32, value_type : UInt8) : String?
      blob = read_blob_at(blob_heap, index)
      return nil unless blob
      return nil if blob.empty?

      case value_type
      when 0x02_u8 # boolean
        blob[0] == 0_u8 ? "false" : "true"
      when 0x03_u8 # char
        if blob.size < 2
          nil
        else
          code = blob[0].to_u16 | (blob[1].to_u16 << 8)
          code.chr.to_s
        end
      when 0x04_u8 # i1
        blob[0].unsafe_as(Int8).to_s
      when 0x05_u8 # u1
        blob[0].to_s
      when 0x06_u8 # i2
        return nil if blob.size < 2
        value = blob[0].to_u16 | (blob[1].to_u16 << 8)
        value.unsafe_as(Int16).to_s
      when 0x07_u8 # u2
        return nil if blob.size < 2
        (blob[0].to_u16 | (blob[1].to_u16 << 8)).to_s
      when 0x08_u8 # i4
        return nil if blob.size < 4
        value = blob[0].to_u32 | (blob[1].to_u32 << 8) | (blob[2].to_u32 << 16) | (blob[3].to_u32 << 24)
        value.unsafe_as(Int32).to_s
      when 0x09_u8 # u4
        return nil if blob.size < 4
        (blob[0].to_u32 | (blob[1].to_u32 << 8) | (blob[2].to_u32 << 16) | (blob[3].to_u32 << 24)).to_s
      when 0x0A_u8 # i8
        return nil if blob.size < 8
        value = blob[0].to_u64 |
                (blob[1].to_u64 << 8) |
                (blob[2].to_u64 << 16) |
                (blob[3].to_u64 << 24) |
                (blob[4].to_u64 << 32) |
                (blob[5].to_u64 << 40) |
                (blob[6].to_u64 << 48) |
                (blob[7].to_u64 << 56)
        value.unsafe_as(Int64).to_s
      when 0x0B_u8 # u8
        return nil if blob.size < 8
        (blob[0].to_u64 |
          (blob[1].to_u64 << 8) |
          (blob[2].to_u64 << 16) |
          (blob[3].to_u64 << 24) |
          (blob[4].to_u64 << 32) |
          (blob[5].to_u64 << 40) |
          (blob[6].to_u64 << 48) |
          (blob[7].to_u64 << 56)).to_s
      when 0x0E_u8 # string (UTF-16)
        decode_utf16le(blob)
      else
        nil
      end
    rescue ParseError
      nil
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


    private def resolve_type_def_or_ref(coded_index : UInt32, type_refs : Array(TypeRefRow), type_defs : Array(TypeDefRow)) : String
      tag = coded_index & 0x3_u32
      row_index = (coded_index >> 2).to_i
      return "<null>" if row_index <= 0

      case tag
      when 0_u32
        type = type_defs[row_index - 1]?
        return "<typedef:#{row_index}>" unless type
        qualify_type_name(type.type_namespace, type.type_name)
      when 1_u32
        type = type_refs[row_index - 1]?
        return "<typeref:#{row_index}>" unless type
        qualify_type_name(type.type_namespace, type.type_name)
      when 2_u32
        "<typespec:#{row_index}>"
      else
        "<invalid-typedeforref:#{coded_index}>"
      end
    end

    private def resolve_type_def_name(type_def_index : UInt32, type_defs : Array(TypeDefRow)) : String?
      row_index = type_def_index.to_i
      return nil if row_index <= 0
      type = type_defs[row_index - 1]?
      return nil unless type
      qualify_type_name(type.type_namespace, type.type_name)
    end

    private def qualify_type_name(namespace_name : String, type_name : String) : String
      return type_name if namespace_name.empty?
      "#{namespace_name}.#{type_name}"
    end

    private def decode_has_constant_owner(coded_parent : UInt32, fields : Array(FieldRow), params : Array(ParamRow)) : {String, String?}
      tag = coded_parent & 0x3_u32
      row_index = (coded_parent >> 2).to_i
      return {"unknown", nil} if row_index <= 0

      case tag
      when 0_u32
        field = fields[row_index - 1]?
        {"field", field.try(&.name)}
      when 1_u32
        param = params[row_index - 1]?
        {"param", param.try(&.name)}
      when 2_u32
        {"property", nil}
      else
        {"unknown", nil}
      end
    end

    private def decode_member_ref_parent(
      coded_parent : UInt32,
      type_defs : Array(TypeDefRow),
      type_refs : Array(TypeRefRow),
      method_defs : Array(MethodDefRow),
      type_specs : Array(TypeSpecRow),
      module_refs : Array(ModuleRefRow),
    ) : {String, String?}
      tag = coded_parent & 0x7_u32
      row_index = (coded_parent >> 3).to_i
      return {"unknown", nil} if row_index <= 0

      case tag
      when 0_u32
        type = type_defs[row_index - 1]?
        {"typedef", type.try { |t| qualify_type_name(t.type_namespace, t.type_name) }}
      when 1_u32
        type = type_refs[row_index - 1]?
        {"typeref", type.try { |t| qualify_type_name(t.type_namespace, t.type_name) }}
      when 2_u32
        module_ref = module_refs[row_index - 1]?
        {"moduleref", module_ref.try(&.name)}
      when 3_u32
        method = method_defs[row_index - 1]?
        {"methoddef", method.try(&.name)}
      when 4_u32
        typespec = type_specs[row_index - 1]?
        {"typespec", typespec.try(&.decoded_type)}
      else
        {"unknown", nil}
      end
    end

    private def resolve_member_ref_parents(
      member_refs : Array(MemberRefRow),
      type_defs : Array(TypeDefRow),
      type_refs : Array(TypeRefRow),
      method_defs : Array(MethodDefRow),
      type_specs : Array(TypeSpecRow),
      module_refs : Array(ModuleRefRow),
    ) : Array(MemberRefRow)
      member_refs.map do |member_ref|
        parent_kind, parent_name = decode_member_ref_parent(member_ref.class_token, type_defs, type_refs, method_defs, type_specs, module_refs)
        MemberRefRow.new(
          member_ref.class_token,
          member_ref.name,
          member_ref.signature,
          parent_kind,
          parent_name,
          member_ref.decoded_signature
        )
      end
    end

    private def resolve_module_ref_name(module_ref_index : UInt32, module_refs : Array(ModuleRefRow)) : String?
      row_index = module_ref_index.to_i
      return nil if row_index <= 0
      module_refs[row_index - 1]?.try(&.name)
    end

    private def decode_member_forwarded(coded_index : UInt32, fields : Array(FieldRow), method_defs : Array(MethodDefRow)) : {String, String?}
      tag = coded_index & 0x1_u32
      row_index = (coded_index >> 1).to_i
      return {"unknown", nil} if row_index <= 0

      case tag
      when 0_u32
        field = fields[row_index - 1]?
        {"field", field.try(&.name)}
      when 1_u32
        method = method_defs[row_index - 1]?
        {"method", method.try(&.name)}
      else
        {"unknown", nil}
      end
    end

    private def resolve_method_name(method_index : UInt32, method_defs : Array(MethodDefRow)) : String?
      row_index = method_index.to_i
      return nil if row_index <= 0
      method_defs[row_index - 1]?.try(&.name)
    end

    private def resolve_field_name(field_index : UInt32, fields : Array(FieldRow)) : String?
      row_index = field_index.to_i
      return nil if row_index <= 0
      fields[row_index - 1]?.try(&.name)
    end

    private def resolve_generic_param_name(index : UInt32, generic_params : Array(GenericParamRow)) : String?
      row_index = index.to_i
      return nil if row_index <= 0
      generic_params[row_index - 1]?.try(&.name)
    end

    private def decode_has_semantics_association(coded_association : UInt32, events : Array(EventRow), properties : Array(PropertyRow)) : {String, String?}
      tag = coded_association & 0x1_u32
      row_index = (coded_association >> 1).to_i
      return {"unknown", nil} if row_index <= 0

      case tag
      when 0_u32
        event = events[row_index - 1]?
        {"event", event.try(&.name)}
      when 1_u32
        property = properties[row_index - 1]?
        {"property", property.try(&.name)}
      else
        {"unknown", nil}
      end
    end

    private def decode_method_def_or_ref(coded : UInt32, method_defs : Array(MethodDefRow), member_refs : Array(MemberRefRow)) : {String, String?}
      tag = coded & 0x1_u32
      row_index = (coded >> 1).to_i
      return {"unknown", nil} if row_index <= 0

      case tag
      when 0_u32
        method = method_defs[row_index - 1]?
        {"methoddef", method.try(&.name)}
      when 1_u32
        member_ref = member_refs[row_index - 1]?
        {"memberref", member_ref.try(&.name)}
      else
        {"unknown", nil}
      end
    end

    private def decode_type_or_method_def(coded : UInt32, type_defs : Array(TypeDefRow), method_defs : Array(MethodDefRow)) : {String, String?}
      tag = coded & 0x1_u32
      row_index = (coded >> 1).to_i
      return {"unknown", nil} if row_index <= 0

      case tag
      when 0_u32
        type_def = type_defs[row_index - 1]?
        {"typedef", type_def.try { |t| qualify_type_name(t.type_namespace, t.type_name) }}
      when 1_u32
        method = method_defs[row_index - 1]?
        {"methoddef", method.try(&.name)}
      else
        {"unknown", nil}
      end
    end

    private def decode_implementation(
      coded : UInt32,
      files : Array(FileRow),
      assembly_refs : Array(AssemblyRefRow),
      exported_types : Array(ExportedTypeRow),
    ) : {String, String?}
      tag = coded & 0x3_u32
      row_index = (coded >> 2).to_i
      return {"none", nil} if row_index <= 0

      case tag
      when 0_u32
        file = files[row_index - 1]?
        {"file", file.try(&.name)}
      when 1_u32
        assembly_ref = assembly_refs[row_index - 1]?
        {"assemblyref", assembly_ref.try(&.name)}
      when 2_u32
        exported = exported_types[row_index - 1]?
        {"exportedtype", exported.try { |row| qualify_type_name(row.type_namespace, row.type_name) }}
      else
        {"unknown", nil}
      end
    end

    private def signature_has_unknown?(signature : String?) : Bool
      return false unless signature
      signature.includes?("unknown(")
    end

    private def method_signature_has_unknown?(signature : MethodSignature?) : Bool
      return true unless signature
      return true if signature.return_type.includes?("unknown(")
      signature.parameter_types.any? { |param| param.includes?("unknown(") }
    end

    private def decode_custom_attribute_parent(
      coded_parent : UInt32,
      type_defs : Array(TypeDefRow),
      type_refs : Array(TypeRefRow),
      fields : Array(FieldRow),
      method_defs : Array(MethodDefRow),
      params : Array(ParamRow),
      interface_impls : Array(InterfaceImplRow),
      member_refs : Array(MemberRefRow),
      module_refs : Array(ModuleRefRow),
    ) : {String, String?}
      tag = coded_parent & 0x1F_u32
      row_index = (coded_parent >> 5).to_i
      return {"unknown", nil} if row_index <= 0

      case tag
      when 0_u32
        method = method_defs[row_index - 1]?
        {"methoddef", method.try(&.name)}
      when 1_u32
        field = fields[row_index - 1]?
        {"field", field.try(&.name)}
      when 2_u32
        type_ref = type_refs[row_index - 1]?
        {"typeref", type_ref.try { |t| qualify_type_name(t.type_namespace, t.type_name) }}
      when 3_u32
        type_def = type_defs[row_index - 1]?
        {"typedef", type_def.try { |t| qualify_type_name(t.type_namespace, t.type_name) }}
      when 4_u32
        param = params[row_index - 1]?
        {"param", param.try(&.name)}
      when 5_u32
        interface_impl = interface_impls[row_index - 1]?
        {"interfaceimpl", interface_impl.try(&.class_name)}
      when 6_u32
        member_ref = member_refs[row_index - 1]?
        {"memberref", member_ref.try(&.name)}
      when 7_u32
        {"module", "<Module>"}
      when 12_u32
        module_ref = module_refs[row_index - 1]?
        {"moduleref", module_ref.try(&.name)}
      else
        {"unknown", nil}
      end
    end

    private def decode_custom_attribute_type(
      coded_type : UInt32,
      method_defs : Array(MethodDefRow),
      member_refs : Array(MemberRefRow),
    ) : String?
      tag = coded_type & 0x7_u32
      row_index = (coded_type >> 3).to_i
      return nil if row_index <= 0

      case tag
      when 2_u32
        method_defs[row_index - 1]?.try(&.name)
      when 3_u32
        member_refs[row_index - 1]?.try(&.parent_name)
      else
        nil
      end
    end

    private def decode_custom_attribute_value(blob_heap : Bytes?, index : UInt32, type_name : String?) : String?
      blob = read_blob_at(blob_heap, index)
      return nil unless blob
      CustomAttributeDecoder.new.decode(blob, type_name)
    rescue ParseError
      nil
    end

    private def resolve_custom_attribute_parents(
      custom_attributes : Array(CustomAttributeRow),
      type_defs : Array(TypeDefRow),
      type_refs : Array(TypeRefRow),
      fields : Array(FieldRow),
      method_defs : Array(MethodDefRow),
      params : Array(ParamRow),
      interface_impls : Array(InterfaceImplRow),
      member_refs : Array(MemberRefRow),
      module_refs : Array(ModuleRefRow),
    ) : Array(CustomAttributeRow)
      custom_attributes.map do |attribute|
        parent_kind, parent_name = decode_custom_attribute_parent(attribute.parent, type_defs, type_refs, fields, method_defs, params, interface_impls, member_refs, module_refs)
        CustomAttributeRow.new(
          attribute.parent,
          attribute.attribute_type,
          attribute.value,
          parent_kind,
          parent_name,
          attribute.type_name,
          attribute.decoded_value
        )
      end
    end

    private def resolve_constant_owners(constants : Array(ConstantRow), fields : Array(FieldRow), params : Array(ParamRow)) : Array(ConstantRow)
      constants.map do |constant|
        owner_kind, owner_name = decode_has_constant_owner(constant.parent, fields, params)
        ConstantRow.new(constant.value_type, constant.parent, constant.value_blob_index, constant.decoded_value, owner_kind, owner_name)
      end
    end

    private def decode_utf16le(bytes : Bytes) : String?
      return "" if bytes.empty?
      return nil unless (bytes.size % 2) == 0
      String.build do |io|
        cursor = 0
        while cursor < bytes.size
          codepoint = bytes[cursor].to_u16 | (bytes[cursor + 1].to_u16 << 8)
          io << codepoint.chr
          cursor += 2
        end
      end
    end

    private def attach_param_signature_types(params : Array(ParamRow), method_defs : Array(MethodDefRow)) : Array(ParamRow)
      return params if params.empty? || method_defs.empty?

      overrides = Array(String?).new(params.size, nil)

      method_defs.each_with_index do |method, index|
        signature = method.decoded_signature
        next unless signature
        start_rid = method.param_list.to_i
        next if start_rid <= 0

        end_rid = if index + 1 < method_defs.size
                    method_defs[index + 1].param_list.to_i - 1
                  else
                    params.size
                  end
        next if end_rid < start_rid

        (start_rid..end_rid).each do |rid|
          row = params[rid - 1]?
          next unless row
          sequence = row.sequence.to_i
          if sequence == 0
            overrides[rid - 1] = signature.return_type
          elsif sequence > 0 && sequence <= signature.parameter_types.size
            overrides[rid - 1] = signature.parameter_types[sequence - 1]
          end
        end
      end

      Array(ParamRow).new(params.size) do |idx|
        row = params[idx]
        signature_type = overrides[idx]
        if signature_type
          ParamRow.new(row.flags, row.sequence, row.name, signature_type)
        else
          row
        end
      end
    end

  end
end
