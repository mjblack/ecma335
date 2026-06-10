require "./spec_helper"

describe Ecma335 do
  it "parses metadata root and stream headers from a minimal PE fixture" do
    parsed = Ecma335.parse_bytes(build_minimal_metadata_fixture)

    parsed.metadata_root.signature.should eq(0x424A5342_u32)
    parsed.metadata_root.version_string.should eq("v4.0.30319")
    parsed.metadata_root.stream_names.should eq(["#~", "#Strings", "#Blob", "#GUID", "#US"])
    tables = parsed.metadata_root.tables_stream
    tables.should_not be_nil
    next unless tables

    tables.row_count("Module").should eq(1_u32)
    tables.row_count("TypeRef").should eq(1_u32)
    tables.row_count("TypeDef").should eq(2_u32)
    tables.row_count("Field").should eq(1_u32)
    tables.row_count("MethodDef").should eq(2_u32)
    tables.row_count("Param").should eq(1_u32)
    tables.row_count("MemberRef").should eq(1_u32)
    tables.row_count("Constant").should eq(2_u32)
    tables.row_count("CustomAttribute").should eq(1_u32)
    tables.row_count("EventMap").should eq(0_u32)
    tables.row_count("Event").should eq(0_u32)
    tables.row_count("PropertyMap").should eq(0_u32)
    tables.row_count("Property").should eq(0_u32)
    tables.row_count("MethodSemantics").should eq(0_u32)
    tables.row_count("MethodImpl").should eq(0_u32)
    tables.row_count("AssemblyRef").should eq(0_u32)
    tables.row_count("File").should eq(0_u32)
    tables.row_count("ExportedType").should eq(0_u32)
    tables.row_count("ManifestResource").should eq(0_u32)
    tables.row_count("GenericParam").should eq(0_u32)
    tables.row_count("MethodSpec").should eq(0_u32)
    tables.row_count("GenericParamConstraint").should eq(0_u32)
    tables.row_count("ModuleRef").should eq(1_u32)
    tables.row_count("TypeSpec").should eq(1_u32)
    tables.row_count("ImplMap").should eq(1_u32)
    tables.row_count("InterfaceImpl").should eq(1_u32)
    tables.row_count("NestedClass").should eq(1_u32)
    tables.type_refs.size.should eq(1)
    tables.type_defs.size.should eq(2)
    tables.fields.size.should eq(1)
    tables.method_defs.size.should eq(2)
    tables.params.size.should eq(1)
    tables.member_refs.size.should eq(1)
    tables.constants.size.should eq(2)
    tables.custom_attributes.size.should eq(1)
    tables.event_maps.size.should eq(0)
    tables.events.size.should eq(0)
    tables.property_maps.size.should eq(0)
    tables.properties.size.should eq(0)
    tables.method_semantics.size.should eq(0)
    tables.method_impls.size.should eq(0)
    tables.assembly_refs.size.should eq(0)
    tables.files.size.should eq(0)
    tables.exported_types.size.should eq(0)
    tables.manifest_resources.size.should eq(0)
    tables.generic_params.size.should eq(0)
    tables.method_specs.size.should eq(0)
    tables.generic_param_constraints.size.should eq(0)
    tables.module_refs.size.should eq(1)
    tables.type_specs.size.should eq(1)
    tables.impl_maps.size.should eq(1)
    tables.interface_impls.size.should eq(1)
    tables.nested_classes.size.should eq(1)
    tables.parsed_row_counts["TypeDef"]?.should eq(2_u32)
    tables.parsed_row_counts["MethodDef"]?.should eq(2_u32)
    tables.parsed_row_counts["Module"]?.should eq(1_u32)
    tables.parsed_tables.should contain("TypeDef")
    tables.parsed_tables.should contain("Module")
    tables.skipped_tables.should eq([] of String)
    tables.parse_coverage_ratio.should eq(1.0)
    tables.type_refs[0].type_name.should eq("Object")
    tables.type_refs[0].type_namespace.should eq("System")
    tables.type_defs[0].type_name.should eq("SampleType")
    tables.fields[0].name.should eq("SampleField")
    tables.fields[0].decoded_signature.should eq("valuetype(SampleType)")
    tables.params[0].name.should eq("value")
    tables.params[0].signature_type.should eq("valuetype(SampleType)")
    tables.constants[0].owner_kind.should eq("field")
    tables.constants[0].owner_name.should eq("SampleField")
    tables.constants[0].decoded_value.should eq("42")
    tables.constants[1].owner_kind.should eq("param")
    tables.constants[1].owner_name.should eq("value")
    tables.constants[1].decoded_value.should eq("7")
    tables.member_refs[0].name.should eq("SampleMemberRef")
    tables.member_refs[0].parent_kind.should eq("typeref")
    tables.member_refs[0].parent_name.should eq("System.Object")
    tables.member_refs[0].decoded_signature.should eq("() -> void")
    tables.type_specs[0].decoded_type.should eq("class(System.Object)")
    tables.module_refs[0].name.should eq("KERNEL32.DLL")
    tables.impl_maps[0].import_name.should eq("CreateFileW")
    tables.impl_maps[0].scope_name.should eq("KERNEL32.DLL")
    tables.impl_maps[0].target_kind.should eq("method")
    tables.impl_maps[0].target_name.should eq("SampleMethod")
    tables.custom_attributes[0].parent_kind.should eq("typedef")
    tables.custom_attributes[0].parent_name.should eq("SampleType")
    tables.interface_impls[0].class_name.should eq("SampleType")
    tables.interface_impls[0].interface_name.should eq("System.Object")
    tables.nested_classes[0].nested_name.should eq("<Module>")
    tables.nested_classes[0].enclosing_name.should eq("SampleType")
    tables.method_defs[0].name.should eq("SampleMethod")
    signature = tables.method_defs[0].decoded_signature
    signature.should_not be_nil
    next unless signature

    signature.return_type.should eq("void")
    signature.parameter_count.should eq(0_u32)
    signature.parameter_types.should eq([] of String)
    tables.method_defs[1].name.should eq("SecondMethod")
    second_signature = tables.method_defs[1].decoded_signature
    second_signature.should_not be_nil
    next unless second_signature

    second_signature.return_type.should eq("class(System.Object)")
    second_signature.parameter_count.should eq(1_u32)
    second_signature.parameter_types.should eq(["valuetype(SampleType)"])

    tables.type_def_by_token?(0x02000001_u32).try(&.type_name).should eq("SampleType")
    tables.method_def_by_token?(0x06000001_u32).try(&.name).should eq("SampleMethod")
    tables.field_by_token?(0x04000001_u32).try(&.name).should eq("SampleField")
    tables.type_def_by_token?(0x06000001_u32).should be_nil

    parsed.type_def_by_token?(0x02000001_u32).try(&.type_name).should eq("SampleType")
    parsed.method_def_by_token?(0x06000001_u32).try(&.name).should eq("SampleMethod")
    parsed.field_by_token?(0x04000001_u32).try(&.name).should eq("SampleField")

    api = parsed.api_model
    api.should_not be_nil
    next unless api

    sample_type = api.type?("SampleType")
    sample_type.should_not be_nil
    next unless sample_type
    sample_type.fields.any? { |field| field.name == "SampleField" }.should be_true
    sample_type.methods.any? { |method| method.native_import == "CreateFileW" }.should be_true
    sample_type.nested_types.should contain("<Module>")
    sample_type.token.should eq(0x02000001_u32)
    sample_type.generic_params.should eq([] of String)

    module_type = api.type?("<Module>")
    module_type.should_not be_nil
    next unless module_type
    module_type.enclosing_type.should eq("SampleType")
    module_type.token.should eq(0x02000002_u32)

    sample_method = sample_type.methods.find { |method| method.name == "SampleMethod" }
    sample_method.should_not be_nil
    next unless sample_method
    sample_method.token.should eq(0x06000001_u32)
    sample_method.generic_params.should eq([] of String)
    sample_method.signature.should_not be_nil
    next unless sample_method.signature
    sample_method.signature.not_nil!.return_type.should eq("void")

    sample_field = sample_type.fields.find { |field| field.name == "SampleField" }
    sample_field.should_not be_nil
    next unless sample_field
    sample_field.token.should eq(0x04000001_u32)
  end

  it "raises parse errors for non-PE input" do
    expect_raises(Ecma335::ParseError, /Invalid DOS signature/) do
      Ecma335.parse_bytes(Bytes[0x00_u8, 0x01_u8, 0x02_u8, 0x03_u8])
    end
  end

  it "supports strict mode for fully decoded tables" do
    parsed = Ecma335.parse_bytes(build_minimal_metadata_fixture, strict: true)
    parsed.metadata_root.tables_stream.should_not be_nil
  end

  it "provides canonical signature formatting helpers" do
    parsed = Ecma335.parse_bytes(build_minimal_metadata_fixture)
    tables = parsed.metadata_root.tables_stream
    tables.should_not be_nil
    next unless tables

    signature = tables.method_defs[1].decoded_signature
    signature.should_not be_nil
    next unless signature

    signature.to_signature_string.should eq("(valuetype(SampleType)) -> class(System.Object)")
    signature.to_signature_string(canonical: true).should eq("(SampleType) -> System.Object")
    signature.canonical_return_type.should eq("System.Object")
    signature.canonical_parameter_types.should eq(["SampleType"])
  end

  it "decodes unmanaged method calling conventions in signatures" do
    # HASTHIS | THISCALL, 1 parameter, return ptr(void), param uint32.
    blob = Bytes[0x23_u8, 0x01_u8, 0x0F_u8, 0x01_u8, 0x09_u8]
    decoder = Ecma335::SignatureDecoder.new([] of Ecma335::TypeRefRow, [] of Ecma335::TypeDefRow)
    signature = decoder.decode_method(blob)
    signature.should_not be_nil
    next unless signature

    signature.has_this.should be_true
    signature.parameter_count.should eq(1_u32)
    signature.return_type.should eq("ptr(void)")
    signature.parameter_types.should eq(["uint32"])
  end

  it "decodes known WinMD custom attribute payloads" do
    decoder = Ecma335::CustomAttributeDecoder.new

    contract_blob = Bytes[0x01_u8, 0x00_u8, 0x07_u8, 0x00_u8, 0x00_u8, 0x00_u8, 0x00_u8, 0x00_u8]
    decoder.decode(contract_blob, "Windows.Foundation.Metadata.ContractVersionAttribute").should eq("contract_version(7)")

    supported_arch_blob = Bytes[0x01_u8, 0x00_u8, 0x03_u8, 0x00_u8, 0x00_u8, 0x00_u8, 0x00_u8, 0x00_u8]
    decoder.decode(supported_arch_blob, "Windows.Foundation.Metadata.SupportedArchitectureAttribute").should eq("supported_architecture(0x3)")

    deprecated_blob = Bytes[
      0x01_u8, 0x00_u8, # prolog
      0x03_u8,          # string length
      0x6F_u8, 0x6C_u8, 0x64_u8, # "old"
      0x02_u8, 0x00_u8, 0x00_u8, 0x00_u8, # DeprecationType
      0x00_u8, 0x00_u8, # named args
    ]
    decoder.decode(deprecated_blob, "Windows.Foundation.Metadata.DeprecatedAttribute").should eq("deprecated(old, 2)")
  end

  it "parses the local winmd fixture when present" do
    winmd_path = File.expand_path("../winmd/Windows.Win32.winmd", __DIR__)
    unless File.exists?(winmd_path)
      pending("Place Windows.Win32.winmd in ./winmd to run this integration spec")
    end

    parsed = Ecma335.parse(winmd_path)
    parsed.metadata_root.signature.should eq(0x424A5342_u32)
    parsed.metadata_root.stream_names.should contain("#~")
    parsed.metadata_root.stream_names.should contain("#Strings")
    parsed.metadata_root.stream_names.should contain("#Blob")
    parsed.metadata_root.stream_names.should contain("#GUID")
    parsed.metadata_root.stream_names.should contain("#US")
    tables = parsed.metadata_root.tables_stream
    tables.should_not be_nil
    next unless tables

    tables.row_count("TypeDef").should be > 0_u32
    tables.row_count("Field").should be > 0_u32
    tables.row_count("Param").should be > 0_u32
    tables.row_count("MemberRef").should be > 0_u32
    tables.row_count("Constant").should be > 0_u32
    tables.row_count("CustomAttribute").should be > 0_u32
    tables.row_count("EventMap").should be >= 0_u32
    tables.row_count("Event").should be >= 0_u32
    tables.row_count("PropertyMap").should be >= 0_u32
    tables.row_count("Property").should be >= 0_u32
    tables.row_count("MethodSemantics").should be >= 0_u32
    tables.row_count("MethodImpl").should be >= 0_u32
    tables.row_count("AssemblyRef").should be >= 0_u32
    tables.row_count("File").should be >= 0_u32
    tables.row_count("ExportedType").should be >= 0_u32
    tables.row_count("ManifestResource").should be >= 0_u32
    tables.row_count("GenericParam").should be >= 0_u32
    tables.row_count("MethodSpec").should be >= 0_u32
    tables.row_count("GenericParamConstraint").should be >= 0_u32
    tables.row_count("ModuleRef").should be > 0_u32
    tables.row_count("InterfaceImpl").should be > 0_u32
    tables.row_count("NestedClass").should be > 0_u32
    tables.type_defs.size.should be > 0
    tables.fields.size.should be > 0
    tables.params.size.should be > 0
    tables.member_refs.size.should be <= tables.row_count("MemberRef").to_i
    tables.constants.size.should be <= tables.row_count("Constant").to_i
    tables.custom_attributes.size.should be <= tables.row_count("CustomAttribute").to_i
    tables.event_maps.size.should be <= tables.row_count("EventMap").to_i
    tables.events.size.should be <= tables.row_count("Event").to_i
    tables.property_maps.size.should be <= tables.row_count("PropertyMap").to_i
    tables.properties.size.should be <= tables.row_count("Property").to_i
    tables.method_semantics.size.should be <= tables.row_count("MethodSemantics").to_i
    tables.method_impls.size.should be <= tables.row_count("MethodImpl").to_i
    tables.assembly_refs.size.should be <= tables.row_count("AssemblyRef").to_i
    tables.files.size.should be <= tables.row_count("File").to_i
    tables.exported_types.size.should be <= tables.row_count("ExportedType").to_i
    tables.manifest_resources.size.should be <= tables.row_count("ManifestResource").to_i
    tables.generic_params.size.should be <= tables.row_count("GenericParam").to_i
    tables.method_specs.size.should be <= tables.row_count("MethodSpec").to_i
    tables.generic_param_constraints.size.should be <= tables.row_count("GenericParamConstraint").to_i
    tables.module_refs.size.should be <= tables.row_count("ModuleRef").to_i
    tables.type_specs.size.should be <= tables.row_count("TypeSpec").to_i
    tables.impl_maps.size.should be <= tables.row_count("ImplMap").to_i
    tables.interface_impls.size.should be <= tables.row_count("InterfaceImpl").to_i
    tables.nested_classes.size.should be <= tables.row_count("NestedClass").to_i
    tables.parsed_row_counts["TypeDef"]?.should eq(tables.row_count("TypeDef"))
    tables.parsed_row_counts["MethodDef"]?.should eq(tables.row_count("MethodDef"))
    tables.parsed_row_counts["Module"]?.should eq(tables.row_count("Module"))
    tables.method_defs.size.should be > 0
    tables.method_defs.any? { |row| !row.decoded_signature.nil? }.should be_true

    api = parsed.api_model
    api.should_not be_nil
    next unless api

    api.types.size.should be > 0
    api.types.any? { |type| type.full_name.starts_with?("Windows.") || type.full_name.starts_with?("Win32.") }.should be_true
    api.find_methods("CreateFileW").size.should be >= 0
  end

  it "does not emit duplicate lines in `list types --all` output for local winmd fixture" do
    winmd_path = File.expand_path("../winmd/Windows.Win32.winmd", __DIR__)
    unless File.exists?(winmd_path)
      pending("Place Windows.Win32.winmd in ./winmd to run this integration spec")
    end

    repo_root = File.expand_path("..", __DIR__)
    stdout_io = IO::Memory.new
    stderr_io = IO::Memory.new
    status = Process.run(
      "crystal",
      ["run", "src/ecma335_tool.cr", "--", winmd_path, "list", "types", "--all"],
      output: stdout_io,
      error: stderr_io,
      chdir: repo_root
    )

    status.success?.should be_true
    lines = stdout_io.to_s.lines.map(&.strip).reject(&.empty?)
    lines.size.should eq(lines.uniq.size)
  end
end

private def build_minimal_metadata_fixture : Bytes
  bytes = Bytes.new(0x800, 0_u8)

  # DOS header and PE location.
  write_u16(bytes, 0x00, 0x5A4D_u16)
  write_u32(bytes, 0x3C, 0x80_u32)

  # PE signature + COFF header.
  write_u32(bytes, 0x80, 0x00004550_u32)
  write_u16(bytes, 0x84, 0x014C_u16)
  write_u16(bytes, 0x86, 1_u16)
  write_u16(bytes, 0x94, 0x00E0_u16) # optional header size

  optional_header = 0x98
  write_u16(bytes, optional_header, 0x010B_u16) # PE32

  cli_data_directory = optional_header + 96 + (14 * 8)
  write_u32(bytes, cli_data_directory, 0x2100_u32)
  write_u32(bytes, cli_data_directory + 4, 0x48_u32)

  section_header = optional_header + 0xE0
  write_string(bytes, section_header, ".text")
  write_u32(bytes, section_header + 8, 0x800_u32)
  write_u32(bytes, section_header + 12, 0x2000_u32)
  write_u32(bytes, section_header + 16, 0x800_u32)
  write_u32(bytes, section_header + 20, 0x200_u32)

  # CLI header at RVA 0x2100 -> file offset 0x300
  cli_header = 0x300
  write_u32(bytes, cli_header, 0x48_u32)
  write_u16(bytes, cli_header + 4, 2_u16)
  write_u16(bytes, cli_header + 6, 5_u16)
  write_u32(bytes, cli_header + 8, 0x2200_u32)
  write_u32(bytes, cli_header + 12, 0x180_u32)

  metadata_root = 0x400
  write_u32(bytes, metadata_root, 0x424A5342_u32)
  write_u16(bytes, metadata_root + 4, 1_u16)
  write_u16(bytes, metadata_root + 6, 1_u16)
  write_u32(bytes, metadata_root + 8, 0_u32)
  write_u32(bytes, metadata_root + 12, 12_u32)
  write_string(bytes, metadata_root + 16, "v4.0.30319")
  write_u16(bytes, metadata_root + 28, 0_u16)
  write_u16(bytes, metadata_root + 30, 5_u16)

  stream_cursor = metadata_root + 32
  stream_cursor = write_stream_header(bytes, stream_cursor, 0x100_u32, 0x80_u32, "#~")
  stream_cursor = write_stream_header(bytes, stream_cursor, 0x200_u32, 0x90_u32, "#Strings")
  stream_cursor = write_stream_header(bytes, stream_cursor, 0x300_u32, 0x50_u32, "#Blob")
  stream_cursor = write_stream_header(bytes, stream_cursor, 0x350_u32, 0x10_u32, "#GUID")
  write_stream_header(bytes, stream_cursor, 0x360_u32, 0x20_u32, "#US")

  # #~ stream at metadata root + 0x100
  tables_stream = metadata_root + 0x100
  write_u32(bytes, tables_stream, 0_u32)                 # reserved
  bytes[tables_stream + 4] = 2_u8                        # major
  bytes[tables_stream + 5] = 0_u8                        # minor
  bytes[tables_stream + 6] = 0_u8                        # heap sizes
  bytes[tables_stream + 7] = 1_u8                        # reserved
  write_u64(bytes, tables_stream + 8, 0x2001C001F57_u64) # Module + TypeRef + TypeDef + Field + MethodDef + Param + InterfaceImpl + MemberRef + Constant + CustomAttribute + ModuleRef + TypeSpec + ImplMap + NestedClass
  write_u64(bytes, tables_stream + 16, 0_u64)            # sorted mask
  write_u32(bytes, tables_stream + 24, 1_u32)            # Module rows
  write_u32(bytes, tables_stream + 28, 1_u32)            # TypeRef rows
  write_u32(bytes, tables_stream + 32, 2_u32)            # TypeDef rows
  write_u32(bytes, tables_stream + 36, 1_u32)            # Field rows
  write_u32(bytes, tables_stream + 40, 2_u32)            # MethodDef rows
  write_u32(bytes, tables_stream + 44, 1_u32)            # Param rows
  write_u32(bytes, tables_stream + 48, 1_u32)            # InterfaceImpl rows
  write_u32(bytes, tables_stream + 52, 1_u32)            # MemberRef rows
  write_u32(bytes, tables_stream + 56, 2_u32)            # Constant rows
  write_u32(bytes, tables_stream + 60, 1_u32)            # CustomAttribute rows
  write_u32(bytes, tables_stream + 64, 1_u32)            # ModuleRef rows
  write_u32(bytes, tables_stream + 68, 1_u32)            # TypeSpec rows
  write_u32(bytes, tables_stream + 72, 1_u32)            # ImplMap rows
  write_u32(bytes, tables_stream + 76, 1_u32)            # NestedClass rows

  tables_data = tables_stream + 80
  # Module row (Generation + Name + Mvid + EncId + EncBaseId)
  write_u16(bytes, tables_data, 0_u16)
  write_u16(bytes, tables_data + 2, 0_u16)
  write_u16(bytes, tables_data + 4, 0_u16)
  write_u16(bytes, tables_data + 6, 0_u16)
  write_u16(bytes, tables_data + 8, 0_u16)

  type_ref_row = tables_data + 10
  write_u16(bytes, type_ref_row, 0_u16)     # ResolutionScope
  write_u16(bytes, type_ref_row + 2, 1_u16) # TypeName => "Object"
  write_u16(bytes, type_ref_row + 4, 8_u16) # TypeNamespace => "System"

  type_def_row1 = type_ref_row + 6
  write_u32(bytes, type_def_row1, 0_u32)
  write_u16(bytes, type_def_row1 + 4, 15_u16) # "SampleType"
  write_u16(bytes, type_def_row1 + 6, 0_u16)  # empty namespace
  write_u16(bytes, type_def_row1 + 8, 5_u16)  # Extends => TypeRef row 1
  write_u16(bytes, type_def_row1 + 10, 1_u16) # FieldList
  write_u16(bytes, type_def_row1 + 12, 1_u16) # MethodList

  type_def_row2 = type_def_row1 + 14
  write_u32(bytes, type_def_row2, 0_u32)
  write_u16(bytes, type_def_row2 + 4, 26_u16) # "<Module>"
  write_u16(bytes, type_def_row2 + 6, 0_u16)
  write_u16(bytes, type_def_row2 + 8, 0_u16)
  write_u16(bytes, type_def_row2 + 10, 2_u16)
  write_u16(bytes, type_def_row2 + 12, 2_u16)

  field_row = type_def_row2 + 14
  write_u16(bytes, field_row, 0_u16)
  write_u16(bytes, field_row + 2, 35_u16) # "SampleField"
  write_u16(bytes, field_row + 4, 12_u16) # blob signature index

  method_def_row = field_row + 6
  write_u32(bytes, method_def_row, 0x1234_u32)
  write_u16(bytes, method_def_row + 4, 0_u16)
  write_u16(bytes, method_def_row + 6, 0_u16)
  write_u16(bytes, method_def_row + 8, 53_u16) # "SampleMethod"
  write_u16(bytes, method_def_row + 10, 1_u16) # blob signature index
  write_u16(bytes, method_def_row + 12, 1_u16) # ParamList

  method_def_row2 = method_def_row + 14
  write_u32(bytes, method_def_row2, 0x1240_u32)
  write_u16(bytes, method_def_row2 + 4, 0_u16)
  write_u16(bytes, method_def_row2 + 6, 0_u16)
  write_u16(bytes, method_def_row2 + 8, 66_u16) # "SecondMethod"
  write_u16(bytes, method_def_row2 + 10, 5_u16) # blob signature index
  write_u16(bytes, method_def_row2 + 12, 1_u16) # ParamList

  param_row = method_def_row2 + 14
  write_u16(bytes, param_row, 0_u16)
  write_u16(bytes, param_row + 2, 1_u16)
  write_u16(bytes, param_row + 4, 47_u16) # "value"

  interface_impl_row = param_row + 6
  write_u16(bytes, interface_impl_row, 1_u16)     # Class => TypeDef row 1
  write_u16(bytes, interface_impl_row + 2, 5_u16) # Interface => TypeRef row 1 (TypeDefOrRef)

  member_ref_row = interface_impl_row + 4
  write_u16(bytes, member_ref_row, 9_u16)      # Class => TypeRef row 1 (MemberRefParent)
  write_u16(bytes, member_ref_row + 2, 79_u16) # Name => "SampleMemberRef"
  write_u16(bytes, member_ref_row + 4, 26_u16) # blob index for memberref signature

  constant_row = member_ref_row + 6
  bytes[constant_row] = 0x08_u8 # ELEMENT_TYPE_I4
  bytes[constant_row + 1] = 0_u8
  write_u16(bytes, constant_row + 2, 4_u16)  # HasConstant(Field row 1)
  write_u16(bytes, constant_row + 4, 16_u16) # blob index for 42

  constant_row2 = constant_row + 6
  bytes[constant_row2] = 0x08_u8 # ELEMENT_TYPE_I4
  bytes[constant_row2 + 1] = 0_u8
  write_u16(bytes, constant_row2 + 2, 5_u16)  # HasConstant(Param row 1)
  write_u16(bytes, constant_row2 + 4, 21_u16) # blob index for 7

  custom_attr_row = constant_row2 + 6
  write_u16(bytes, custom_attr_row, 35_u16)     # Parent => TypeDef row 1 (HasCustomAttribute)
  write_u16(bytes, custom_attr_row + 2, 11_u16) # Type => MemberRef row 1 (CustomAttributeType)
  write_u16(bytes, custom_attr_row + 4, 33_u16) # Value blob index

  module_ref_row = custom_attr_row + 6
  write_u16(bytes, module_ref_row, 95_u16) # "KERNEL32.DLL"

  type_spec_row = module_ref_row + 2
  write_u16(bytes, type_spec_row, 30_u16) # blob index for class(System.Object) typespec

  impl_map_row = type_spec_row + 2
  write_u16(bytes, impl_map_row, 0_u16)       # mapping flags
  write_u16(bytes, impl_map_row + 2, 3_u16)   # MemberForwarded => MethodDef row 1
  write_u16(bytes, impl_map_row + 4, 108_u16) # ImportName => "CreateFileW"
  write_u16(bytes, impl_map_row + 6, 1_u16)   # ImportScope => ModuleRef row 1

  nested_class_row = impl_map_row + 8
  write_u16(bytes, nested_class_row, 2_u16)     # NestedClass => TypeDef row 2 (<Module>)
  write_u16(bytes, nested_class_row + 2, 1_u16) # EnclosingClass => TypeDef row 1 (SampleType)

  strings_stream = metadata_root + 0x200
  write_string(bytes, strings_stream, "")
  write_string(bytes, strings_stream + 1, "Object")
  write_string(bytes, strings_stream + 8, "System")
  write_string(bytes, strings_stream + 15, "SampleType")
  write_string(bytes, strings_stream + 26, "<Module>")
  write_string(bytes, strings_stream + 35, "SampleField")
  write_string(bytes, strings_stream + 47, "value")
  write_string(bytes, strings_stream + 53, "SampleMethod")
  write_string(bytes, strings_stream + 66, "SecondMethod")
  write_string(bytes, strings_stream + 79, "SampleMemberRef")
  write_string(bytes, strings_stream + 95, "KERNEL32.DLL")
  write_string(bytes, strings_stream + 108, "CreateFileW")

  blob_stream = metadata_root + 0x300
  bytes[blob_stream] = 0_u8
  bytes[blob_stream + 1] = 3_u8
  bytes[blob_stream + 2] = 0_u8     # default call conv
  bytes[blob_stream + 3] = 0_u8     # param count
  bytes[blob_stream + 4] = 1_u8     # ELEMENT_TYPE_VOID
  bytes[blob_stream + 5] = 6_u8     # second signature length
  bytes[blob_stream + 6] = 0_u8     # default call conv
  bytes[blob_stream + 7] = 1_u8     # param count
  bytes[blob_stream + 8] = 0x12_u8  # return class
  bytes[blob_stream + 9] = 0x05_u8  # TypeDefOrRef(TypeRef row 1)
  bytes[blob_stream + 10] = 0x11_u8 # param valuetype
  bytes[blob_stream + 11] = 0x04_u8 # TypeDefOrRef(TypeDef row 1)
  bytes[blob_stream + 12] = 3_u8    # field sig length
  bytes[blob_stream + 13] = 0x06_u8 # field signature prefix
  bytes[blob_stream + 14] = 0x11_u8 # valuetype
  bytes[blob_stream + 15] = 0x04_u8 # TypeDefOrRef(TypeDef row 1)
  bytes[blob_stream + 16] = 4_u8    # constant payload length
  bytes[blob_stream + 17] = 42_u8
  bytes[blob_stream + 18] = 0_u8
  bytes[blob_stream + 19] = 0_u8
  bytes[blob_stream + 20] = 0_u8
  bytes[blob_stream + 21] = 4_u8 # constant payload length
  bytes[blob_stream + 22] = 7_u8
  bytes[blob_stream + 23] = 0_u8
  bytes[blob_stream + 24] = 0_u8
  bytes[blob_stream + 25] = 0_u8
  bytes[blob_stream + 26] = 3_u8    # memberref sig length
  bytes[blob_stream + 27] = 0_u8    # default call conv
  bytes[blob_stream + 28] = 0_u8    # param count
  bytes[blob_stream + 29] = 1_u8    # ELEMENT_TYPE_VOID
  bytes[blob_stream + 30] = 2_u8    # typespec sig length
  bytes[blob_stream + 31] = 0x12_u8 # class
  bytes[blob_stream + 32] = 0x05_u8 # TypeDefOrRef(TypeRef row 1)
  bytes[blob_stream + 33] = 4_u8    # custom attribute payload length
  bytes[blob_stream + 34] = 0x01_u8 # prolog low
  bytes[blob_stream + 35] = 0x00_u8 # prolog high
  bytes[blob_stream + 36] = 0x00_u8 # named args count low
  bytes[blob_stream + 37] = 0x00_u8 # named args count high

  bytes
end

private def write_stream_header(bytes : Bytes, offset : Int32, stream_offset : UInt32, stream_size : UInt32, name : String) : Int32
  write_u32(bytes, offset, stream_offset)
  write_u32(bytes, offset + 4, stream_size)
  write_string(bytes, offset + 8, name)
  cursor = offset + 8 + name.bytesize + 1
  aligned = ((cursor + 3) // 4) * 4
  aligned.to_i
end

private def write_u16(bytes : Bytes, offset : Int32, value : UInt16) : Nil
  bytes[offset] = (value & 0xFF).to_u8
  bytes[offset + 1] = ((value >> 8) & 0xFF).to_u8
end

private def write_u32(bytes : Bytes, offset : Int32, value : UInt32) : Nil
  bytes[offset] = (value & 0xFF).to_u8
  bytes[offset + 1] = ((value >> 8) & 0xFF).to_u8
  bytes[offset + 2] = ((value >> 16) & 0xFF).to_u8
  bytes[offset + 3] = ((value >> 24) & 0xFF).to_u8
end

private def write_u64(bytes : Bytes, offset : Int32, value : UInt64) : Nil
  bytes[offset] = (value & 0xFF).to_u8
  bytes[offset + 1] = ((value >> 8) & 0xFF).to_u8
  bytes[offset + 2] = ((value >> 16) & 0xFF).to_u8
  bytes[offset + 3] = ((value >> 24) & 0xFF).to_u8
  bytes[offset + 4] = ((value >> 32) & 0xFF).to_u8
  bytes[offset + 5] = ((value >> 40) & 0xFF).to_u8
  bytes[offset + 6] = ((value >> 48) & 0xFF).to_u8
  bytes[offset + 7] = ((value >> 56) & 0xFF).to_u8
end

private def write_string(bytes : Bytes, offset : Int32, value : String) : Nil
  value.to_slice.each_with_index do |byte, index|
    bytes[offset + index] = byte
  end
  bytes[offset + value.bytesize] = 0_u8
end
