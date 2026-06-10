module Ecma335
  struct SectionHeader
    getter name : String
    getter virtual_size : UInt32
    getter virtual_address : UInt32
    getter size_of_raw_data : UInt32
    getter pointer_to_raw_data : UInt32

    def initialize(@name : String, @virtual_size : UInt32, @virtual_address : UInt32, @size_of_raw_data : UInt32, @pointer_to_raw_data : UInt32)
    end

    def contains_rva?(rva : UInt32) : Bool
      span = {@virtual_size, @size_of_raw_data}.max
      span = 1_u32 if span == 0_u32
      rva >= @virtual_address && rva < @virtual_address + span
    end
  end

  struct StreamHeader
    getter name : String
    getter offset : UInt32
    getter size : UInt32

    def initialize(@name : String, @offset : UInt32, @size : UInt32)
    end
  end

  struct MetadataRoot
    getter signature : UInt32
    getter major_version : UInt16
    getter minor_version : UInt16
    getter version_string : String
    getter streams : Array(StreamHeader)
    getter tables_stream : TablesStream?

    def initialize(@signature : UInt32, @major_version : UInt16, @minor_version : UInt16, @version_string : String, @streams : Array(StreamHeader), @tables_stream : TablesStream? = nil)
    end

    def stream_names : Array(String)
      @streams.map(&.name)
    end

    def has_stream?(name : String) : Bool
      @streams.any? { |stream| stream.name == name }
    end

    def stream?(name : String) : StreamHeader?
      @streams.find { |stream| stream.name == name }
    end
  end

  struct TablesStream
    TYPE_DEF_TOKEN_PREFIX   = 0x02_u32
    FIELD_TOKEN_PREFIX      = 0x04_u32
    METHOD_DEF_TOKEN_PREFIX = 0x06_u32

    getter major_version : UInt8
    getter minor_version : UInt8
    getter heap_sizes : UInt8
    getter valid_mask : UInt64
    getter sorted_mask : UInt64
    getter row_counts : Hash(String, UInt32)
    getter modules : Array(ModuleRow)
    getter type_refs : Array(TypeRefRow)
    getter type_defs : Array(TypeDefRow)
    getter fields : Array(FieldRow)
    getter method_defs : Array(MethodDefRow)
    getter params : Array(ParamRow)
    getter constants : Array(ConstantRow)
    getter interface_impls : Array(InterfaceImplRow)
    getter member_refs : Array(MemberRefRow)
    getter event_maps : Array(EventMapRow)
    getter events : Array(EventRow)
    getter property_maps : Array(PropertyMapRow)
    getter properties : Array(PropertyRow)
    getter method_semantics : Array(MethodSemanticsRow)
    getter method_impls : Array(MethodImplRow)
    getter assemblies : Array(AssemblyRow)
    getter assembly_refs : Array(AssemblyRefRow)
    getter class_layouts : Array(ClassLayoutRow)
    getter field_layouts : Array(FieldLayoutRow)
    getter files : Array(FileRow)
    getter exported_types : Array(ExportedTypeRow)
    getter manifest_resources : Array(ManifestResourceRow)
    getter generic_params : Array(GenericParamRow)
    getter method_specs : Array(MethodSpecRow)
    getter generic_param_constraints : Array(GenericParamConstraintRow)
    getter type_specs : Array(TypeSpecRow)
    getter module_refs : Array(ModuleRefRow)
    getter impl_maps : Array(ImplMapRow)
    getter custom_attributes : Array(CustomAttributeRow)
    getter nested_classes : Array(NestedClassRow)
    getter parsed_row_counts : Hash(String, UInt32)
    getter skipped_row_counts : Hash(String, UInt32)

    def initialize(
      @major_version : UInt8,
      @minor_version : UInt8,
      @heap_sizes : UInt8,
      @valid_mask : UInt64,
      @sorted_mask : UInt64,
      @row_counts : Hash(String, UInt32),
      @modules : Array(ModuleRow) = [] of ModuleRow,
      @type_refs : Array(TypeRefRow) = [] of TypeRefRow,
      @type_defs : Array(TypeDefRow) = [] of TypeDefRow,
      @fields : Array(FieldRow) = [] of FieldRow,
      @method_defs : Array(MethodDefRow) = [] of MethodDefRow,
      @params : Array(ParamRow) = [] of ParamRow,
      @constants : Array(ConstantRow) = [] of ConstantRow,
      @interface_impls : Array(InterfaceImplRow) = [] of InterfaceImplRow,
      @member_refs : Array(MemberRefRow) = [] of MemberRefRow,
      @event_maps : Array(EventMapRow) = [] of EventMapRow,
      @events : Array(EventRow) = [] of EventRow,
      @property_maps : Array(PropertyMapRow) = [] of PropertyMapRow,
      @properties : Array(PropertyRow) = [] of PropertyRow,
      @method_semantics : Array(MethodSemanticsRow) = [] of MethodSemanticsRow,
      @method_impls : Array(MethodImplRow) = [] of MethodImplRow,
      @assemblies : Array(AssemblyRow) = [] of AssemblyRow,
      @assembly_refs : Array(AssemblyRefRow) = [] of AssemblyRefRow,
      @class_layouts : Array(ClassLayoutRow) = [] of ClassLayoutRow,
      @field_layouts : Array(FieldLayoutRow) = [] of FieldLayoutRow,
      @files : Array(FileRow) = [] of FileRow,
      @exported_types : Array(ExportedTypeRow) = [] of ExportedTypeRow,
      @manifest_resources : Array(ManifestResourceRow) = [] of ManifestResourceRow,
      @generic_params : Array(GenericParamRow) = [] of GenericParamRow,
      @method_specs : Array(MethodSpecRow) = [] of MethodSpecRow,
      @generic_param_constraints : Array(GenericParamConstraintRow) = [] of GenericParamConstraintRow,
      @type_specs : Array(TypeSpecRow) = [] of TypeSpecRow,
      @module_refs : Array(ModuleRefRow) = [] of ModuleRefRow,
      @impl_maps : Array(ImplMapRow) = [] of ImplMapRow,
      @custom_attributes : Array(CustomAttributeRow) = [] of CustomAttributeRow,
      @nested_classes : Array(NestedClassRow) = [] of NestedClassRow,
      @parsed_row_counts : Hash(String, UInt32) = Hash(String, UInt32).new,
      @skipped_row_counts : Hash(String, UInt32) = Hash(String, UInt32).new,
    )
    end

    def row_count(table_name : String) : UInt32
      @row_counts[table_name]? || 0_u32
    end

    def parsed_tables : Array(String)
      @parsed_row_counts.keys.sort
    end

    def skipped_tables : Array(String)
      @skipped_row_counts.keys.sort
    end

    def parse_coverage_ratio : Float64
      parsed = @parsed_row_counts.values.sum(&.to_i64).to_f64
      skipped = @skipped_row_counts.values.sum(&.to_i64).to_f64
      total = parsed + skipped
      return 1.0 if total == 0.0
      parsed / total
    end

    def type_def_by_rid?(rid : UInt32) : TypeDefRow?
      return nil if rid == 0_u32
      @type_defs[rid.to_i - 1]?
    end

    def method_def_by_rid?(rid : UInt32) : MethodDefRow?
      return nil if rid == 0_u32
      @method_defs[rid.to_i - 1]?
    end

    def field_by_rid?(rid : UInt32) : FieldRow?
      return nil if rid == 0_u32
      @fields[rid.to_i - 1]?
    end

    def type_def_by_token?(token : UInt32) : TypeDefRow?
      return nil unless token_table_prefix(token) == TYPE_DEF_TOKEN_PREFIX
      type_def_by_rid?(token_rid(token))
    end

    def method_def_by_token?(token : UInt32) : MethodDefRow?
      return nil unless token_table_prefix(token) == METHOD_DEF_TOKEN_PREFIX
      method_def_by_rid?(token_rid(token))
    end

    def field_by_token?(token : UInt32) : FieldRow?
      return nil unless token_table_prefix(token) == FIELD_TOKEN_PREFIX
      field_by_rid?(token_rid(token))
    end

    private def token_table_prefix(token : UInt32) : UInt32
      (token >> 24) & 0xFF_u32
    end

    private def token_rid(token : UInt32) : UInt32
      token & 0x00FF_FFFF_u32
    end
  end

  struct ModuleRow
    getter generation : UInt16
    getter name : String
    getter mvid : UInt32
    getter enc_id : UInt32
    getter enc_base_id : UInt32

    def initialize(@generation : UInt16, @name : String, @mvid : UInt32, @enc_id : UInt32, @enc_base_id : UInt32)
    end
  end

  struct TypeRefRow
    getter resolution_scope : UInt32
    getter type_name : String
    getter type_namespace : String

    def initialize(@resolution_scope : UInt32, @type_name : String, @type_namespace : String)
    end
  end

  struct TypeDefRow
    getter flags : UInt32
    getter type_name : String
    getter type_namespace : String
    getter extends : UInt32
    getter field_list : UInt32
    getter method_list : UInt32

    def initialize(@flags : UInt32, @type_name : String, @type_namespace : String, @extends : UInt32, @field_list : UInt32, @method_list : UInt32)
    end
  end

  struct MethodDefRow
    getter rva : UInt32
    getter impl_flags : UInt16
    getter flags : UInt16
    getter name : String
    getter signature : UInt32
    getter param_list : UInt32
    getter decoded_signature : MethodSignature?

    def initialize(@rva : UInt32, @impl_flags : UInt16, @flags : UInt16, @name : String, @signature : UInt32, @param_list : UInt32, @decoded_signature : MethodSignature? = nil)
    end
  end

  struct FieldRow
    getter flags : UInt16
    getter name : String
    getter signature : UInt32
    getter decoded_signature : String?

    def initialize(@flags : UInt16, @name : String, @signature : UInt32, @decoded_signature : String? = nil)
    end
  end

  struct ParamRow
    getter flags : UInt16
    getter sequence : UInt16
    getter name : String
    getter signature_type : String?

    def initialize(@flags : UInt16, @sequence : UInt16, @name : String, @signature_type : String? = nil)
    end
  end

  struct ConstantRow
    getter value_type : UInt8
    getter parent : UInt32
    getter value_blob_index : UInt32
    getter decoded_value : String?
    getter owner_kind : String
    getter owner_name : String?

    def initialize(
      @value_type : UInt8,
      @parent : UInt32,
      @value_blob_index : UInt32,
      @decoded_value : String? = nil,
      @owner_kind : String = "unknown",
      @owner_name : String? = nil,
    )
    end
  end

  struct InterfaceImplRow
    getter class_index : UInt32
    getter interface_token : UInt32
    getter class_name : String?
    getter interface_name : String?

    def initialize(@class_index : UInt32, @interface_token : UInt32, @class_name : String? = nil, @interface_name : String? = nil)
    end
  end

  struct MemberRefRow
    getter class_token : UInt32
    getter name : String
    getter signature : UInt32
    getter parent_kind : String
    getter parent_name : String?
    getter decoded_signature : String?

    def initialize(@class_token : UInt32, @name : String, @signature : UInt32, @parent_kind : String = "unknown", @parent_name : String? = nil, @decoded_signature : String? = nil)
    end
  end

  struct EventMapRow
    getter parent : UInt32
    getter event_list : UInt32
    getter parent_name : String?

    def initialize(@parent : UInt32, @event_list : UInt32, @parent_name : String? = nil)
    end
  end

  struct EventRow
    getter flags : UInt16
    getter name : String
    getter event_type : UInt32
    getter event_type_name : String?

    def initialize(@flags : UInt16, @name : String, @event_type : UInt32, @event_type_name : String? = nil)
    end
  end

  struct PropertyMapRow
    getter parent : UInt32
    getter property_list : UInt32
    getter parent_name : String?

    def initialize(@parent : UInt32, @property_list : UInt32, @parent_name : String? = nil)
    end
  end

  struct PropertyRow
    getter flags : UInt16
    getter name : String
    getter type : UInt32
    getter decoded_signature : String?

    def initialize(@flags : UInt16, @name : String, @type : UInt32, @decoded_signature : String? = nil)
    end
  end

  struct MethodSemanticsRow
    getter semantics : UInt16
    getter method : UInt32
    getter association : UInt32
    getter method_name : String?
    getter association_kind : String
    getter association_name : String?

    def initialize(
      @semantics : UInt16,
      @method : UInt32,
      @association : UInt32,
      @method_name : String? = nil,
      @association_kind : String = "unknown",
      @association_name : String? = nil,
    )
    end
  end

  struct MethodImplRow
    getter class : UInt32
    getter method_body : UInt32
    getter method_declaration : UInt32
    getter class_name : String?
    getter method_body_kind : String
    getter method_body_name : String?
    getter method_declaration_kind : String
    getter method_declaration_name : String?

    def initialize(
      @class : UInt32,
      @method_body : UInt32,
      @method_declaration : UInt32,
      @class_name : String? = nil,
      @method_body_kind : String = "unknown",
      @method_body_name : String? = nil,
      @method_declaration_kind : String = "unknown",
      @method_declaration_name : String? = nil,
    )
    end
  end

  struct AssemblyRow
    getter hash_alg_id : UInt32
    getter major_version : UInt16
    getter minor_version : UInt16
    getter build_number : UInt16
    getter revision_number : UInt16
    getter flags : UInt32
    getter public_key : UInt32
    getter name : String
    getter culture : String

    def initialize(
      @hash_alg_id : UInt32,
      @major_version : UInt16,
      @minor_version : UInt16,
      @build_number : UInt16,
      @revision_number : UInt16,
      @flags : UInt32,
      @public_key : UInt32,
      @name : String,
      @culture : String,
    )
    end
  end

  struct AssemblyRefRow
    getter major_version : UInt16
    getter minor_version : UInt16
    getter build_number : UInt16
    getter revision_number : UInt16
    getter flags : UInt32
    getter public_key_or_token : UInt32
    getter name : String
    getter culture : String
    getter hash_value : UInt32

    def initialize(
      @major_version : UInt16,
      @minor_version : UInt16,
      @build_number : UInt16,
      @revision_number : UInt16,
      @flags : UInt32,
      @public_key_or_token : UInt32,
      @name : String,
      @culture : String,
      @hash_value : UInt32,
    )
    end
  end

  struct ClassLayoutRow
    getter packing_size : UInt16
    getter class_size : UInt32
    getter parent : UInt32
    getter parent_name : String?

    def initialize(@packing_size : UInt16, @class_size : UInt32, @parent : UInt32, @parent_name : String? = nil)
    end
  end

  struct FieldLayoutRow
    getter offset : UInt32
    getter field : UInt32
    getter field_name : String?

    def initialize(@offset : UInt32, @field : UInt32, @field_name : String? = nil)
    end
  end

  struct FileRow
    getter flags : UInt32
    getter name : String
    getter hash_value : UInt32

    def initialize(@flags : UInt32, @name : String, @hash_value : UInt32)
    end
  end

  struct ExportedTypeRow
    getter flags : UInt32
    getter type_def_id : UInt32
    getter type_name : String
    getter type_namespace : String
    getter implementation : UInt32
    getter implementation_kind : String
    getter implementation_name : String?

    def initialize(
      @flags : UInt32,
      @type_def_id : UInt32,
      @type_name : String,
      @type_namespace : String,
      @implementation : UInt32,
      @implementation_kind : String = "unknown",
      @implementation_name : String? = nil,
    )
    end
  end

  struct ManifestResourceRow
    getter offset : UInt32
    getter flags : UInt32
    getter name : String
    getter implementation : UInt32
    getter implementation_kind : String
    getter implementation_name : String?

    def initialize(
      @offset : UInt32,
      @flags : UInt32,
      @name : String,
      @implementation : UInt32,
      @implementation_kind : String = "unknown",
      @implementation_name : String? = nil,
    )
    end
  end

  struct GenericParamRow
    getter number : UInt16
    getter flags : UInt16
    getter owner : UInt32
    getter name : String
    getter owner_kind : String
    getter owner_name : String?

    def initialize(
      @number : UInt16,
      @flags : UInt16,
      @owner : UInt32,
      @name : String,
      @owner_kind : String = "unknown",
      @owner_name : String? = nil,
    )
    end
  end

  struct MethodSpecRow
    getter method : UInt32
    getter instantiation : UInt32
    getter method_kind : String
    getter method_name : String?
    getter decoded_instantiation : String?

    def initialize(
      @method : UInt32,
      @instantiation : UInt32,
      @method_kind : String = "unknown",
      @method_name : String? = nil,
      @decoded_instantiation : String? = nil,
    )
    end
  end

  struct GenericParamConstraintRow
    getter owner : UInt32
    getter constraint : UInt32
    getter owner_name : String?
    getter constraint_name : String?

    def initialize(@owner : UInt32, @constraint : UInt32, @owner_name : String? = nil, @constraint_name : String? = nil)
    end
  end

  struct TypeSpecRow
    getter signature : UInt32
    getter decoded_type : String?

    def initialize(@signature : UInt32, @decoded_type : String? = nil)
    end
  end

  struct NestedClassRow
    getter nested_class : UInt32
    getter enclosing_class : UInt32
    getter nested_name : String?
    getter enclosing_name : String?

    def initialize(@nested_class : UInt32, @enclosing_class : UInt32, @nested_name : String? = nil, @enclosing_name : String? = nil)
    end
  end

  struct ModuleRefRow
    getter name : String

    def initialize(@name : String)
    end
  end

  struct ImplMapRow
    getter mapping_flags : UInt16
    getter member_forwarded : UInt32
    getter import_name : String
    getter import_scope : UInt32
    getter scope_name : String?
    getter target_kind : String
    getter target_name : String?

    def initialize(
      @mapping_flags : UInt16,
      @member_forwarded : UInt32,
      @import_name : String,
      @import_scope : UInt32,
      @scope_name : String? = nil,
      @target_kind : String = "unknown",
      @target_name : String? = nil,
    )
    end
  end

  struct CustomAttributeRow
    getter parent : UInt32
    getter attribute_type : UInt32
    getter value : UInt32
    getter parent_kind : String
    getter parent_name : String?
    getter type_name : String?
    getter decoded_value : String?

    def initialize(
      @parent : UInt32,
      @attribute_type : UInt32,
      @value : UInt32,
      @parent_kind : String = "unknown",
      @parent_name : String? = nil,
      @type_name : String? = nil,
      @decoded_value : String? = nil,
    )
    end
  end

  struct MethodSignature
    getter has_this : Bool
    getter explicit_this : Bool
    getter generic_parameter_count : UInt32?
    getter parameter_count : UInt32
    getter return_type : String
    getter parameter_types : Array(String)

    def initialize(@has_this : Bool, @explicit_this : Bool, @generic_parameter_count : UInt32?, @parameter_count : UInt32, @return_type : String, @parameter_types : Array(String))
    end

    def canonical_return_type : String
      SignatureCanonicalizer.new.canonicalize(@return_type)
    end

    def canonical_parameter_types : Array(String)
      @parameter_types.map { |param| SignatureCanonicalizer.new.canonicalize(param) }
    end

    def to_signature_string(canonical : Bool = false) : String
      if canonical
        "(#{canonical_parameter_types.join(", ")}) -> #{canonical_return_type}"
      else
        "(#{@parameter_types.join(", ")}) -> #{@return_type}"
      end
    end
  end

  struct ParsedAssembly
    getter cli_header_rva : UInt32
    getter metadata_rva : UInt32
    getter metadata_root : MetadataRoot
    getter api_model : ApiModel?

    def initialize(@cli_header_rva : UInt32, @metadata_rva : UInt32, @metadata_root : MetadataRoot, @api_model : ApiModel? = nil)
    end

    def type?(full_name : String) : ApiType?
      @api_model.try(&.type?(full_name))
    end

    def type_def_by_token?(token : UInt32) : TypeDefRow?
      @metadata_root.tables_stream.try(&.type_def_by_token?(token))
    end

    def method_def_by_token?(token : UInt32) : MethodDefRow?
      @metadata_root.tables_stream.try(&.method_def_by_token?(token))
    end

    def field_by_token?(token : UInt32) : FieldRow?
      @metadata_root.tables_stream.try(&.field_by_token?(token))
    end
  end

  struct ApiField
    getter name : String
    getter signature : String?
    getter constant_value : String?
    getter token : UInt32?

    def initialize(@name : String, @signature : String? = nil, @constant_value : String? = nil, @token : UInt32? = nil)
    end
  end

  struct ApiParam
    getter name : String
    getter sequence : UInt16
    getter signature_type : String?
    getter constant_value : String?
    getter token : UInt32?

    def initialize(@name : String, @sequence : UInt16, @signature_type : String? = nil, @constant_value : String? = nil, @token : UInt32? = nil)
    end
  end

  struct ApiMethod
    getter name : String
    getter signature : MethodSignature?
    getter params : Array(ApiParam)
    getter native_import : String?
    getter native_module : String?
    getter generic_params : Array(String)
    getter token : UInt32?

    def initialize(
      @name : String,
      @signature : MethodSignature? = nil,
      @params : Array(ApiParam) = [] of ApiParam,
      @native_import : String? = nil,
      @native_module : String? = nil,
      @generic_params : Array(String) = [] of String,
      @token : UInt32? = nil,
    )
    end
  end

  struct ApiType
    getter full_name : String
    getter namespace_name : String
    getter name : String
    getter fields : Array(ApiField)
    getter methods : Array(ApiMethod)
    getter interfaces : Array(String)
    getter custom_attributes : Array(String)
    getter nested_types : Array(String)
    getter enclosing_type : String?
    getter generic_params : Array(String)
    getter token : UInt32?

    def initialize(
      @full_name : String,
      @namespace_name : String,
      @name : String,
      @fields : Array(ApiField),
      @methods : Array(ApiMethod),
      @interfaces : Array(String),
      @custom_attributes : Array(String),
      @nested_types : Array(String) = [] of String,
      @enclosing_type : String? = nil,
      @generic_params : Array(String) = [] of String,
      @token : UInt32? = nil,
    )
    end
  end

  struct ApiModel
    getter types : Array(ApiType)

    def initialize(@types : Array(ApiType))
      @by_full_name = Hash(String, ApiType).new
      @by_namespace = Hash(String, Array(ApiType)).new { |hash, key| hash[key] = [] of ApiType }
      @types.each do |type|
        @by_full_name[type.full_name] = type
        @by_namespace[type.namespace_name] << type
      end
    end

    def type?(full_name : String) : ApiType?
      @by_full_name[full_name]?
    end

    def types_in_namespace(namespace_name : String) : Array(ApiType)
      @by_namespace[namespace_name]? || [] of ApiType
    end

    def method?(type_full_name : String, method_name : String) : ApiMethod?
      type = @by_full_name[type_full_name]?
      return nil unless type
      type.methods.find { |method| method.name == method_name }
    end

    def find_methods(method_name : String) : Array(ApiMethod)
      matches = [] of ApiMethod
      @types.each do |type|
        type.methods.each do |method|
          matches << method if method.name == method_name
        end
      end
      matches
    end
  end
end
