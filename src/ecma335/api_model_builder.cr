module Ecma335
  class ApiModelBuilder
    TYPE_DEF_TOKEN_PREFIX   = 0x02000000_u32
    FIELD_TOKEN_PREFIX      = 0x04000000_u32
    METHOD_DEF_TOKEN_PREFIX = 0x06000000_u32
    PARAM_TOKEN_PREFIX      = 0x08000000_u32

    def build(tables : TablesStream?) : ApiModel?
      return nil unless tables

      field_constants = Hash(UInt32, String).new
      param_constants = Hash(UInt32, String).new
      tables.constants.each do |constant|
        value = constant.decoded_value
        next unless value
        owner_token = decode_has_constant_owner_token(constant.parent)
        next unless owner_token
        token_prefix = owner_token & 0xFF00_0000_u32
        if token_prefix == FIELD_TOKEN_PREFIX
          field_constants[owner_token] = value
        elsif token_prefix == PARAM_TOKEN_PREFIX
          param_constants[owner_token] = value
        end
      end

      impl_by_method = Hash(UInt32, ImplMapRow).new
      tables.impl_maps.each do |impl|
        next unless impl.target_kind == "method"
        method_token = decode_member_forwarded_method_token(impl.member_forwarded)
        next unless method_token
        impl_by_method[method_token] = impl
      end

      interfaces_by_type = Hash(UInt32, Array(String)).new { |h, k| h[k] = [] of String }
      tables.interface_impls.each do |impl|
        class_index = impl.class_index
        interface_name = impl.interface_name
        next unless interface_name
        next if class_index == 0_u32
        class_token = make_token(TYPE_DEF_TOKEN_PREFIX, class_index.to_i)
        interfaces_by_type[class_token] << interface_name
      end

      attrs_by_type = Hash(UInt32, Array(String)).new { |h, k| h[k] = [] of String }
      attrs_by_field = Hash(UInt32, Array(String)).new { |h, k| h[k] = [] of String }
      attrs_by_method = Hash(UInt32, Array(String)).new { |h, k| h[k] = [] of String }
      attrs_by_param = Hash(UInt32, Array(String)).new { |h, k| h[k] = [] of String }
      tables.custom_attributes.each do |attr|
        parent_token = decode_custom_attribute_parent_token(attr.parent)
        next unless parent_token
        display = if value = attr.decoded_value
                    "#{attr.type_name || "attribute"}=#{value}"
                  else
                    attr.type_name || "attribute"
                  end
        token_prefix = parent_token & 0xFF00_0000_u32
        case token_prefix
        when TYPE_DEF_TOKEN_PREFIX
          attrs_by_type[parent_token] << display
        when FIELD_TOKEN_PREFIX
          attrs_by_field[parent_token] << display
        when METHOD_DEF_TOKEN_PREFIX
          attrs_by_method[parent_token] << display
        when PARAM_TOKEN_PREFIX
          attrs_by_param[parent_token] << display
        end
      end

      type_generic_params = Hash(UInt32, Array(String)).new { |h, k| h[k] = [] of String }
      method_generic_params = Hash(UInt32, Array(String)).new { |h, k| h[k] = [] of String }
      tables.generic_params.each do |gp|
        next if gp.name.empty?
        owner_token = decode_type_or_method_def_token(gp.owner)
        next unless owner_token
        token_prefix = owner_token & 0xFF00_0000_u32
        if token_prefix == TYPE_DEF_TOKEN_PREFIX
          type_generic_params[owner_token] << gp.name
        elsif token_prefix == METHOD_DEF_TOKEN_PREFIX
          method_generic_params[owner_token] << gp.name
        end
      end

      nested_types_by_parent = Hash(UInt32, Array(String)).new { |h, k| h[k] = [] of String }
      enclosing_type_by_nested = Hash(UInt32, String).new
      tables.nested_classes.each do |nested|
        child = nested.nested_name
        parent_name = nested.enclosing_name
        next unless child && parent_name
        next if nested.enclosing_class == 0_u32 || nested.nested_class == 0_u32
        parent_token = make_token(TYPE_DEF_TOKEN_PREFIX, nested.enclosing_class.to_i)
        child_token = make_token(TYPE_DEF_TOKEN_PREFIX, nested.nested_class.to_i)
        nested_types_by_parent[parent_token] << child
        enclosing_type_by_nested[child_token] = parent_name
      end

      class_layout_by_type = Hash(UInt32, ClassLayoutRow).new
      tables.class_layouts.each do |layout|
        next if layout.parent == 0_u32
        type_token = make_token(TYPE_DEF_TOKEN_PREFIX, layout.parent.to_i)
        class_layout_by_type[type_token] = layout
      end

      api_types = [] of ApiType
      tables.type_defs.each_with_index do |type_def, idx|
        full_name = qualify_type_name(type_def.type_namespace, type_def.type_name)
        type_token = make_token(TYPE_DEF_TOKEN_PREFIX, idx + 1)
        next_field_rid = tables.type_defs[idx + 1]?.try(&.field_list).try(&.to_i) || (tables.fields.size + 1)
        next_method_rid = tables.type_defs[idx + 1]?.try(&.method_list).try(&.to_i) || (tables.method_defs.size + 1)

        fields = [] of ApiField
        start_field = type_def.field_list.to_i
        if start_field > 0 && start_field < next_field_rid
          (start_field...(next_field_rid)).each do |rid|
            row = tables.fields[rid - 1]?
            next unless row
            field_token = make_token(FIELD_TOKEN_PREFIX, rid)
            fields << ApiField.new(
              row.name,
              row.decoded_signature,
              field_constants[field_token]?,
              row.flags,
              attrs_by_field[field_token]? || [] of String,
              field_token
            )
          end
        end

        methods = [] of ApiMethod
        start_method = type_def.method_list.to_i
        if start_method > 0 && start_method < next_method_rid
          (start_method...(next_method_rid)).each do |rid|
            method = tables.method_defs[rid - 1]?
            next unless method
            next_param_rid = tables.method_defs[rid]?.try(&.param_list).try(&.to_i) || (tables.params.size + 1)
            params = [] of ApiParam
            start_param = method.param_list.to_i
            if start_param > 0 && start_param < next_param_rid
              (start_param...(next_param_rid)).each do |prid|
                param = tables.params[prid - 1]?
                next unless param
                next if param.sequence == 0_u16
                param_token = make_token(PARAM_TOKEN_PREFIX, prid)
                params << ApiParam.new(
                  param.name,
                  param.sequence,
                  param.signature_type,
                  param_constants[param_token]?,
                  param.flags,
                  attrs_by_param[param_token]? || [] of String,
                  param_token
                )
              end
            end

            method_token = make_token(METHOD_DEF_TOKEN_PREFIX, rid)
            impl = impl_by_method[method_token]?
            method_generics = method_generic_params[method_token]? || [] of String
            type_generics = type_generic_params[type_token]? || [] of String
            signature = apply_generic_context(method.decoded_signature, type_generics, method_generics)
            methods << ApiMethod.new(
              method.name,
              signature,
              params,
              impl.try(&.import_name),
              impl.try(&.scope_name),
              method_generics,
              method.rva,
              method.impl_flags,
              method.flags,
              attrs_by_method[method_token]? || [] of String,
              method_token
            )
          end
        end

        layout = class_layout_by_type[type_token]?

        api_types << ApiType.new(
          full_name,
          type_def.type_namespace,
          type_def.type_name,
          fields,
          methods,
          interfaces_by_type[type_token]? || [] of String,
          attrs_by_type[type_token]? || [] of String,
          nested_types_by_parent[type_token]? || [] of String,
          enclosing_type_by_nested[type_token]?,
          type_generic_params[type_token]? || [] of String,
          type_def.flags,
          type_def.extends,
          resolve_type_def_or_ref(type_def.extends, tables),
          layout.try(&.class_size),
          layout.try(&.packing_size),
          type_token
        )
      end

      ApiModel.new(api_types)
    end

    private def qualify_type_name(namespace_name : String, type_name : String) : String
      return type_name if namespace_name.empty?
      "#{namespace_name}.#{type_name}"
    end

    private def make_token(prefix : UInt32, rid : Int32) : UInt32
      prefix | rid.to_u32
    end

    private def decode_has_constant_owner_token(coded_parent : UInt32) : UInt32?
      tag = coded_parent & 0x3_u32
      row_index = (coded_parent >> 2).to_i
      return nil if row_index <= 0

      case tag
      when 0_u32
        make_token(FIELD_TOKEN_PREFIX, row_index)
      when 1_u32
        make_token(PARAM_TOKEN_PREFIX, row_index)
      else
        nil
      end
    end

    private def decode_member_forwarded_method_token(coded_index : UInt32) : UInt32?
      tag = coded_index & 0x1_u32
      row_index = (coded_index >> 1).to_i
      return nil if row_index <= 0
      return nil unless tag == 1_u32
      make_token(METHOD_DEF_TOKEN_PREFIX, row_index)
    end

    private def decode_custom_attribute_parent_token(coded_parent : UInt32) : UInt32?
      tag = coded_parent & 0x1F_u32
      row_index = (coded_parent >> 5).to_i
      return nil if row_index <= 0

      case tag
      when 0_u32
        make_token(METHOD_DEF_TOKEN_PREFIX, row_index)
      when 1_u32
        make_token(FIELD_TOKEN_PREFIX, row_index)
      when 3_u32
        make_token(TYPE_DEF_TOKEN_PREFIX, row_index)
      when 4_u32
        make_token(PARAM_TOKEN_PREFIX, row_index)
      else
        nil
      end
    end

    private def decode_type_or_method_def_token(coded_owner : UInt32) : UInt32?
      tag = coded_owner & 0x1_u32
      row_index = (coded_owner >> 1).to_i
      return nil if row_index <= 0

      case tag
      when 0_u32
        make_token(TYPE_DEF_TOKEN_PREFIX, row_index)
      when 1_u32
        make_token(METHOD_DEF_TOKEN_PREFIX, row_index)
      else
        nil
      end
    end

    private def resolve_type_def_or_ref(coded_index : UInt32, tables : TablesStream) : String?
      return nil if coded_index == 0_u32

      tag = coded_index & 0x3_u32
      row_index = (coded_index >> 2).to_i
      return nil if row_index <= 0

      case tag
      when 0_u32
        type = tables.type_defs[row_index - 1]?
        type ? qualify_type_name(type.type_namespace, type.type_name) : nil
      when 1_u32
        type = tables.type_refs[row_index - 1]?
        type ? qualify_type_name(type.type_namespace, type.type_name) : nil
      when 2_u32
        type_spec = tables.type_specs[row_index - 1]?
        type_spec.try(&.decoded_type) || "<typespec:#{row_index}>"
      else
        nil
      end
    end

    private def apply_generic_context(signature : MethodSignature?, type_generics : Array(String), method_generics : Array(String)) : MethodSignature?
      return nil unless signature
      return signature if type_generics.empty? && method_generics.empty?

      resolved_return_type = apply_generic_context_to_type(signature.return_type, type_generics, method_generics)
      resolved_params = signature.parameter_types.map do |param|
        apply_generic_context_to_type(param, type_generics, method_generics)
      end

      MethodSignature.new(
        signature.has_this,
        signature.explicit_this,
        signature.generic_parameter_count,
        signature.parameter_count,
        resolved_return_type,
        resolved_params
      )
    end

    private def apply_generic_context_to_type(type_name : String, type_generics : Array(String), method_generics : Array(String)) : String
      value = type_name
      type_generics.each_with_index do |name, idx|
        value = value.gsub("var(#{idx})", name)
      end
      method_generics.each_with_index do |name, idx|
        value = value.gsub("mvar(#{idx})", name)
      end
      value
    end
  end
end
