module Ecma335
  class ApiModelBuilder
    TYPE_DEF_TOKEN_PREFIX   = 0x02000000_u32
    FIELD_TOKEN_PREFIX      = 0x04000000_u32
    METHOD_DEF_TOKEN_PREFIX = 0x06000000_u32
    PARAM_TOKEN_PREFIX      = 0x08000000_u32

    def build(tables : TablesStream?) : ApiModel?
      return nil unless tables

      field_constants = Hash(String, String).new
      param_constants = Hash(String, String).new
      tables.constants.each do |constant|
        value = constant.decoded_value
        next unless value
        case constant.owner_kind
        when "field"
          owner = constant.owner_name || ""
          field_constants[owner] = value
        when "param"
          owner = constant.owner_name || ""
          param_constants[owner] = value
        end
      end

      impl_by_method = Hash(String, ImplMapRow).new
      tables.impl_maps.each do |impl|
        next unless impl.target_kind == "method"
        target = impl.target_name || ""
        impl_by_method[target] = impl
      end

      interfaces_by_type = Hash(String, Array(String)).new { |h, k| h[k] = [] of String }
      tables.interface_impls.each do |impl|
        class_name = impl.class_name
        interface_name = impl.interface_name
        next unless class_name && interface_name
        interfaces_by_type[class_name] << interface_name
      end

      attrs_by_type = Hash(String, Array(String)).new { |h, k| h[k] = [] of String }
      tables.custom_attributes.each do |attr|
        next unless attr.parent_kind == "typedef"
        type_name = attr.parent_name
        next unless type_name
        display = if value = attr.decoded_value
                    "#{attr.type_name || "attribute"}=#{value}"
                  else
                    attr.type_name || "attribute"
                  end
        attrs_by_type[type_name] << display
      end

      type_generic_params = Hash(String, Array(String)).new { |h, k| h[k] = [] of String }
      method_generic_params = Hash(String, Array(String)).new { |h, k| h[k] = [] of String }
      tables.generic_params.each do |gp|
        next if gp.name.empty?
        case gp.owner_kind
        when "typedef"
          owner_name = gp.owner_name
          next unless owner_name
          type_generic_params[owner_name] << gp.name
        when "methoddef"
          owner_name = gp.owner_name
          next unless owner_name
          method_generic_params[owner_name] << gp.name
        end
      end

      nested_types_by_parent = Hash(String, Array(String)).new { |h, k| h[k] = [] of String }
      enclosing_type_by_nested = Hash(String, String).new
      tables.nested_classes.each do |nested|
        child = nested.nested_name
        parent = nested.enclosing_name
        next unless child && parent
        nested_types_by_parent[parent] << child
        enclosing_type_by_nested[child] = parent
      end

      api_types = [] of ApiType
      tables.type_defs.each_with_index do |type_def, idx|
        full_name = qualify_type_name(type_def.type_namespace, type_def.type_name)
        next_field_rid = tables.type_defs[idx + 1]?.try(&.field_list).try(&.to_i) || (tables.fields.size + 1)
        next_method_rid = tables.type_defs[idx + 1]?.try(&.method_list).try(&.to_i) || (tables.method_defs.size + 1)

        fields = [] of ApiField
        start_field = type_def.field_list.to_i
        if start_field > 0 && start_field < next_field_rid
          (start_field...(next_field_rid)).each do |rid|
            row = tables.fields[rid - 1]?
            next unless row
            fields << ApiField.new(row.name, row.decoded_signature, field_constants[row.name]?, make_token(FIELD_TOKEN_PREFIX, rid))
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
                params << ApiParam.new(param.name, param.sequence, param.signature_type, param_constants[param.name]?, make_token(PARAM_TOKEN_PREFIX, prid))
              end
            end

            impl = impl_by_method[method.name]?
            method_generics = method_generic_params[method.name]? || [] of String
            type_generics = type_generic_params[full_name]? || [] of String
            signature = apply_generic_context(method.decoded_signature, type_generics, method_generics)
            methods << ApiMethod.new(
              method.name,
              signature,
              params,
              impl.try(&.import_name),
              impl.try(&.scope_name),
              method_generics,
              make_token(METHOD_DEF_TOKEN_PREFIX, rid)
            )
          end
        end

        api_types << ApiType.new(
          full_name,
          type_def.type_namespace,
          type_def.type_name,
          fields,
          methods,
          interfaces_by_type[full_name]? || [] of String,
          attrs_by_type[full_name]? || [] of String,
          nested_types_by_parent[full_name]? || [] of String,
          enclosing_type_by_nested[full_name]?,
          type_generic_params[full_name]? || [] of String,
          make_token(TYPE_DEF_TOKEN_PREFIX, idx + 1)
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
