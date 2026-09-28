# ECMA-335 Parser Status

## Purpose

This library is parser-focused. It is intended to parse ECMA-335 metadata (including WinMD files) so a separate application can generate Crystal bindings without depending on `win32json`.

## Current State

The parser is now beyond initial stream parsing and includes table decoding plus a normalized API model.

### Implemented

- PE/CLI metadata loading pipeline
  - DOS header -> PE headers -> CLI header -> metadata root
  - stream headers: `#~`, `#Strings`, `#Blob`, `#GUID`, `#US`

- `#~` tables stream header
  - heap-size flags
  - valid/sorted masks
  - row counts

- Table rows currently parsed
  - `TypeRef`
  - `TypeDef`
  - `Field`
  - `MethodDef`
  - `Param`
  - `Constant`
  - `InterfaceImpl`
  - `MemberRef`
  - `EventMap`
  - `Event`
  - `PropertyMap`
  - `Property`
  - `MethodSemantics`
  - `MethodImpl`
  - `AssemblyRef`
  - `File`
  - `ExportedType`
  - `ManifestResource`
  - `GenericParam`
  - `MethodSpec`
  - `GenericParamConstraint`
  - `TypeSpec`
  - `ModuleRef`
  - `ImplMap`
  - `CustomAttribute`
  - `NestedClass`
  - `ClassLayout` (packing size, class size)
  - `FieldLayout` (explicit field offsets)

- Signature decoding (current coverage)
  - method signatures (`MethodDef`, `MemberRef` method-like)
  - field signatures
  - type signatures with support for:
    - primitive types
    - class/valuetype (TypeDefOrRef resolution)
    - byref
    - pointer
    - single- and multi-dimensional arrays
    - generic instantiations
    - function pointers (`fnptr`)
    - custom modifiers (`cmod_reqd`, `cmod_opt`)
  - vararg sentinel marker handling in method signatures
  - canonical signature rendering helpers via `MethodSignature#to_signature_string(canonical: true)`

- Constant decoding
  - bool/char/int/uint widths, float32/float64
  - UTF-16 string constants
  - owner resolution for `field` and `param` (kind, name and RID)
  - `ConstantRow#type_name` exposes the element type

- Native mapping support
  - `ModuleRef` names
  - `ImplMap` import name/scope and forwarded member resolution

- Custom attributes (expanded support)
  - rows parsed and linked to parent/type/value
  - structured decoding (`CustomAttributeDecoder#decode_args`): fixed
    constructor arguments driven by the constructor signature (primitives,
    strings, enums, `System.Type`, boxed objects, arrays) plus FIELD/PROPERTY
    named arguments; exposed as `CustomAttributeRow#fixed_args` / `#named_args`
  - attribute type names resolve for constructors defined in the same module
    (MethodDef) as well as MemberRef constructors
  - typed payload handling for several fixed-arg patterns (string/bool/u16/u32/no-args)
  - specific helper for `GuidAttribute`-style decode
  - WinMD-focused schema decoders for:
    - `ContractVersionAttribute`
    - `SupportedArchitectureAttribute`
    - `VersionAttribute`
    - `ThreadingAttribute`
    - `MarshalingBehaviorAttribute`
    - `DeprecatedAttribute`

- Normalized consumer model
  - `ApiModel`, `ApiType`, `ApiMethod`, `ApiField`, `ApiParam`, `ApiAttribute`
  - built from parsed tables; every cross-table link (constants, ImplMap,
    custom attributes, generic params, nested classes, layout) is keyed by RID,
    never by name
  - type classification from metadata: `ApiType#flags`, `#extends` (coded index), `#base_type`, and the
    predicates `enum?`, `delegate?`, `interface?`, `value_type?`, `struct?`,
    `union?` (explicit layout), `static_class?`, `attribute_type?`
  - layout: `ApiType#packing_size`, `#class_size`, `ApiField#offset`
  - custom attributes on types, fields, methods and params
    (`custom_attributes`, `attribute?`, `attributes`, `has_attribute?`)
  - flags: `ApiField#literal?/static?/has_default?`,
    `ApiParam#in?/out?/optional?`, `ApiMethod#set_last_error?` (ImplMap),
    `ApiMethod#virtual?/abstract?/static?`
  - constants: `ApiField#constant_value` and `#constant_type`
  - lookup helpers:
    - `ApiModel#type?`
    - `ApiModel#type_by_token?`
    - `ApiModel#types_in_namespace`
    - `ApiModel#method?`
    - `ApiModel#find_methods`
    - `ParsedAssembly#type?`
  - token lookup helpers:
    - `TablesStream#type_def_by_token?`
    - `TablesStream#method_def_by_token?`
    - `TablesStream#field_by_token?`
    - `ParsedAssembly#type_def_by_token?`
    - `ParsedAssembly#method_def_by_token?`
    - `ParsedAssembly#field_by_token?`
  - nested type projection:
    - `ApiType#nested_types` / `#nested_type_tokens`
    - `ApiType#enclosing_type` / `#enclosing_type_token`
    (nested type names such as `_Anonymous_e__Union` are not unique, tokens are)
  - token projection in normalized API:
    - `ApiType#token`
    - `ApiMethod#token`
    - `ApiField#token`
    - `ApiParam#token`
  - generic context projection:
    - `ApiType#generic_params`
    - `ApiMethod#generic_params`
    - method signatures in API model resolve `var(n)` / `mvar(n)` using known generic names

- Test coverage
  - synthetic fixture exercises parser behavior and table relationships
  - integration test against local `winmd/Windows.Win32.winmd` when present
  - specs currently pass

- Parse diagnostics
  - `TablesStream#parsed_row_counts` and `#skipped_row_counts` report which metadata tables were decoded vs skipped
  - `TablesStream#parsed_tables`, `#skipped_tables`, and `#parse_coverage_ratio` provide quick confidence checks

- Maintainability progress
  - normalized API model construction extracted from `Parser` into `ApiModelBuilder`
  - signature decoding extracted into `SignatureDecoder`
  - custom attribute payload decoding extracted into `CustomAttributeDecoder`
  - metadata table iteration/dispatch extracted from `Parser` into `TableIteration`

## Known Gaps

These are the key areas still needed for robust WinMD-to-binding workflows.

### Metadata coverage gaps

- Additional table decoding still needed for richer fidelity:
  - deeper assembly identity and cross-assembly resolution details beyond raw `AssemblyRef` rows

### Signature fidelity gaps

- More complete grammar handling and richer shape output
  - deeper generic-context rendering across all signature surfaces (beyond API-model method signatures)
  - continue expanding canonical rendering and formatting for edge signatures

### Custom attribute decoding

- Structured decoding covers every attribute whose constructor signature is
  known (MethodDef or MemberRef); enum-typed constructor parameters are assumed
  to be Int32-backed, which holds for all WinMD attributes seen so far.
- Additional high-value WinRT projection attributes still need dedicated
  display decoders for the legacy `decoded_value` string.

### API model quality

- Improve linkage and completeness:
  - surface `MemberRef`/`TypeSpec` usage in higher-level model
  - `ApiModel#type?` keeps the last definition when a full name is duplicated
    (per-architecture variants); iterate `types` or use tokens for those

### Error handling and resilience

- Parser currently allows partial decoding across unsupported table sections.
- Basic "parsed vs skipped" table diagnostics now available in `TablesStream`.
- Still need richer range-level diagnostics and structured warnings for skipped constructs.
- Opt-in strict mode is available via `Ecma335.parse(..., strict: true)` / `parse_bytes(..., strict: true)` to fail on skipped tables.
- Strict mode also rejects decoded signatures that still contain unsupported/unknown signature elements.

### Performance

- Current implementation is functional-first.
- Future improvements:
  - lower allocation in hot paths
  - lazy decoding options for very large WinMDs
  - optional selective table decoding

### Maintainability

- `parser.cr` has grown significantly and has complexity warnings.
- Refactor target:
  - split into focused components (`TablesParser`, `SignatureDecoder`, `CustomAttributeDecoder`, `ApiModelBuilder`)
  - keep public API stable while reducing implementation complexity
  - `ApiModelBuilder`, `SignatureDecoder`, `CustomAttributeDecoder`, and `TableIteration` extractions are complete; table row decoders remain to split further

## Practical Next Steps

Recommended order:

1. Refactor parser into smaller classes (no behavior change).
2. Implement property/event/method-semantics tables.
3. Expand generic/method-spec signature handling.
4. Add typed decoders for high-value WinMD custom attributes.
5. Strengthen normalized model with token-rich relationships.
6. Add golden assertions for specific well-known Win32 symbols used by your generator.

## Future Ideas

- Add broader strict coverage for unsupported signature constructs (table strict mode is now available).
- Add token-based query API:
  - `type_by_token`, `method_by_token`, `field_by_token`.
- Add a serializer/debug utility:
  - dump selected metadata as JSON for easier inspection.
- Add a compatibility snapshot tool:
  - compare two WinMD files and report API deltas.
- Add benchmark suite for large WinMD parsing.

## Summary

The project has moved from bootstrap to a solid mid-stage parser with meaningful table decoding and a usable normalized API model. It is now capable of replacing part of the `win32json` dependency path, with the largest remaining work in completeness (properties/events/generics/attributes) and maintainability refactor.
