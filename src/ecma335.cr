require "./ecma335/parse_error"
require "./ecma335/model"
require "./ecma335/binary_reader"
require "./ecma335/table_iteration"
require "./ecma335/api_model_builder"
require "./ecma335/custom_attribute_decoder"
require "./ecma335/signature_decoder"
require "./ecma335/signature_canonicalizer"
require "./ecma335/parser"

module Ecma335
  VERSION = "1.1.0"

  def self.parse(path : String, strict : Bool = false) : ParsedAssembly
    parse_bytes(File.read(path).to_slice, strict: strict)
  end

  def self.parse_bytes(bytes : Bytes, strict : Bool = false) : ParsedAssembly
    Parser.new(bytes, strict).parse
  end
end
