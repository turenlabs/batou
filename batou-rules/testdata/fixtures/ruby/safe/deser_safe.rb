# Safe deserialization patterns
# Tests: YAML.safe_load, Psych.safe_load, Oj.safe_load, Oj.strict_load

require 'yaml'
require 'psych'
require 'oj'

class ConfigController < ApplicationController
  def import_yaml
    data = params[:config]
    # Safe: YAML.safe_load only allows basic types
    config = YAML.safe_load(data)
    apply_config(config)
  end

  def import_psych
    data = params[:config]
    # Safe: Psych.safe_load disables arbitrary object creation
    config = Psych.safe_load(data)
    apply_config(config)
  end

  def import_json_safe
    data = params[:json_data]
    # Safe: Oj.safe_load disables object mode deserialization
    obj = Oj.safe_load(data)
    render json: obj
  end

  def import_json_strict
    data = params[:json_data]
    # Safe: Oj.strict_load only allows basic JSON types
    obj = Oj.strict_load(data)
    render json: obj
  end
end
