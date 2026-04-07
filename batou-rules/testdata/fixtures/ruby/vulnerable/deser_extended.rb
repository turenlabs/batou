# Extended deserialization vulnerabilities
# Tests: Marshal.restore, YAML.unsafe_load, Psych.unsafe_load, Oj.load

require 'yaml'
require 'psych'
require 'oj'

class ConfigController < ApplicationController
  def import_marshal
    data = params[:payload]
    # Vulnerable: Marshal.restore is an alias for Marshal.load
    obj = Marshal.restore(data)
    render json: obj
  end

  def import_yaml
    data = params[:config]
    # Vulnerable: YAML.unsafe_load explicitly allows arbitrary object creation (Ruby 3.1+)
    config = YAML.unsafe_load(data)
    apply_config(config)
  end

  def import_psych
    data = params[:config]
    # Vulnerable: Psych.unsafe_load is the YAML backend's unsafe method
    config = Psych.unsafe_load(data)
    apply_config(config)
  end

  def import_json
    data = params[:json_data]
    # Vulnerable: Oj.load with default or :object mode can deserialize arbitrary Ruby objects
    obj = Oj.load(data)
    render json: obj
  end
end
