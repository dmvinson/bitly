module Bitly
  module Config
    OPTION_KEYS = [
      :login,
      :api_key,
      :api_version,
      :timeout
    ]
    attr_accessor(*OPTION_KEYS)

    def configure
      yield self
      self
    end

    def options
      options = {}
      OPTION_KEYS.each{|key| options[key] = send(key)}
      options
    end
  end
end

