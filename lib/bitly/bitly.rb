module Bitly
  def self.new(login, api_key)
    Bitly::Client.new(login, api_key)
  end
end
