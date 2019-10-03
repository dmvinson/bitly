module Bitly
  # Url objects should only be created by the client object as it collects the correct information
  # from the API.
  class Bitlink
    def initialize(client, opts={})
      @client = client
      attr_reader :archived, :tags, :created_at, :title, :deeplinks,
        :created_by, :long_url, :custom_bitlinks, :link, :id
    end
  end
end
