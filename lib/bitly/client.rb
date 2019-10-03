module Bitly
  # The client is the main part of this gem. You need to initialize the client with your
  # username and API key and then you will be able to use the client to perform
  # all the rest of the actions available through the API.
  class Client
    include HTTParty
    base_uri 'https://api-ssl.bitly.com/v4/'

    # Requires a generic OAuth2 access token or -deprecated- login and api key.
    # http://dev.bitly.com/authentication.html#apikey
    # Generic OAuth2 access token: https://bitly.com/a/oauth_apps
    # ApiKey: Get yours from your account page at https://bitly.com/a/your_api_key
    # Visit your account at http://bit.ly/a/account
    def initialize(*args)
      args.compact!
      self.timeout = args.last.is_a?(0.class) ? args.pop : nil
      if args.count == 1
        # Set generic OAuth2 access token
        access_token = args.first
      else
        # Deprecated ApiKey authentication
        access_token = get_access_token_from_login_credentials
      end
      @default_headers = { :access_token => access_token }
    end

    def do_basic_auth(username, password)
      auth_val = "Basic #{Base64.encode64(username + ':' + password)}"
      headers = {'Authorization': auth_val}
      resp = self.class.get('/oauth/access_token')
      return response.body # Access token
    end

    # Shortens a long url
    #
    # Options can be:
    #
    # [domain]                choose bit.ly or j.mp (bit.ly is default)
    #
    # [group_guid] 
    # 
    # [tags]
    #
    # [deeplinks]
    # [x_login and x_apiKey]  add this link to another user's history (both required)
    #
    def shorten(long_url, opts={})
      query = { :long_url => long_url }.merge(opts)
      response = post('/shorten', :query => query)
      return Bitly::Url.new(self, response['data'])
    end

    # Expands either a hash, short url or array of either.
    #
    # Returns the results in the order they were entered
    def expand(input)
      get_endpoint(:expand, input)
    end

    # Expands either a hash, short url or array of either and gets click data too.
    #
    # Returns the results in the order they were entered
    def clicks(input)
      get_endpoint(:clicks, input)
    end

    # Like expand, but gets the title of the page and who created it
    def info(input)
      get_endpoint(:info, input)
    end

    # Looks up the short url and global hash of a url or array of urls
    #
    # Returns the results in the order they were entered
    def lookup(input)
      input = arrayize(input)
      query = input.inject([]) { |q, i| q << "url=#{CGI.escape(i)}" }
      query = "/lookup?" + query.join('&')
      response = get(query)
      results = response['data']['lookup'].inject([]) do |rs, url|
        url['long_url'] = url['url']
        url['url'] = nil
        if url['error'].nil?
          # builds the results array in the same order as the input
          rs[input.index(url['long_url'])] = Bitly::Url.new(self, url)
          # remove the key from the original array, in case the same hash/url was entered twice
          input[input.index(url['long_url'])] = nil
        else
          rs[input.index(url['long_url'])] = Bitly::MissingUrl.new(url)
          input[input.index(url['long_url'])] = nil
        end
        rs
      end
      return results.length > 1 ? results : results[0]
    end

    # Expands either a short link or hash and gets the referrer data for that link
    #
    # This endpoint does not take an array as an input
    def referrers(input)
      get_single_endpoint('referrers', input)
    end

    # Expands either a short link or hash and gets the country data for that link
    #
    # This endpoint does not take an array as an input
    def countries(input)
      get_single_endpoint('countries', input)
    end

    # Takes a short url, hash or array of either and gets the clicks by minute of each of the last hour
    def clicks_by_minute(input)
      get_endpoint(:clicks_by_minute, input)
    end

    # Takes a short url, hash or array of either and gets the clicks by day
    def clicks_by_day(input, opts={})
      opts.reject! { |k, v| k.to_s != 'days' }
      get_endpoint(:clicks_by_day, input, opts)
    end

    def timeout=(timeout=nil)
      self.class.default_timeout(timeout) if timeout
    end

    private

    def arrayize(arg)
      if arg.is_a?(String)
        [arg]
      else
        arg.dup
      end
    end

    def get(endpoint, opts={}, headers={})
      opts[:query] ||= {}
      opts[:query].merge!(@default_query_opts)
      headers.merge!(@default_headers)

      begin
        response = self.class.get(endpoint, opts)
      rescue Timeout::Error
        raise BitlyTimeout.new("Bitly didn't respond in time", "504")
      end

      if response['status_code'] == 200
        return response
      else
        raise BitlyError.new(response['status_txt'], response['status_code'])
      end
    end

    def post(endpoint, opts={}, headers={})
      opts[:query] ||= {}
      opts[:query].merge!(@default_query_opts)
      headers.merge!(@default_headers)

      begin
        response = self.class.post(endpoint, body: opts, headers: headers)
      rescue Timeout::Error
        raise BitlyTimeout.new("Bitly didn't respond in time", "504")
      end

      if response['status_code'] == 200
        return response
      else
        raise BitlyError.new(response['status_txt'], response['status_code'])
      end
    end

    def is_a_short_url?(input)
      input.match(/^https?:\/\//)
    end

    def get_single_endpoint(endpoint, input)
      raise ArgumentError.new("This endpoint only takes a hash or url input") unless input.is_a? String
      if is_a_short_url?(input)
        query = "shortUrl=#{CGI.escape(input)}"
      else
        query = "hash=#{CGI.escape(input)}"
      end
      query = "/#{endpoint}?" + query
      response = get(query)
      return Bitly::Url.new(self,response['data'])
    end

    def get_endpoint(endpoint, input, opts={})
      input = arrayize(input)
      query = input.inject([]) do |q, i|
        if is_a_short_url?(i)
          q << "shortUrl=#{CGI.escape(i)}"
        else
          q << "hash=#{CGI.escape(i)}"
        end
      end
      query = opts.inject(query) do |q, (k,v)|
        q << "#{k}=#{v}"
      end
      query = "/#{endpoint}?" + query.join('&')
      response = get(query)
      results = response['data'][endpoint.to_s].inject([]) do |rs, url|
        result_index = input.index(url['short_url'] || url['hash']) || input.index(url['global_hash'])
        if url['error'].nil?
          # builds the results array in the same order as the input
          rs[result_index] = Bitly::Url.new(self, url)
          # remove the key from the original array, in case the same hash/url was entered twice
          input[result_index] = nil
        else
          rs[result_index] = Bitly::MissingUrl.new(url)
          input[result_index] = nil
        end
        rs
      end
      return results.length > 1 ? results : results[0]
    end
  end
end

class BitlyError < StandardError
  attr_reader :code
  alias :msg :message
  def initialize(msg, code)
    @code = code
    super("#{msg} - '#{code}'")
  end
end

class BitlyTimeout < BitlyError; end
