module APNS
  require 'socket'
  require 'openssl'
  require 'json'

  @host = 'gateway.sandbox.push.apple.com'
  @port = 2195
  # openssl pkcs12 -in mycert.p12 -out client-cert.pem -nodes -clcerts
  @pem = nil # this should be the path of the pem file not the contentes
  @pass = nil
  @tcp_sock = nil
  @ssl_sock = nil
  @chunk_size = 999999999
  @nID = 0
  @numb_reconnections = 0
  @error_timeout = 0.4

  class << self
    attr_accessor :host, :pem, :port, :pass, :chunk_size, :error_timeout
  end

  ##
  #
  # send one notification message
  #
  # @param device_token [String] the token from device to which send notification
  # @param message [Hash] the notification message
  # @return [Array] the array of bad tokens
  #
  def self.send_notification(device_token, message)
    n = APNS::Notification.new(device_token, message)
    self.send_notifications([n])
  end

  ##
  #
  # check for errors after sending notification to Apple
  #
  # @return [Boolean] true if Apple return error on sending notifications or false if no error ; can raised exception
  #
  def self.check_for_errors
    if self.select(@error_timeout)
      error = nil
      if tuple = @ssl_socket.read(6)
        _, code, notification_id = tuple.unpack("ccN")
        @nID = notification_id
      else
        puts "Error - do not read error code ! "
      end

      begin
        puts("Error received, reconnecting...")
        @numb_reconnections += 1
        raise "APNS: many consecutive reconnections !" if @numb_reconnections > 10
        # reconnect
        @ssl_socket.close
        @tcp_socket.close

        @tcp_socket, @ssl_socket = self.open_connection
      ensure
        raise error if error
      end
      true
    else
      @numb_reconnections = 0
      false
    end
  end

  ##
  #
  # check for reading from connection
  #
  # @param time_out [Float] the timeout
  # @return [Boolean] true if you can read from connection
  #
  def self.select(timeout)
    IO.select([@ssl_socket], nil, nil, timeout)
  end

  ##
  #
  # send many notification messages
  #
  # @param notifications [Array] the array notifications which need send to Apple
  # @return [Array] the array of bad tokens
  #
  def self.send_notifications(notifications)
    @bad_tokens = []
    # split notifications for parts
    chunk = notifications.shift(@chunk_size)
    until chunk.empty? do
      # send one part
      self.send_chunk_of_notifications chunk
      # get next part
      chunk = notifications.shift(@chunk_size)
    end
    @bad_tokens
  end

  ##
  #
  # send many notification messages
  #
  # @param notifications [Array] the array notifications which need send to Apple
  # @return [Array] the array of bad tokens
  #
  def self.send_chunk_of_notifications(notifications)
    @tcp_socket, @ssl_socket = self.open_connection
    packed_nofications = self.packed_nofications(notifications)
    pushes = packed_nofications[:pushes]
    begin
      @ssl_socket.write(pushes)
      error = self.check_for_errors
      if error
        bad_token = notifications[@nID].device_token
        puts "was error ! Try resend after bad token = '#{bad_token}'"
        pushes = packed_nofications[:pushes][packed_nofications[:bounds][@nID]..-1]
        @bad_tokens << bad_token
        break if pushes.empty?
      end
    end while error
    # close connection
    begin
      @ssl_socket.close if @ssl_socket
      @tcp_socket.close if @tcp_socket
    rescue IOError
    end
  end

  def self.packed_nofications(notifications)
    bytes = ''
    bounds = []
    notifications.each_with_index  do |notification, id|
      # Each notification frame consists of
      # 1. (e.g. protocol version) 2 (unsigned char [1 byte]) 
      # 2. size of the full frame (unsigend int [4 byte], big endian)
      notification.message_identifier = id
      pn = notification.packaged_notification

      bytes << ([2, pn.bytesize].pack('CN') + pn)
      bounds << bytes.length
    end
    {pushes: bytes, bounds: bounds}
  end

  def self.feedback
    sock, ssl = self.feedback_connection

    apns_feedback = []

    while message = ssl.read(38)
      timestamp, token_size, token = message.unpack('N1n1H*')
      apns_feedback << [Time.at(timestamp), token]
    end

    ssl.close
    sock.close

    return apns_feedback
  end

  protected

  def self.open_connection
    raise "The path to your pem file is not set. (APNS.pem = /path/to/cert.pem)" unless self.pem
    raise "The path to your pem file does not exist!" unless File.exist?(self.pem)

    context      = OpenSSL::SSL::SSLContext.new
    context.cert = OpenSSL::X509::Certificate.new(File.read(self.pem))
    context.key  = OpenSSL::PKey::RSA.new(File.read(self.pem), self.pass)

    sock         = TCPSocket.new(self.host, self.port)
    ssl          = OpenSSL::SSL::SSLSocket.new(sock,context)
    ssl.connect

    return sock, ssl
  end

  def self.feedback_connection
    raise "The path to your pem file is not set. (APNS.pem = /path/to/cert.pem)" unless self.pem
    raise "The path to your pem file does not exist!" unless File.exist?(self.pem)

    context      = OpenSSL::SSL::SSLContext.new
    context.cert = OpenSSL::X509::Certificate.new(File.read(self.pem))
    context.key  = OpenSSL::PKey::RSA.new(File.read(self.pem), self.pass)

    fhost = self.host.gsub('gateway','feedback')
    puts fhost

    sock         = TCPSocket.new(fhost, 2196)
    ssl          = OpenSSL::SSL::SSLSocket.new(sock,context)
    ssl.connect

    return sock, ssl
  end
end
