# Encoding: ASCII-8BIT
##
# transaction.rb
# Created June 20, 2017
# By Ron Bowes
#
# See: LICENSE.md
#
# When a request comes in, a transaction is created and sent to the callback.
# The transaction can be used to respond to the request at any point in the
# future.
#
# Any methods with a bang ('!') in front will send the response back to the
# requester. Only one bang method can be called, any subsequent calls will
# throw an exception.
##
module DNSer
  class Transaction
    attr_reader :request, :response, :sent

    def initialize(s, request, host, port, cache = nil)
      @s       = s
      @request = request
      @host    = host
      @port    = port
      @sent    = false
      @cache   = cache

      @response = DNSer::Packet.new(
        @request.trn_id,
        DNSer::Packet::QR_RESPONSE,
        @request.opcode,
        DNSer::Packet::FLAG_RD | DNSer::Packet::FLAG_RA,
        DNSer::Packet::RCODE_SUCCESS
      )

      @response.add_question(@request.questions[0])
    end

    def add_answer(answer)
      raise ArgumentError("Already sent!") if(@sent)

      @response.add_answer(answer)
    end

    def error(rcode)
      raise ArgumentError("Already sent!") if(@sent)

      @response.rcode = rcode
    end

    def error!(rcode)
      raise ArgumentError("Already sent!") if(@sent)

      @response.rcode = rcode
      reply!()
    end

    def passthrough!(pt_host, pt_port, callback = nil)
      raise ArgumentError("Already sent!") if(@sent)

      DNSer.query(@request.questions[0].name, {
          :server  => pt_host,
          :port    => pt_port,
          :type    => @request.questions[0].type,
          :cls     => @request.questions[0].cls,
          :timeout => 3,
        }
      ) do |response|
        # If there was a timeout, handle it
        if(response.nil?)
          response = @response
          response.rcode = DNSer::Packet::RCODE_SERVER_FAILURE
        end

        response.trn_id = @request.trn_id
        @s.send(response.serialize(), 0, @host, @port)

        # Let the callback know if anybody registered one
        if(callback)
          callback.call(response)
        end
      end

      @sent = true
    end

    def reply!()
      raise ArgumentError("Already sent!") if(@sent)

      # Cache it if we have a cache
      if(@cache)
        @cache[@request.trn_id, 3] = {
          :request  => @request,
          :response => @response,
        }
      end

      # Send the response
      @s.send(@response.serialize(), 0, @host, @port)
      @sent = true
    end
  end

  # Create a new DNSer and listen on the given host/port. This will throw an
  # exception if we aren't allowed to bind to the given port.
  def initialize(host, port, cache=false)
    @s = UDPSocket.new()
    @s.bind(host, port)
    @thread = nil

    # Create a cache if the user wanted one
    if(cache)
      @cache = Vash.new()
    end
  end

  # This method returns immediately, but spawns a background thread. The thread
  # will recveive and unpack DNS packets, create a transaction, and pass it to
  # the caller's block.
  def on_request()
    @thread = Thread.new() do |t|
      begin
        loop do
          data = @s.recvfrom(65536)

          # Data is an array where the first element is the actual data, and the second is the host/port
          request = DNSer::Packet.unpack(data[0])

          # Create a transaction object, which we can use to respond
          transaction = Transaction.new(@s, request, data[1][3], data[1][1], @cache)

          # If caching is enabled, deal with it
          if(@cache)
            # This is somewhat expensive, but we aren't using the cache for performance
            @cache.cleanup!()

            # See if the transaction is cached
            cached = @cache[request.trn_id]

            # Verify it deeper (for security reasons)
            if(!cached.nil?)
              puts("POTENTIAL CACHE HIT")
              if(request == cached[:request])
                puts("CACHE HIT")
                transaction.reply!(cached[:response])
              end
            end
          end

          if(!transaction.sent)
            begin
              proc.call(transaction)
            rescue StandardError => e
              puts("Caught an error: #{e}")
              puts(e.backtrace())
              transaction.reply!(transaction.response_template({:rcode => DNSer::Packet::RCODE_SERVER_FAILURE}))
            end
          end
        end
      ensure
        @s.close
      end
    end
  end

  # Kill the listener
  def stop()
    if(@thread.nil?)
      puts("Tried to stop a listener that wasn't listening!")
      return
    end

    @thread.kill()
    @thread = nil
  end

  # After calling on_request(), this can be called to halt the program's
  # execution until the thread is stopped.
  def wait()
    if(@thread.nil?)
      puts("Tried to wait on a DNSer instance that wasn't listening!")
      return
    end

    @thread.join()
  end
end
