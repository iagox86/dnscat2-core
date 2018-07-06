# Encoding: ASCII-8BIT
##
# dnser.rb
# Created Oct 7, 2015
# By Ron Bowes
#
# See: LICENSE.md
##

module Dnscat2
  LOG_LEVEL_INFO = 0
  LOG_LEVEL_LOG = 1
  LOG_LEVEL_WARNING = 2
  LOG_LEVEL_ERROR = 3
  LOG_LEVEL_FATAL = 4

  class Logger
    def initialize(level:LOG_LEVEL_WARNING, sink: ::STDERR)
      @level = level
      @sink = sink
    end

    def info(msg)
      sink.puts(msg.to_s) if level <= LOG_LEVEL_INFO
    end

    def log(msg)
      sink.puts(msg.to_s) if level <= LOG_LEVEL_LOG
    end

    def warning(msg)
      sink.puts(msg.to_s) if level <= LOG_LEVEL_WARNING
    end

    def error(msg)
      sink.puts(msg.to_s) if level <= LOG_LEVEL_ERROR
    end

    def fatal(msg)
      sink.puts(msg.to_s) if level <= LOG_LEVEL_FATAL
    end
  end
end
