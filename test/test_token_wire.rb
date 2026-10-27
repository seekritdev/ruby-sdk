# frozen_string_literal: true
require "json"
require "socket"
$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))
require "seekrit/sdk"
v = JSON.parse(File.read(File.expand_path("../testdata/vectors.json", __dir__)))
auth = Seekrit::Crypto.service_token_auth(v["token"])
raise "wrong auth" unless auth == v["authToken"]
server = TCPServer.new("127.0.0.1", 0)
received = nil
thread = Thread.new do
  socket = server.accept
  received = +""
  until received.end_with?("\r\n\r\n")
    received << socket.read(1)
  end
  socket.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
  socket.close
end
client = Seekrit::Client.new(token: v["token"], api_url: "http://127.0.0.1:#{server.addr[1]}")
client.send(:fetch)
thread.join
server.close
raise "wrong header" unless received.include?("Bearer #{auth}\r\n")
raise "private key sent" if received.include?(v["token"].split(".")[2])
begin
  Seekrit::Crypto::TokenKey.parse(auth)
  raise "auth credential accepted as a private key"
rescue Seekrit::CryptoError
end
legacy = v["tokenId"] + "_" + v["token"].split(".")[2]
Seekrit::Crypto::TokenKey.parse(legacy)
begin
  Seekrit::Client.new(token: legacy)
  raise "legacy accepted for network use"
rescue Seekrit::CryptoError
end
puts "ok: v2 auth only on HTTP, legacy rejected, offline legacy key readable"
