defmodule Managoat.Broker.ReflectionGuardTest do
  use ExUnit.Case, async: true

  alias Managoat.Broker.{HTTPOnly, ReflectionGuard}

  @bearer "tok/en.AbC-123_xyz"

  defp guard(framing \\ {:length, 1_000_000}) do
    @bearer |> ReflectionGuard.needles() |> ReflectionGuard.new() |> ReflectionGuard.body(framing)
  end

  # Feed `parts` one read at a time. `{:ok, forwarded}` is everything that
  # was released, the end-of-body flush included.
  defp feed(guard, parts) do
    Enum.reduce_while(parts, {:ok, guard, []}, fn part, {:ok, guard, out} ->
      case ReflectionGuard.scan(guard, part) do
        {:ok, guard, safe} -> {:cont, {:ok, guard, [out, safe]}}
        {:error, reason} -> {:halt, {:error, reason, IO.iodata_to_binary(out)}}
      end
    end)
    |> case do
      {:ok, guard, out} -> {:ok, IO.iodata_to_binary([out, ReflectionGuard.flush(guard)])}
      error -> error
    end
  end

  defp chunked(parts),
    do:
      Enum.map_join(parts, &"#{Integer.to_string(byte_size(&1), 16)}\r\n#{&1}\r\n") <> "0\r\n\r\n"

  test "the value is recognised as itself and in its JSON spelling, and the guard shows neither" do
    assert ReflectionGuard.needles(@bearer) == [@bearer, "tok\\/en.AbC-123_xyz"]
    assert ReflectionGuard.needles("plain") == ["plain"]
    assert ReflectionGuard.new(nil) == nil
    refute inspect(guard()) =~ "tok"

    assert {:error, :credential_reflected, _} = feed(guard(), [~s({"auth":"Bearer #{@bearer}"})])
    assert {:error, :credential_reflected, _} = feed(guard(), [~s({"a":"tok\\/en.AbC-123_xyz"})])

    # What it says it does not recognise.
    for other <- [Base.encode64(@bearer), String.upcase(@bearer), String.slice(@bearer, 0..-2//1)] do
      assert {:ok, ^other} = feed(guard(), [other])
    end
  end

  test "a value split at every possible byte is caught, and no part of it is released first" do
    for at <- 1..(byte_size(@bearer) - 1) do
      {first, second} = String.split_at(@bearer, at)

      assert {:error, :credential_reflected, released} =
               feed(guard(), ["data: " <> first, second <> "\n\n"])

      assert released == "data: "
    end

    # One byte per read is the limit of that.
    bytes = for <<byte <- "x " <> @bearer>>, do: <<byte>>
    assert {:error, :credential_reflected, "x "} = feed(guard(), bytes)
  end

  test "bytes that only began like the value are released as soon as they stop" do
    guard = guard()
    assert {:ok, guard, out} = ReflectionGuard.scan(guard, "abc tok/en.")
    assert IO.iodata_to_binary(out) == "abc "
    assert {:ok, guard, out} = ReflectionGuard.scan(guard, "NOT tok")
    assert IO.iodata_to_binary(out) == "tok/en.NOT "
    assert IO.iodata_to_binary(ReflectionGuard.flush(guard)) == "tok"
    assert ReflectionGuard.flush(nil) == []
  end

  test "chunk framing in the middle of the value does not hide it" do
    {first, second} = String.split_at(@bearer, 7)
    raw = chunked(["data: " <> first, second <> "\n\n"])

    assert {:error, :credential_reflected, _} = feed(guard(:chunked), [raw])

    # And at every read boundary of those raw bytes, framing included.
    for at <- 1..(byte_size(raw) - 1) do
      <<one::binary-size(^at), two::binary>> = raw
      assert {:error, :credential_reflected, released} = feed(guard(:chunked), [one, two])
      refute released =~ "tok"
    end
  end

  test "a clean chunked body comes out byte for byte however it is read" do
    raw = chunked(["event: a\ndata: tok", "/en. almost\n\n", "tail tok/en.AbC-123_xy"])

    for size <- [1, 2, 3, 7, 64, byte_size(raw)] do
      parts = for <<part::binary-size(size) <- raw>>, do: part
      rest = binary_part(raw, length(parts) * size, rem(byte_size(raw), size))
      assert {:ok, ^raw} = feed(guard(:chunked), parts ++ [rest])
    end
  end

  test "trailers are searched, and a chunk extension is refused rather than searched" do
    assert {:error, :credential_reflected, _} =
             feed(guard(:chunked), ["2\r\nok\r\n0\r\nx-debug: #{@bearer}\r\n\r\n"])

    assert {:error, :malformed_response, _} =
             feed(guard(:chunked), ["2;note=#{@bearer}\r\nok\r\n0\r\n\r\n"])

    assert {:error, :malformed_response, _} = feed(guard(:chunked), ["2;no", "te=x\r\nok\r\n"])
  end

  test "only a coding other than identity counts as encoded" do
    refute ReflectionGuard.encoded?([{"Content-Type", "text/plain"}])
    refute ReflectionGuard.encoded?([{"Content-Encoding", "identity"}])
    refute ReflectionGuard.encoded?([{"content-encoding", " Identity , "}])
    assert ReflectionGuard.encoded?([{"Content-Encoding", "gzip"}])

    assert ReflectionGuard.encoded?([
             {"content-encoding", "identity"},
             {"CONTENT-ENCODING", "br"}
           ])

    assert ReflectionGuard.encoded?([{"content-encoding", "identity, zstd"}])
  end

  describe "through the response gate" do
    defp gate(method \\ "POST") do
      guard = @bearer |> ReflectionGuard.needles() |> ReflectionGuard.new()
      HTTPOnly.expect(HTTPOnly.new(true), method, guard)
    end

    test "an informational head is searched like the one that follows it" do
      assert {:error, :credential_reflected} =
               HTTPOnly.filter(gate(), "HTTP/1.1 103 Early Hints\r\nLink: </#{@bearer}>\r\n\r\n")

      assert {:error, :credential_reflected} =
               HTTPOnly.filter(gate(), "HTTP/1.1 401 #{@bearer}\r\nContent-Length: 0\r\n\r\n")
    end

    test "a body that only the close ends gives up what it held when the origin closes" do
      head = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
      assert {:ok, gate, out} = HTTPOnly.filter(gate(), head <> "ends on tok/en")
      assert out == head <> "ends on "
      assert HTTPOnly.closed(gate) == "tok/en"
      assert HTTPOnly.closed(nil) == ""
    end

    test "the guard is spent with its response: the next one on the connection is not searched" do
      gate = HTTPOnly.expect(gate(), "GET")
      first = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
      second = "HTTP/1.1 200 OK\r\nContent-Length: #{byte_size(@bearer)}\r\n\r\n#{@bearer}"
      assert {:ok, gate, ^first} = HTTPOnly.filter(gate, first)
      assert {:ok, _gate, ^second} = HTTPOnly.filter(gate, second)
    end

    test "a held tail is released when a length-framed body ends in the same read" do
      body = "ends on tok/en"
      raw = "HTTP/1.1 200 OK\r\nContent-Length: #{byte_size(body)}\r\n\r\n#{body}"
      assert {:ok, _gate, ^raw} = HTTPOnly.filter(gate(), raw)

      at = byte_size(raw) - 3
      <<one::binary-size(^at), two::binary>> = raw
      assert {:ok, gate, out} = HTTPOnly.filter(gate(), one)
      refute out =~ "tok"
      assert {:ok, _gate, rest} = HTTPOnly.filter(gate, two)
      assert out <> rest == raw
    end
  end
end
