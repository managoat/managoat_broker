defmodule Managoat.Broker.Diagnostics do
  @moduledoc false

  # One optional observer per CONNECT tunnel. It monitors the handler rather
  # than linking to it: diagnostics must neither keep a connection alive nor
  # kill one. Counters are shared with the relay, so a blocked ssl.send cannot
  # also block the progress report. No packet, URL, credential or raw transport
  # error is sent to this process.
  @upstream_bytes 1
  @client_bytes 2
  @write_duration 3
  @pending 4
  @writing 5
  @write_started 6
  @first_byte 7
  @last_byte 8
  @requests 9

  def start(nil, _meta), do: nil

  def start(interval, meta) do
    counters = :atomics.new(9, signed: true)
    owner = self()
    started = System.monotonic_time()

    meta =
      Map.put(meta, :connection_id, Base.encode16(:crypto.strong_rand_bytes(12), case: :lower))

    pid =
      spawn(fn ->
        Process.send_after(self(), :sample, interval)
        observe(Process.monitor(owner), interval, counters, meta, started, :setup)
      end)

    %{pid: pid, counters: counters, meta: meta}
  end

  def measure(nil, _phase, fun), do: fun.()

  def measure(trace, phase, fun) do
    started = System.monotonic_time()
    send(trace.pid, {:phase, phase})
    result = fun.()
    outcome = if match?({:ok, _}, result), do: :ok, else: :error
    send(trace.pid, {:measured, phase, System.monotonic_time() - started, outcome})
    result
  end

  def request(nil, request), do: request

  def request(trace, request) do
    ordinal = :atomics.add_get(trace.counters, @requests, 1)
    :atomics.add(trace.counters, @pending, 1)
    id = trace.meta.connection_id <> ":" <> Integer.to_string(ordinal)
    send(trace.pid, {:request, id})

    Map.merge(request, %{
      diagnostics: trace,
      connection_id: trace.meta.connection_id,
      request_id: id
    })
  end

  def finished(%{diagnostics: trace}), do: :atomics.sub(trace.counters, @pending, 1)
  def finished(_request), do: :ok

  def received(nil, _bytes), do: :ok

  def received(trace, bytes) do
    now = System.monotonic_time()
    :atomics.compare_exchange(trace.counters, @first_byte, 0, now)
    :atomics.put(trace.counters, @last_byte, now)
    :atomics.add(trace.counters, @upstream_bytes, bytes)
  end

  def write(nil, _bytes, fun), do: fun.()

  def write(trace, bytes, fun) do
    started = System.monotonic_time()
    :atomics.put(trace.counters, @write_started, started)
    :atomics.put(trace.counters, @writing, 1)
    result = fun.()
    :atomics.add(trace.counters, @write_duration, System.monotonic_time() - started)
    if result == :ok, do: :atomics.add(trace.counters, @client_bytes, bytes)
    :atomics.put(trace.counters, @writing, 0)
    result
  end

  def stop(nil, _reason), do: :ok
  def stop(trace, reason), do: send(trace.pid, {:stop, reason})

  defp observe(ref, interval, counters, meta, started, phase) do
    receive do
      {:phase, next} ->
        observe(ref, interval, counters, meta, started, next)

      {:measured, measured, duration, outcome} ->
        emit(meta, :phase, %{duration: duration}, %{phase: measured, outcome: outcome})
        observe(ref, interval, counters, meta, started, :serving)

      {:request, id} ->
        emit(meta, :request_start, %{}, %{request_id: id})
        observe(ref, interval, counters, meta, started, phase)

      {:stop, reason} ->
        snapshot(counters, meta, started, phase, :stop, reason)
        Process.demonitor(ref, [:flush])

      {:DOWN, ^ref, :process, _owner, _reason} ->
        snapshot(counters, meta, started, phase, :stop, :handler_exit)

      :sample ->
        Process.send_after(self(), :sample, interval)

        if phase != :serving or :atomics.get(counters, @pending) > 0 do
          snapshot(counters, meta, started, phase, :progress, nil)
        end

        observe(ref, interval, counters, meta, started, phase)
    end
  end

  defp snapshot(counters, meta, started, phase, event, reason) do
    now = System.monotonic_time()
    writing? = :atomics.get(counters, @writing) == 1
    blocked = if writing?, do: now - :atomics.get(counters, @write_started), else: 0
    first = :atomics.get(counters, @first_byte)
    last = :atomics.get(counters, @last_byte)

    measurements = %{
      duration: now - started,
      upstream_bytes: :atomics.get(counters, @upstream_bytes),
      client_bytes: :atomics.get(counters, @client_bytes),
      client_write_duration: :atomics.get(counters, @write_duration),
      client_write_in_flight: blocked,
      pending_requests: :atomics.get(counters, @pending),
      requests: :atomics.get(counters, @requests)
    }

    measurements =
      if first == 0, do: measurements, else: Map.put(measurements, :first_byte, first - started)

    measurements =
      if last == 0, do: measurements, else: Map.put(measurements, :upstream_idle, now - last)

    emit(meta, event, measurements, %{phase: phase, client_writing: writing?, reason: reason})
  end

  defp emit(meta, event, measurements, extra) do
    :telemetry.execute(
      [:managoat, :broker, :diagnostic],
      measurements,
      meta |> Map.merge(extra) |> Map.put(:event, event)
    )
  end
end
