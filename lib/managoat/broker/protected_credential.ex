defmodule Managoat.Broker.ProtectedCredential do
  @moduledoc """
  A fresh bearer and its public identity, returned only for a protected
  request. Never put this value in ordinary Rule credentials, templates,
  session metadata, or persisted session rules. Inspection is redacted.
  The identity must equal the identity pinned in the ProtectedRule.
  """
  @derive {Inspect, only: []}
  @enforce_keys [:bearer, :identity]
  defstruct [:bearer, :identity]
  @type t :: %__MODULE__{bearer: binary(), identity: binary()}
end
