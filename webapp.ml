open Lwt.Infix

type verifier = string (* code_verifier from PKCE *)
type state = string (* "state" from Etsy OpenAPI 3.0 *)
type code = string (* "code" from Etsy OpenAPI 3.0, returned from resource server after a successful grant from the end user *)
type token = string

type authentication_step =
  | None
  | Began of state * verifier
  | Awaiting_tokens of code
  | Has_tokens of token (* returns only the refresh token, I guess? *)

module Make
    (Random : Mirage_random.S)
    (Clock : Mirage_clock.PCLOCK)
    (Kv : Mirage_kv.RW)
    (H : Cohttp_mirage.Server.S) = struct

  module PKCE = Pkce.Make(Random)

  let state = Mirage_kv.Key.v "state"
  let verifier = Mirage_kv.Key.v "verifier"

  let start_auth kv uuid =
    let new_state = PKCE.verifier () in
    let new_verifier = PKCE.verifier () in
    Lwt_result.both
      (Kv.set kv Mirage_kv.Key.(uuid // state) new_state)
      (Kv.set kv Mirage_kv.Key.(uuid // verifier) new_verifier) >>= function
    | Error e -> Logs.err (fun f -> f "error storing new state and verifier: %a" Kv.pp_write_error e);
      Lwt.return @@ Error `Storage
    | Ok ((), ()) -> Lwt.return @@ Ok (new_state, new_verifier)

  let lookup_state kv uuid =
    (* it's very annoying that "state" is overloaded to mean a specific secret
     * in Etsy's OpenAPI 3, because I would like to use "state" to mean
     * "the current state of the OAuth2 transaction related to this ID, as deduced
     * from the presence of items in the database" :/ *)
    (* TODO: this should look up what's in the database related to this UUID,
     * and return a useful state thing related to it *)
    let uuid = Mirage_kv.Key.v uuid in
    Lwt_result.both
      (Kv.get kv @@ Mirage_kv.Key.(uuid // state))
      (Kv.get kv @@ Mirage_kv.Key.(uuid // verifier)) >>= function
    | Ok (state, verifier) -> Lwt.return @@ Ok (state, verifier)
    | Error Kv.(`Not_found _) -> start_auth kv uuid
    | Error e ->
      Logs.err (fun f -> f "error looking up a uuid's state: %a" Kv.pp_error e);
      Lwt.return (Error `Lookup)

  let not_found = (
    Cohttp.Response.make ~status:Cohttp.Code.(`Not_found) (),
    Cohttp_lwt__.Body.of_string "Not found")

  let ise = (
    Cohttp.Response.make ~status:Cohttp.Code.(`Internal_server_error) (),
    Cohttp_lwt__.Body.of_string "Internal server error")

  let bad_request = (
    Cohttp.Response.make ~status:Cohttp.Code.(`Bad_request) (),
    Cohttp_lwt__.Body.of_string "Bad request")

  let reply kv _host _start_time = 
    let callback _connection request body =
      let endpoint = Mirage_kv.Key.v @@ Uri.path @@ Cohttp.Request.uri request in
      let meth = Cohttp.Request.meth request in
      match meth, Mirage_kv.Key.equal endpoint @@ Mirage_kv.Key.v "/etsy" with
      | _, false -> Lwt.return not_found
      | `POST, true -> begin
          Cohttp_lwt__.Body.to_form body >>= fun entries ->
          match List.assoc_opt "uuid" entries with
          | None | Some [] | Some (_::_::_) -> Lwt.return bad_request
          | Some (uuid::[]) -> lookup_state kv uuid >>= function
            | Error `Lookup -> Logs.err (fun f -> f "error looking up uuid, failing");
              Lwt.return ise
            | Error `Storage -> Logs.err (fun f -> f "error retrieving uuid-related information from storage, failing");
              Lwt.return ise
            | Ok (state, verifier) ->
              let response = Cohttp.Response.make ~status:Cohttp.Code.(`OK) () in
              let body = Cohttp_lwt__.Body.(of_string @@ state ^ "\n" ^ verifier) in
              Lwt.return (response, body)
        end
      | _, true -> Lwt.return @@ ise
    in
    H.make ~conn_closed:(fun _ -> ()) ~callback ()
end
