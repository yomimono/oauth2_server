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
    (H : Cohttp_mirage.Server.S)
    (Client : Cohttp_lwt.S.Client) = struct

  module PKCE = Pkce.Make(Random)

  let code = Mirage_kv.Key.v "code"
  let state = Mirage_kv.Key.v "state"
  let verifier = Mirage_kv.Key.v "verifier"
  let access = Mirage_kv.Key.v "access"
  let refresh = Mirage_kv.Key.v "refresh"
  let expiration = Mirage_kv.Key.v "expires_in"

  let start_auth kv =
    let new_state = PKCE.verifier () in
    let new_verifier = PKCE.verifier () in
    Kv.set kv Mirage_kv.Key.(v new_state // verifier) new_verifier >>= function
    | Error e -> Logs.err (fun f -> f "error storing new state and verifier: %a" Kv.pp_write_error e);
      Lwt.return @@ Error `Storage
    | Ok () -> Lwt.return @@ Ok (new_state, new_verifier)

  let not_found = (
    Cohttp.Response.make ~status:Cohttp.Code.(`Not_found) (),
    Cohttp_lwt__.Body.of_string "Not found")

  let ise = (
    Cohttp.Response.make ~status:Cohttp.Code.(`Internal_server_error) (),
    Cohttp_lwt__.Body.of_string "Internal server error")

  let bad_request = (
    Cohttp.Response.make ~status:Cohttp.Code.(`Bad_request) (),
    Cohttp_lwt__.Body.of_string "Bad request")

  let ok_empty = (
    Cohttp.Response.make ~status:Cohttp.Code.(`OK) (),
    Cohttp_lwt__.Body.empty)

  let maybe_store kv state body =
    let store kv state access_token refresh_token seconds =
      Lwt_result.both
        (Lwt_result.both
           (Kv.set kv Mirage_kv.Key.(v state // access) access_token)
           (Kv.set kv Mirage_kv.Key.(v state // refresh) refresh_token))
        (Kv.set kv Mirage_kv.Key.(v state // expiration) seconds) >>= function
      | Error e ->
        Logs.err (fun f -> f "error writing tokens: %a" Kv.pp_write_error e);
        Lwt.return_unit
      | Ok _ -> Lwt.return_unit
    in
    try
      let result = Yojson.Safe.from_string body in
      let open Yojson.Safe.Util in
      match member "access_token" result, member "refresh_token" result, member "expires_in" result with
      | `String access_token, `String refresh_token, `Int expires_in ->
        store kv state access_token refresh_token (string_of_int expires_in)
      | _, _, _ -> Logs.err (fun f -> f "response did not contain usable tokens & expiration");
        Lwt.return_unit
    with
    | Yojson.Json_error s ->
      Logs.debug (fun f -> f "exception handling token response from remote server: %s" s);
      Lwt.return_unit

  let request_token ~keystring ~host kv http_client state =
    Lwt_result.both 
      (Kv.get kv Mirage_kv.Key.(v state // verifier)) @@
      Kv.get kv Mirage_kv.Key.(v state // code) >>= function
    | Error e -> Logs.err (fun f -> f "error retrieving verifier or code when attempting to get a token: %a" Kv.pp_error e);
      Lwt.return_unit
    | Ok (this_verifier, this_code) ->
      Logs.debug (fun f -> f "constructing request for tokens");
      (* this is where we have to make our own request to the remote server *)
      let redirect_uri = "https://" ^ host ^ "/etsy" in
      let host = "api.etsy.com"
      and path = "v3/public/oauth/token"
      and scheme = "https"
      in
      let params = [
        "grant_type", ["authorization_code"];
        "client_id", [keystring];
        "redirect_uri", [redirect_uri];
        "code", [this_code];
        "code_verifier", [this_verifier]
      ] in
      let uri = Uri.make ~scheme ~host ~path () in
      Logs.debug (fun f -> f "asking for %s" (Uri.to_string uri));
      Client.post_form ~ctx:http_client ~params uri >>= fun (response, body) ->
      Cohttp_lwt__.Body.to_string body >>= fun bstr ->
      Logs.debug (fun f -> f "response from token get: %s" bstr);
      maybe_store kv state bstr

  let maybe_initiate_state ~keystring ~host kv http_client request =
    Logs.debug (fun f -> f "HI ETSY: %s" @@ Uri.to_string @@ Cohttp.Request.uri request);
    let request = Cohttp.Request.uri request in
    match Uri.get_query_param request "code", Uri.get_query_param request "state" with
    | None, None | None, _ | _, None ->
      Logs.debug (fun f -> f "GET from /etsy without required params");
      Lwt.return @@ bad_request
    | Some this_code, Some this_state -> begin
      let this_code = Uri.pct_decode this_code in
      let this_state = Uri.pct_decode this_state in
      Kv.exists kv (Mirage_kv.Key.v this_state) >>= function
      | Error e -> Logs.err (fun f -> f "error retrieving a state: %a" Kv.pp_error e);
        Lwt.return @@ ise
      | Ok None -> Lwt.return @@ bad_request
      | Ok (Some `Value) -> Logs.err (fun f -> f "state was a value, not a dictionary; refusing to store code");
        Lwt.return @@ ise
      | Ok (Some `Dictionary) ->
        Kv.set kv Mirage_kv.Key.(v this_state // code) this_code >>= function
        | Error e -> Logs.err (fun f -> f
            "got a valid looking code for a real state, \
             but failed to save it: %a" Kv.pp_write_error e);
          Lwt.return @@ ise
        | Ok () ->
          Logs.debug (fun f -> f "code retrieved and saved; requesting tokens");
          Lwt.dont_wait (fun () -> request_token ~keystring ~host kv http_client this_state) (fun _ -> ());
          Lwt.return @@ ok_empty
    end

  let reply ~keystring kv http_client host _start_time =
    let maybe_serve_code this_state =
      Kv.get kv Mirage_kv.Key.(v this_state // code) >>= function
      | Error (`Not_found _) -> Lwt.return not_found
      | Error e -> Logs.err (fun f -> f "getting code for client: %a" Kv.pp_error e);
        Lwt.return ise
      | Ok this_code ->
        Lwt.return @@ (Cohttp.Response.make ~status:Cohttp.Code.(`OK) (),
        Cohttp_lwt__.Body.of_string this_code)
    in
    let callback _connection request body =
      let endpoint = Mirage_kv.Key.v @@ Uri.path @@ Cohttp.Request.uri request in
      let meth = Cohttp.Request.meth request in
      match meth with
      | `GET when Mirage_kv.Key.equal endpoint @@ Mirage_kv.Key.v "/etsy" -> begin
          maybe_initiate_state ~keystring ~host kv http_client request
      end
      | `POST when Mirage_kv.Key.equal endpoint @@ Mirage_kv.Key.v "/etsy" ->
        Cohttp_lwt__.Body.to_string body >>= fun bstr ->
        Logs.debug (fun f -> f "POST to /etsy: %s" bstr);
        Lwt.return ise
      | `POST when Mirage_kv.Key.equal endpoint @@ Mirage_kv.Key.v "/token" ->
          Cohttp_lwt__.Body.to_form body >>= fun entries -> begin
          match List.assoc_opt "state" entries with
          | None | Some [] | Some (_::_::_) -> Lwt.return bad_request
          | Some (this_state::[]) ->
            maybe_serve_code this_state
        end
      | `POST when Mirage_kv.Key.equal endpoint @@ Mirage_kv.Key.v "/auth" ->
          Cohttp_lwt__.Body.to_form body >>= fun entries ->
          match List.assoc_opt "uuid" entries with
          | None | Some [] | Some (_::_::_) -> Lwt.return bad_request
          | Some (uuid::[]) ->
            start_auth kv >>= function
            | Error `Lookup -> Logs.err (fun f -> f "error looking up uuid, failing");
              Lwt.return ise
            | Error `Storage -> Logs.err (fun f -> f "error retrieving uuid-related information from storage, failing");
              Lwt.return ise
            | Ok (state, verifier) ->
              Logs.debug (fun f -> f "state and verifier found or made for request; generating redirect URI for resource server");
              let parameters = [
                "response_type", ["code"];
                "client_id", [keystring];
                "redirect_uri", ["https://" ^ host ^ "/etsy" ];
                "scope", ["listings_r listings_w"];
                "state", [state];
                "code_challenge", [PKCE.challenge verifier];
                "code_challenge_method", ["S256"];
              ] in
              let url = Uri.make ~scheme:"https" ~host:"etsy.com" ~path:"/oauth/connect" ~query:parameters () in
              let headers = Cohttp.Header.init_with "Location" (Uri.to_string url) in
              let response = Cohttp.Response.make ~status:Cohttp.Code.(`Temporary_redirect) ~headers () in
              let body = Cohttp_lwt__.Body.of_string "<html><body>Redirecting...</body></html>" in
              Lwt.return (response, body)
      | _ -> Lwt.return @@ ise
    in
    H.make ~conn_closed:(fun _ -> ()) ~callback ()
end
