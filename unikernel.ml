open Lwt.Infix

module Webapp
    (Clock : Mirage_clock.PCLOCK)
    (KV : Mirage_kv.RW)
    (H : Cohttp_mirage.Server.S) = struct

  let not_found = (
    Cohttp.Response.make ~status:Cohttp.Code.(`Not_found) (),
    Cohttp_lwt__.Body.of_string "Not found")

  let ise = (
    Cohttp.Response.make ~status:Cohttp.Code.(`Internal_server_error) (),
    Cohttp_lwt__.Body.of_string "Internal server error")

  let bad_request = (
    Cohttp.Response.make ~status:Cohttp.Code.(`Bad_request) (),
    Cohttp_lwt__.Body.of_string "Bad request")

  let reply _ _ _ = 
    let callback _ _ _ = Lwt.return @@ ise
    in
    H.make ~conn_closed:(fun _ -> ()) ~callback ()
end

module Main
    (Cert_block : Mirage_block.S)
    (App_block : Mirage_block.S)
    (Clock : Mirage_clock.PCLOCK)
    (Time : Mirage_time.S)
    (Http : Cohttp_mirage.Server.S)
    (Client : Cohttp_lwt.S.Client)
= struct
  module Logs_reporter = Mirage_logs.Make(Clock)
  module Cert_database = Kv.Make(Cert_block)(Clock)
  module App_database = Kv.Make(App_block)(Clock)
  module LE = Le.Make(Cert_database)(Time)(Http)(Client)
  module OAuth2 = Webapp(Clock)(App_database)(Http)

  let start cert_block app_block pclock _time http_server http_client =
    let open Lwt.Infix in
    let start_time = Ptime.v @@ Pclock.now_d_ps () in
    let host = Key_gen.host () in
    Logs_reporter.(create pclock |> run) @@ fun () ->
    (* solo5 requires us to use a block size of, at maximum, 512 *)
    Cert_database.connect ~program_block_size:16 ~block_size:512 cert_block >>= function
    | Error e -> Logs.err (fun f -> f "failed to initialize block-backed key-value store for certs: %a" Cert_database.pp_error e);
      Lwt.return_unit
    | Ok cert_kv ->
      Logs.info (fun f -> f "block-backed key-value store for certs up and running");
      App_database.connect ~program_block_size:16 ~block_size:512 app_block >>= function
      | Error e -> Logs.err (fun f -> f "failed to initialize block-backed key-value store for appplication: %a" App_database.pp_error e);
        Lwt.return_unit
      | Ok kv ->
        LE.provision host cert_kv http_server http_client >>= fun ((certificates, pk), renew_after) ->
        Logs.debug (fun f -> f "usable certificates found in the cert store (valid for %Ld ns)" renew_after);
        let rec provision () =
          let tls_cfg = Tls.Config.server ~certificates:(`Single (certificates, pk)) () in
          let tls = `TLS (tls_cfg, `TCP 443) in
          let https =
            Logs.info (fun f -> f "(re-)initialized https listener");
            http_server tls @@ OAuth2.reply kv host start_time
          in
          let expire = Time.sleep_ns renew_after in
          let http =
            let port = `TCP 80 in
            http_server port @@ OAuth2.reply kv host start_time
          in
          Lwt.pick [
            https ;
            http ;
            expire] >>= fun () ->
          provision ()
        in
        provision ()
end
