open Lwt.Infix

module Main
    (Cert_block : Mirage_block.S)
    (App_block : Mirage_block.S)
    (Clock : Mirage_clock.PCLOCK)
    (Time : Mirage_time.S)
    (Random : Mirage_random.S)
    (Http : Cohttp_mirage.Server.S)
    (Client : Cohttp_lwt.S.Client)
= struct
  module Logs_reporter = Mirage_logs.Make(Clock)
  module Cert_database = Kv.Make(Cert_block)(Clock)
  module App_database = Kv.Make(App_block)(Clock)
  module LE = Le.Make(Cert_database)(Time)(Http)(Client)
  module OAuth2 = Webapp.Make(Random)(Clock)(App_database)(Http)(Client)

  let start cert_block app_block pclock _time _random http_server http_client =
    let open Lwt.Infix in
    let host = Key_gen.host () in
    Logs_reporter.(create pclock |> run) @@ fun () ->
    (* solo5 requires us to use a block size of, at maximum, 512 *)
    Cert_database.connect ~program_block_size:16 ~block_size:512 cert_block >>= function
    | Error e -> Logs.err (fun f -> f "failed to initialize block-backed key-value store for certs: %a" Cert_database.pp_error e);
      Lwt.return_unit
    | Ok cert_kv ->
      Logs.info (fun f -> f "block-backed key-value store for certs up and running");
      Cert_database.get cert_kv (Mirage_kv.Key.v "keystring") >>= function
      | Error e -> Logs.err (fun f -> f "Couldn't retrieve the keystring from the cert store: %a" Cert_database.pp_error e);
        Lwt.return_unit
      | Ok keystring ->
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
              http_server tls @@ OAuth2.serve ~keystring kv http_client host
            in
            let expire = Time.sleep_ns renew_after in
            let http =
              (* replacement service on port 80 is a tarpit *)
              let tarpit _ _ _ = Lwt.return @@
                (Cohttp.Response.make ~status:Cohttp.Code.(`Internal_server_error) (),
                Cohttp_lwt__.Body.of_string "Internal server error")
              in
              let port = `TCP 80 in
              http_server port @@
                Http.make ~conn_closed:(fun _ -> ()) ~callback:tarpit ()
            in
            Lwt.pick [
              https ;
              http ;
              expire] >>= fun () ->
            provision ()
          in
          provision ()
end
