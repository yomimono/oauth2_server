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
    (Block : Mirage_block.S)
    (Clock : Mirage_clock.PCLOCK)
    (Time : Mirage_time.S)
    (Http : Cohttp_mirage.Server.S)
    (Client : Cohttp_lwt.S.Client)
= struct
  module Logs_reporter = Mirage_logs.Make(Clock)
  module LE = Le.Make(Time)(Http)(Client)
  module Database = Kv.Make(Block)(Clock)
  module Shortener = Webapp(Clock)(Database)(Http)

  let start block pclock _time http_server http_client =
    let open Lwt.Infix in
    let start_time = Ptime.v @@ Pclock.now_d_ps () in
    let host = Key_gen.host () in
    Logs_reporter.(create pclock |> run) @@ fun () ->
    (* solo5 requires us to use a block size of, at maximum, 512 *)
    Database.connect ~program_block_size:16 ~block_size:512 block >>= function
    | Error e -> Logs.err (fun f -> f "failed to initialize block-backed key-value store: %a" Database.pp_error e);
      Lwt.return_unit
    | Ok kv ->
    Logs.info (fun f -> f "block-backed key-value store up and running");
    let rec provision () =
      (* if debug then begin *)
        let tcp = `TCP 80 in
        let http =
          Logs.info (fun f -> f "overwriting Let's Encrypt http listener with ours");
          http_server tcp @@ Shortener.reply kv host start_time
        in
        http
      (*
      end else begin
      LE.provision host http_server http_client >>= fun certificates ->
      Logs.info (fun f -> f "got certificates from let's encrypt via acme");
      let tls_cfg = Tls.Config.server ~certificates () in
      let tls = `TLS (tls_cfg, `TCP 443) in
      let tcp = `TCP 80 in
      let https =
        Logs.info (fun f -> f "(re-)initialized https listener");
        http_server tls @@ Shortener.reply kv host start_time
      in
      let http =
        Logs.info (fun f -> f "overwriting Let's Encrypt http listener with ours");
        http_server tcp @@ Shortener.reply kv host start_time
      in
      let expire = Time.sleep_ns @@ Duration.of_day 80 in
      Lwt.pick [
        https ;
        http ;
        expire] >>= fun () ->
      provision ()
    end
         *)
    in provision ()
end
