(* Letsencrypt and cohttp seem to disagree on a few things
 * I made this my problem with foolish life choices *)
module Glue(Http_client : Cohttp_lwt.S.Client) = struct
  include Cohttp_lwt
  include Http_client
  module Headers = Cohttp.Header
  module Response = struct
    include Response
    let status t : int = Cohttp.Code.code_of_status @@ Response.status t
  end
end

module Make(Http_client: Cohttp_lwt.S.Client) (Http: Cohttp_mirage.Server.S) (Time: Mirage_time.S) = struct
  module LOL = Glue(Http_client)
  module Acme = Letsencrypt.Client.Make(LOL)

  let argument_error = 64

  let gen_rsa ?seed () =
    let g = match seed with
      | None -> None
      | Some seed ->
        let seed = Cstruct.of_string seed in
        Some (Mirage_crypto_rng.(create ~seed (module Fortuna)))
    in
    Mirage_crypto_pk.Rsa.generate ?g ~bits:4096 ()

  let csr key host =
    match host with
    | None ->
      Logs.err (fun m -> m "no hostname provided");
      exit argument_error
    | Some host ->
      match Domain_name.of_string host with
      | Error `Msg err ->
        Logs.err (fun m -> m "invalid hostname provided %s" err);
        exit argument_error
      | Ok _ ->
        let cn =
          X509.[Distinguished_name.(Relative_distinguished_name.singleton (CN host))]
        in
        X509.Signing_request.create cn key

  let prefix = ".well-known", "acme-challenge"
  let tokens = Hashtbl.create 1

  let solver _host ~prefix:_ ~token ~content =
    Hashtbl.replace tokens token content;
    Lwt.return (Ok ())

  let dispatch request _body =
    let path = Uri.path (Cohttp.Request.uri request) in
    Logs.info (fun m -> m "let's encrypt dispatcher %s" path);
    match Astring.String.cuts ~sep:"/" ~empty:false path with
    | [ p1; p2; token ] when
        String.equal p1 (fst prefix) && String.equal p2 (snd prefix) ->
      begin
        match Hashtbl.find_opt tokens token with
        | Some data ->
          let headers =
            Cohttp.Header.init_with "content-type" "application/octet-stream"
          in
          Http.respond ~headers ~status:`OK ~body:(`String data) ()
        | None -> Http.respond ~status:`Not_found ~body:`Empty ()
      end
    | _ -> Http.respond ~status:`Not_found ~body:`Empty ()

  let provision_certificate ctx =
    let open Lwt_result.Infix in
    let endpoint =
      if Key_gen.production () then
        Letsencrypt.letsencrypt_production_url
      else
        Letsencrypt.letsencrypt_staging_url
    and email = Key_gen.email ()
    and seed = Key_gen.account_seed ()
    in
    let priv = `RSA (Mirage_crypto_pk.Rsa.generate ~bits:4096 ()) in
    match csr priv (Key_gen.hostname ()) with
    | Error (`Msg err) ->
      Logs.err (fun m -> m "couldn't create signing request %s" err);
      exit argument_error
    | Ok csr ->
      let keys = gen_rsa ?seed () in
      Logs.debug (fun m -> m "generated keys");
      Acme.initialise ~ctx ~endpoint ?email (`RSA keys) >>= fun le ->
      let sleep sec = Time.sleep_ns (Duration.of_sec sec) in
      let solver = Letsencrypt.Client.http_solver solver in
      Acme.sign_certificate ~ctx solver le sleep csr >|= fun certs ->
      `Single (certs, priv)
end
