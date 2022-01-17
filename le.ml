module Shim(Cohttp_client : Cohttp_lwt.S.Client) = struct
  module Headers = Cohttp.Header
  module Response = struct
    include Cohttp.Response
    let status t = Cohttp.Response.status t |> Cohttp.Code.code_of_status
  end
  module Body = Cohttp_lwt__.Body
  include Cohttp_client


end

module Make
    (Time : Mirage_time.S)
    (Http_server : Cohttp_mirage.Server.S)
    (Http_client : Cohttp_lwt.S.Client)
= struct
  module Http_client_shim = Shim(Http_client)
  module Acme = Letsencrypt.Client.Make(Http_client_shim)

  let http_port = 80
  let https_port = 443

  let cn host = X509.[Distinguished_name.(Relative_distinguished_name.singleton (CN host))]

  let csr host key =
    X509.Signing_request.create (cn host) key

  let prefix = ".well-known", "acme-challenge"
  let tokens = Hashtbl.create 1

  let solver _host ~prefix:_ ~token ~content =
    Hashtbl.replace tokens token content;
    Lwt.return (Ok ())

  (* It's important (more so than normal) that this function terminate,
   * because we call it with Lwt.async later *)
  let letsencrypt_dispatch request _body =
    let path = Uri.path (Cohttp.Request.uri request) in
    Logs.debug (fun m -> m "let's encrypt dispatcher %s" path);
    (* we expect very particular incoming requests from the LE web client.
     * Only if the incoming URI matches the right form should we
     * even check to see whether the token's in the store. *)
    match Astring.String.cuts ~sep:"/" ~empty:false path with
    | [p1; p2; token] when
        String.equal p1 (fst prefix) && String.equal p2 (snd prefix) -> begin
        (* anyone trying .well-known/acme-challenge/not-the-token gets a 404 *)
        match Hashtbl.find_opt tokens token with
        | None -> Http_server.respond ~status:`Not_found ~body:`Empty ()
        | Some data ->
          let headers =
            Cohttp.Header.init_with "content-type" "application/octet-stream"
          in
          (* respond to the challenge with the data we have available *)
          Http_server.respond ~headers ~status:`OK ~body:(`String data) ()

      end
    | _ ->
      (* TODO: we could refer this to another dispatcher,
       * which might know what to do *)
      Http_server.respond ~status:`Not_found ~body:`Empty ()

  let provision_certificate host ctx =
    let open Lwt_result.Infix in
    let endpoint =
      (* the example code contains a switch here for a production key,
       * so we can use Letsencrypt.letsencrypt_production_url
       * or the staging one as appropriate.
       * We test in prod ;)
      *)
      Letsencrypt.letsencrypt_production_url
    in

    (* email and seed are provided arguments in the example code;
     * let's see if we can get by without them *)

    (* the example code does some contortions to inject the seed
     * here if it's been provided.  We DGAF so just let generate
     * handle it. *)
    let priv = `RSA (Mirage_crypto_pk.Rsa.generate ~bits:4096 ()) in
    match csr host priv with
    | Error (`Msg err) ->
      Logs.err (fun m -> m "couldn't create signing request for our key: %s" err);
      (* The choice to `exit` here is debatable - we could return and serve on HTTP only *)
      exit 1
    | Ok csr ->
      let http_connection_pk = Mirage_crypto_pk.Rsa.generate ~bits:4096 () in
      Acme.initialise ~ctx ~endpoint (`RSA http_connection_pk) >>= fun lets_encrypt ->
      let sleep sec = Time.sleep_ns (Duration.of_sec sec) in
      let solver = Letsencrypt.Client.http_solver solver in
      Acme.sign_certificate ~ctx solver lets_encrypt sleep csr >|= 
      fun certs ->
      `Single (certs, priv)

  let serve cb =
    let callback _ = cb
    and conn_closed _ = ()
    in
    Http_server.make ~conn_closed ~callback ()

  let rec provision host http_server_impl http_client =
    let open Lwt.Infix in
    Logs.info (fun m -> m "listening on tcp/%d for Let's Encrypt provisioning" http_port);
    (* "this should be cancelled once certificates are retrieved",
     * says the source material *)
    let letsencrypt_http_server = http_server_impl (`TCP http_port) @@ serve letsencrypt_dispatch in
    Lwt.dont_wait (fun () -> letsencrypt_http_server) (fun _ex -> ());
    provision_certificate host http_client >>= function
    | Error (`Msg s) -> Logs.err (fun f -> f "error provisioning TLS certificate: %s" s);
      (* Since the error may be transient, wait a bit and try again *)
      Time.sleep_ns (Duration.of_min 15) >>= fun () ->
      provision host http_server_impl http_client
    | Ok certificates ->
      Lwt.return certificates

end
