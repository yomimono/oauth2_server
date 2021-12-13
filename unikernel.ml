open Lwt.Infix

module Dispatch(Http: Cohttp_mirage.Server.S) = struct
  let dispatch request _body =
    let p = Uri.path (Cohttp.Request.uri request) in
    let path = if String.equal p "/" then "index.html" else p in
    Logs.info (fun f -> f "requested %s" path);
    Logs.debug (fun f -> f "request: %a"
                   Cohttp.Request.pp_hum request
               );
    let data = "Resource not found" in
    Http.respond ~status:`Not_found ~body:(`String data) ()

  let redirect port request _body =
    let uri = Cohttp.Request.uri request in
    let new_uri = Uri.with_scheme uri (Some "https") in
    let port = if port = 443 then None else Some port in
    let new_uri = Uri.with_port new_uri port in
    Logs.info (fun f -> f "[%s] -> [%s]"
                  (Uri.to_string uri) (Uri.to_string new_uri));
    let headers =
      Cohttp.Header.init_with "location" (Uri.to_string new_uri)
    in
    Http.respond ~headers ~status:`Moved_permanently ~body:`Empty ()

end


module Main (Http_client: Cohttp_lwt.S.Client) (Http: Cohttp_mirage.Server.S) (C: Mirage_clock.PCLOCK) (Time: Mirage_time.S) = struct
  module Dispatch = Dispatch(Http)
  module LE = Certcamel.Make(Http_client)(Http)(Time)
  
  let serve cb =
    let callback _ request body = cb request body
    and conn_closed _ = ()
    in
    Http.make ~conn_closed ~callback ()

  let start http_client http () () =
    let https_port = 443 and http_port = 80 in
    let rec provision () =
      Logs.info (fun m ->
          m "listening on %d/HTTP (let's encrypt provisioning)" http_port);
      (* this should be cancelled once certificates are retrieved *)
      Lwt.async (fun () -> http (`TCP http_port) (serve LE.dispatch));
      LE.provision_certificate http_client >>= function
      | Ok certificates -> begin
        let tls_cfg = Tls.Config.server ~certificates () in
        let tls = `TLS (tls_cfg, `TCP https_port) in
        let https =
          Logs.info (fun f -> f "listening on %d/HTTPS" https_port);
          http tls (serve Dispatch.dispatch)
        and http =
          Logs.info (fun f -> f "listening on %d/HTTP, redirecting to %d/HTTPS"
                        http_port https_port);
          let redirect = serve (Dispatch.redirect https_port) in
          http (`TCP http_port) redirect
        in
        let expire = Time.sleep_ns (Duration.of_day 80) in
        Lwt.pick [ https; http; expire ] >>= fun _ ->
        provision ()
      end
      | e -> Lwt.return e
    in
    provision ()
end
