module Make
    (Random : Mirage_random.S)
    (Clock : Mirage_clock.PCLOCK)
    (KV : Mirage_kv.RW)
    (H : Cohttp_mirage.Server.S) = struct

  module PKCE = Pkce.Make(Random)

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
    let callback _ _ _ =
      let verifier = PKCE.verifier () in
      let _challenge = PKCE.challenge verifier in
      Lwt.return @@ ise
    in
    H.make ~conn_closed:(fun _ -> ()) ~callback ()
end
