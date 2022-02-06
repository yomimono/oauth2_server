(* URL to hit for initial redirect URL generation and access token refreshing *)
let auth_url = Uri.of_string "https://api.etsy.com/v3/public/oauth/token"

(* how long should we assume access tokens are valid for, if their expiration
 * time can't be looked up? *)
let default_access_expiration = Ptime.Span.of_int_s 3600

(* which scopes should we request? *)
let requested_scopes = String.concat " " ["listings_r"; "listings_w"]

(* how long should we assume *refresh* tokens are valid for? *)
let expiration_span = Ptime.Span.v (90, 0L)

(* once the resource server has verified the access,
 * what URL should we serve the code verifier back to? *)
(* This is expressed as a series of components to be fed to Uri.Make
 * because the query portion needs to be added, and it's easier
 * to just construct the Uri.t in situ with this info provided *)
module Verify_url = struct
  let host = "etsy.com"
  let path = "/oauth/connect"
  let scheme = "https"
end
